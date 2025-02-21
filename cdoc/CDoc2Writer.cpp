/*
 * libcdoc
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "CDoc2Writer.h"

#include "header_generated.h"

#include "Crypto.h"
#include "CDoc2.h"
#include "ZStream.h"
#include "Tar.h"
#include "Utils.h"
#include "ILogger.h"

#if defined(_WIN32) || defined(_WIN64)
#include <IntSafe.h>
#endif

#define OPENSSL_SUPPRESS_DEPRECATED

#include "openssl/evp.h"
#include <openssl/x509.h>

using namespace libcdoc;

struct CDoc2Writer::Private {
	Private(libcdoc::DataConsumer *dst) {
		fmk = libcdoc::Crypto::extract(libcdoc::Crypto::random(libcdoc::CDoc2::KEY_LEN), std::vector<uint8_t>(libcdoc::CDoc2::SALT.cbegin(), libcdoc::CDoc2::SALT.cend()));
		cek = libcdoc::Crypto::expand(fmk, std::vector<uint8_t>(libcdoc::CDoc2::CEK.cbegin(), libcdoc::CDoc2::CEK.cend()));
		hhk = libcdoc::Crypto::expand(fmk, std::vector<uint8_t>(libcdoc::CDoc2::HMAC.cbegin(), libcdoc::CDoc2::HMAC.cend()));
		nonce = libcdoc::Crypto::random(libcdoc::CDoc2::NONCE_LEN);
		cipher = std::make_unique<libcdoc::Crypto::Cipher>(EVP_chacha20_poly1305(), cek, nonce, true);
		libcdoc::CipherConsumer *ccons = new libcdoc::CipherConsumer(dst, false, cipher.get());
		libcdoc::ZConsumer *zcons = new libcdoc::ZConsumer(ccons, true);
		tar = std::make_unique<libcdoc::TarConsumer>(zcons, true);

        LOG_DBG("fmk: {}", toHex(fmk));
        LOG_DBG("cek: {}", toHex(cek));
        LOG_DBG("hhk: {}", toHex(hhk));
        LOG_DBG("nonce: {}", toHex(hhk));
    }

	~Private() {
		std::fill(fmk.begin(), fmk.end(), 0);
		std::fill(cek.begin(), cek.end(), 0);
		std::fill(hhk.begin(), hhk.end(), 0);
		cipher.reset();
		tar.reset();
	}
	std::vector<uint8_t> fmk;
	std::vector<uint8_t> cek;
	std::vector<uint8_t> hhk;
	std::vector<uint8_t> nonce;
	std::unique_ptr<libcdoc::Crypto::Cipher> cipher;
	std::unique_ptr<libcdoc::TarConsumer> tar;
	std::vector<libcdoc::Recipient> recipients;
	bool header_written = false;
};

CDoc2Writer::CDoc2Writer(libcdoc::DataConsumer *dst, bool take_ownership)
	: CDocWriter(2, dst, take_ownership)
{
}

CDoc2Writer::~CDoc2Writer()
{
}

libcdoc::result_t
CDoc2Writer::encrypt(libcdoc::MultiDataSource& src, const std::vector<libcdoc::Recipient>& keys)
{
	last_error.clear();
	priv = std::make_unique<Private>(dst);
	int result = encryptInternal(src, keys);
	priv.reset();
	if (owned) dst->close();
	return result;
}

int
CDoc2Writer::encryptInternal(libcdoc::MultiDataSource& src, const std::vector<libcdoc::Recipient>& keys)
{
	std::vector<uint8_t> header;
	int result = buildHeader(header, keys, priv->fmk);
	if (result < 0) return result;

	result = writeHeader(header, priv->hhk);
	if (result < 0) return result;

	std::string name;
	int64_t size;
    while (src.next(name, size) == libcdoc::OK) {
		if (priv->tar->open(name, size) < 0) return libcdoc::IO_ERROR;
		if (priv->tar->writeAll(src) < 0) return libcdoc::IO_ERROR;
	}
	if (priv->tar->close() < 0) return libcdoc::IO_ERROR;
	priv->tar.reset();
//	if(!libcdoc::TAR::save(zcons, src)) {
//		setLastError("Error packing encrypted stream");
//		return libcdoc::IO_ERROR;
//	}
	if(!priv->cipher->result()) {
		setLastError("Encryption error");
        LOG_ERROR("{}", last_error);
		return libcdoc::CRYPTO_ERROR;
	}
	std::vector<uint8_t> tag = priv->cipher->tag();

    LOG_DBG("tag: {}", toHex(tag));

	dst->write(tag.data(), tag.size());
	return libcdoc::OK;
}

int
CDoc2Writer::writeHeader(const std::vector<uint8_t>& header, const std::vector<uint8_t>& hhk)
{
	std::vector<uint8_t> headerHMAC = libcdoc::Crypto::sign_hmac(hhk, header);

    LOG_DBG("hmac: {}", toHex(headerHMAC));
    LOG_DBG("nonce: {}", toHex(priv->nonce));

	std::vector<uint8_t> aad(libcdoc::CDoc2::PAYLOAD.cbegin(), libcdoc::CDoc2::PAYLOAD.cend());
	aad.insert(aad.end(), header.cbegin(), header.cend());
	aad.insert(aad.end(), headerHMAC.cbegin(), headerHMAC.cend());
	priv->cipher->updateAAD(aad);
	uint32_t hs = uint32_t(header.size());
	uint8_t header_len[] {uint8_t(hs >> 24), uint8_t((hs >> 16) & 0xff), uint8_t((hs >> 8) & 0xff), uint8_t(hs & 0xff)};

	dst->write((const uint8_t *) libcdoc::CDoc2::LABEL.data(), libcdoc::CDoc2::LABEL.size());
	dst->write((const uint8_t *) &header_len, 4);
	dst->write(header.data(), header.size());
	dst->write(headerHMAC.data(), headerHMAC.size());
	dst->write(priv->nonce.data(), priv->nonce.size());
	return libcdoc::OK;
}

int
CDoc2Writer::buildHeader(std::vector<uint8_t>& header, const std::vector<libcdoc::Recipient>& recipients, const std::vector<uint8_t>& fmk)
{
	flatbuffers::FlatBufferBuilder builder;
    std::vector<flatbuffers::Offset<cdoc20::header::RecipientRecord>> fb_rcpts;

	std::vector<uint8_t> xor_key(libcdoc::CDoc2::KEY_LEN);
    for (unsigned int rcpt_idx = 0; rcpt_idx < recipients.size(); rcpt_idx++) {
        const libcdoc::Recipient& rcpt = recipients.at(rcpt_idx);
        if (rcpt.isPKI()) {
            if(rcpt.pk_type == libcdoc::Recipient::PKType::RSA) {
				std::vector<uint8_t> kek;
				crypto->random(kek, libcdoc::CDoc2::KEY_LEN);
				if (libcdoc::Crypto::xor_data(xor_key, fmk, kek) != libcdoc::OK) {
					setLastError("Internal error");
                    LOG_ERROR("{}", last_error);
					return libcdoc::CRYPTO_ERROR;
				}
                auto publicKey = libcdoc::Crypto::fromRSAPublicKeyDer(rcpt.rcpt_key);
				if(!publicKey) {
					setLastError("Invalid RSA key");
                    LOG_ERROR("{}", last_error);
					return libcdoc::CRYPTO_ERROR;
				}
				std::vector<uint8_t> encrytpedKek = libcdoc::Crypto::encrypt(publicKey.get(), RSA_PKCS1_OAEP_PADDING, kek);

                LOG_DBG("publicKeyDer: {}", toHex(rcpt.rcpt_key));
                LOG_DBG("kek: {}", toHex(kek));
                LOG_DBG("fmk_xor_kek: {}", toHex(xor_key));
                LOG_DBG("enc_kek: {}", toHex(encrytpedKek));

                if(rcpt.isKeyServer()) {
                    if(!conf) {
                        setLastError("Configuration is missing");
                        LOG_ERROR("{}", last_error);
                        return libcdoc::CONFIGURATION_ERROR;
                    }
                    if(!network) {
                        setLastError("Network backend is missing");
                        LOG_ERROR("{}", last_error);
                        return libcdoc::CONFIGURATION_ERROR;
                    }
                    std::string send_url = conf->getValue(rcpt.server_id, libcdoc::Configuration::KEYSERVER_SEND_URL);
                    if (send_url.empty()) {
                        setLastError("Missing keyserver URL");
                        LOG_ERROR("{}", last_error);
                        return libcdoc::CONFIGURATION_ERROR;
                    }
                    libcdoc::NetworkBackend::CapsuleInfo cinfo;
                    int result = network->sendKey(cinfo, send_url, rcpt.rcpt_key, encrytpedKek, "RSA");
                    if (result < 0) {
                        setLastError(network->getLastErrorStr(result));
                        LOG_ERROR("{}", last_error);
                        return libcdoc::IO_ERROR;
                    }

                    LOG_DBG("Keyserver Id: {}", rcpt.server_id);
                    LOG_DBG("Transaction Id: {}", cinfo.transaction_id);

                    auto rsaKeyServer = cdoc20::recipients::CreateRsaKeyDetails(builder,
                                                                                builder.CreateVector(rcpt.rcpt_key));
                    auto capsule = cdoc20::recipients::CreateKeyServerCapsule(builder,
                                                                                cdoc20::recipients::KeyDetailsUnion::RsaKeyDetails,
                                                                                rsaKeyServer.Union(),
                                                                                builder.CreateString(rcpt.server_id),
                                                                                builder.CreateString(cinfo.transaction_id));
                    auto record = cdoc20::header::CreateRecipientRecord(builder,
                                                                      cdoc20::recipients::Capsule::KeyServerCapsule,
                                                                      capsule.Union(),
                                                                      builder.CreateString(rcpt.label),
                                                                      builder.CreateVector(xor_key),
                                                                      cdoc20::header::FMKEncryptionMethod::XOR);
                    fb_rcpts.push_back(record);
                } else {
                    auto capsule = cdoc20::recipients::CreateRSAPublicKeyCapsule(builder,
                                                                                      builder.CreateVector(rcpt.rcpt_key),
																					  builder.CreateVector(encrytpedKek));
                    auto record = cdoc20::header::CreateRecipientRecord(builder,
																	  cdoc20::recipients::Capsule::RSAPublicKeyCapsule,
                                                                      capsule.Union(),
                                                                      builder.CreateString(rcpt.label),
																	  builder.CreateVector(xor_key),
																	  cdoc20::header::FMKEncryptionMethod::XOR);
                    fb_rcpts.push_back(record);
				}
			} else {
                auto publicKey = libcdoc::Crypto::fromECPublicKeyDer(rcpt.rcpt_key, NID_secp384r1);
				if(!publicKey) {
					setLastError("Invalid ECC key");
                    LOG_ERROR("{}", last_error);
					return libcdoc::CRYPTO_ERROR;
				}
				auto ephKey = libcdoc::Crypto::genECKey(publicKey.get());
				std::vector<uint8_t> sharedSecret = libcdoc::Crypto::deriveSharedSecret(ephKey.get(), publicKey.get());
				std::vector<uint8_t> ephPublicKeyDer = libcdoc::Crypto::toPublicKeyDer(ephKey.get());
				std::vector<uint8_t> kekPm = libcdoc::Crypto::extract(sharedSecret, std::vector<uint8_t>(libcdoc::CDoc2::KEKPREMASTER.cbegin(), libcdoc::CDoc2::KEKPREMASTER.cend()));
				std::string info_str = std::string() + libcdoc::CDoc2::KEK.data() +
						cdoc20::header::EnumNameFMKEncryptionMethod(cdoc20::header::FMKEncryptionMethod::XOR) +
                        std::string(rcpt.rcpt_key.cbegin(), rcpt.rcpt_key.cend()) +
						std::string(ephPublicKeyDer.cbegin(), ephPublicKeyDer.cend());

				std::vector<uint8_t> kek = libcdoc::Crypto::expand(kekPm, std::vector<uint8_t>(info_str.cbegin(), info_str.cend()), fmk.size());
				if (libcdoc::Crypto::xor_data(xor_key, fmk, kek) != libcdoc::OK) {
					setLastError("Internal error");
                    LOG_ERROR("{}", last_error);
					return libcdoc::CRYPTO_ERROR;
				}

                LOG_DBG("info: {}", toHex(std::vector<uint8_t>(info_str.cbegin(), info_str.cend())));
                LOG_DBG("publicKeyDer: {}", toHex(rcpt.rcpt_key));
                LOG_DBG("ephPublicKeyDer: {}", toHex(ephPublicKeyDer));
                LOG_DBG("sharedSecret: {}", toHex(sharedSecret));
                LOG_DBG("kekPm: {}", toHex(kekPm));
                LOG_DBG("kek: {}", toHex(kek));
                LOG_DBG("xor: {}", toHex(xor_key));

                if(rcpt.isKeyServer()) {
                    if(!conf) {
                        setLastError("Configuration is missing");
                        LOG_ERROR("{}", last_error);
                        return libcdoc::CONFIGURATION_ERROR;
                    }
                    if(!network) {
                        setLastError("Network backend is missing");
                        LOG_ERROR("{}", last_error);
                        return libcdoc::CONFIGURATION_ERROR;
					}
                    std::string send_url = conf->getValue(rcpt.server_id, libcdoc::Configuration::KEYSERVER_SEND_URL);
                    if (send_url.empty()) {
                        setLastError("Missing keyserver URL");
                        LOG_ERROR("{}", last_error);
                        return libcdoc::CONFIGURATION_ERROR;
                    }
                    libcdoc::NetworkBackend::CapsuleInfo cinfo;
                    int result = network->sendKey(cinfo, send_url, rcpt.rcpt_key, ephPublicKeyDer, "ecc_secp384r1");
                    if (result < 0) {
                        setLastError(network->getLastErrorStr(result));
                        LOG_ERROR("{}", last_error);
                        return libcdoc::IO_ERROR;
                    }

                    LOG_DBG("Keyserver Id: {}", rcpt.server_id);
                    LOG_DBG("Transaction Id: {}", cinfo.transaction_id);

                    auto eccKeyServer = cdoc20::recipients::CreateEccKeyDetails(builder,
                                                                                cdoc20::recipients::EllipticCurve::secp384r1,
                                                                                builder.CreateVector(rcpt.rcpt_key));
                    auto capsule = cdoc20::recipients::CreateKeyServerCapsule(builder,
                                                                                cdoc20::recipients::KeyDetailsUnion::EccKeyDetails,
                                                                                eccKeyServer.Union(),
                                                                                builder.CreateString(rcpt.server_id),
                                                                                builder.CreateString(cinfo.transaction_id));
                    auto record = cdoc20::header::CreateRecipientRecord(builder,
                                                                      cdoc20::recipients::Capsule::KeyServerCapsule,
                                                                      capsule.Union(),
                                                                      builder.CreateString(rcpt.label),
                                                                      builder.CreateVector(xor_key),
                                                                      cdoc20::header::FMKEncryptionMethod::XOR);
                    fb_rcpts.push_back(record);
                } else {
                    auto capsule = cdoc20::recipients::CreateECCPublicKeyCapsule(builder,
																					  cdoc20::recipients::EllipticCurve::secp384r1,
                                                                                      builder.CreateVector(rcpt.rcpt_key),
																					  builder.CreateVector(ephPublicKeyDer));
                    auto record = cdoc20::header::CreateRecipientRecord(builder,
																	  cdoc20::recipients::Capsule::ECCPublicKeyCapsule,
                                                                      capsule.Union(),
                                                                      builder.CreateString(rcpt.label),
																	  builder.CreateVector(xor_key),
																	  cdoc20::header::FMKEncryptionMethod::XOR);
                    fb_rcpts.push_back(record);
				}
			}
        } else if (rcpt.isSymmetric()) {
            std::string info_str = libcdoc::CDoc2::getSaltForExpand(rcpt.label);
			std::vector<uint8_t> kek_pm(32);
			std::vector<uint8_t> salt;
            int64_t result = crypto->random(salt, 32);
            if (result < 0) {
                setLastError(crypto->getLastErrorStr((int) result));
                return result;
            }
			std::vector<uint8_t> pw_salt;
            result = crypto->random(pw_salt, 32);
            if (result < 0) {
                setLastError(crypto->getLastErrorStr((int) result));
                return result;
            }
            result = crypto->extractHKDF(kek_pm, salt, pw_salt, rcpt.kdf_iter, rcpt_idx);
            if (result < 0) {
                setLastError(crypto->getLastErrorStr((int) result));
                return result;
            }
            std::vector<uint8_t> kek = libcdoc::Crypto::expand(kek_pm, std::vector<uint8_t>(info_str.cbegin(), info_str.cend()), 32);

            LOG_DBG("Label: {}", rcpt.label);
            LOG_DBG("KDF iter: {}", rcpt.kdf_iter);
            LOG_DBG("info: {}", toHex(std::vector<uint8_t>(info_str.cbegin(), info_str.cend())));
            LOG_DBG("salt: {}", toHex(salt));
            LOG_DBG("pw_salt: {}", toHex(pw_salt));
            LOG_DBG("kek_pm: {}", toHex(kek_pm));
            LOG_DBG("kek: {}", toHex(kek));

            if (kek.empty()) return libcdoc::CRYPTO_ERROR;
			if (libcdoc::Crypto::xor_data(xor_key, fmk, kek) != libcdoc::OK) {
				setLastError("Internal error");
                LOG_ERROR("{}", last_error);
				return libcdoc::CRYPTO_ERROR;
			}
            if (rcpt.kdf_iter > 0) {
				auto capsule = cdoc20::recipients::CreatePBKDF2Capsule(builder,
																	   builder.CreateVector(salt),
																	   builder.CreateVector(pw_salt),
																	   cdoc20::recipients::KDFAlgorithmIdentifier::PBKDF2WithHmacSHA256,
                                                                       rcpt.kdf_iter);
				auto offs = cdoc20::header::CreateRecipientRecord(builder,
																  cdoc20::recipients::Capsule::PBKDF2Capsule,
																  capsule.Union(),
                                                                  builder.CreateString(rcpt.label),
																  builder.CreateVector(xor_key),
																  cdoc20::header::FMKEncryptionMethod::XOR);
                fb_rcpts.push_back(offs);
			} else {
				auto capsule = cdoc20::recipients::CreateSymmetricKeyCapsule(builder,
																			 builder.CreateVector(salt));
				auto offs = cdoc20::header::CreateRecipientRecord(builder,
																  cdoc20::recipients::Capsule::SymmetricKeyCapsule,
																  capsule.Union(),
                                                                  builder.CreateString(rcpt.label),
																  builder.CreateVector(xor_key),
																  cdoc20::header::FMKEncryptionMethod::XOR);
                fb_rcpts.push_back(offs);
			}
		} else {
			setLastError("Invalid recipient type");
            LOG_ERROR("{}", last_error);
			return libcdoc::UNSPECIFIED_ERROR;
		}
	}

    auto offset = cdoc20::header::CreateHeader(builder, builder.CreateVector(fb_rcpts),
											   cdoc20::header::PayloadEncryptionMethod::CHACHA20POLY1305);
	builder.Finish(offset);

	header.assign(builder.GetBufferPointer(), builder.GetBufferPointer() + builder.GetSize());
	return libcdoc::OK;
}

libcdoc::result_t
CDoc2Writer::beginEncryption()
{
	if (!priv) {
        LOG_ERROR("Encryption workflow already started");
        last_error.clear();
        priv = std::make_unique<Private>(dst);
	}
	return libcdoc::OK;
}

libcdoc::result_t
CDoc2Writer::addRecipient(const libcdoc::Recipient& rcpt)
{
	if (!priv) {
        LOG_ERROR("Encryption workflow not started");
        last_error.clear();
        priv = std::make_unique<Private>(dst);
	}
	priv->recipients.push_back(rcpt);
	return libcdoc::OK;
}

libcdoc::result_t
CDoc2Writer::addFile(const std::string& name, size_t size)
{
	if (!priv) {
		setLastError("Encryption workflow not started");
        LOG_ERROR("{}", last_error);
		return libcdoc::WORKFLOW_ERROR;
	}
	if (priv->recipients.empty()) {
		setLastError("No recipients specified");
        LOG_ERROR("{}", last_error);
		return libcdoc::WRONG_ARGUMENTS;
	}
	if (!priv->header_written) {
		std::vector<uint8_t> header;
		int result = buildHeader(header, priv->recipients, priv->fmk);
		if (result < 0) return result;

		result = writeHeader(header, priv->hhk);
		if (result < 0) return result;

		priv->header_written = true;
	}
	int result = priv->tar->open(name, size);
	if (result < 0) {
		setLastError(priv->tar->getLastErrorStr(result));
        LOG_ERROR("{}", last_error);
		return result;
	}
	return libcdoc::OK;
}

libcdoc::result_t
CDoc2Writer::writeData(const uint8_t *src, size_t size)
{
	if (!priv) {
		setLastError("Encryption workflow not started");
        LOG_ERROR("{}", last_error);
		return libcdoc::WORKFLOW_ERROR;
	}
	if (!priv->header_written) {
		setLastError("No file added");
        LOG_ERROR("{}", last_error);
		return libcdoc::WORKFLOW_ERROR;
	}

	int64_t result = priv->tar->write(src, size);
	if (result != size) {
		setLastError(priv->tar->getLastErrorStr(result));
		return result;
	}

	return libcdoc::OK;
}

libcdoc::result_t
CDoc2Writer::finishEncryption()
{
	if (!priv) {
		setLastError("Encryption workflow not started");
        LOG_ERROR("{}", last_error);
		return libcdoc::WORKFLOW_ERROR;
	}
	if (!priv->header_written) {
		setLastError("No file added");
        LOG_ERROR("{}", last_error);
		return libcdoc::WORKFLOW_ERROR;
	}
	int result = priv->tar->close();
	if (result < 0) {
		setLastError(priv->tar->getLastErrorStr(result));
		return result;
	}
	priv->tar.reset();
	if(!priv->cipher->result()) {
		setLastError("Encryption error");
        LOG_ERROR("{}", last_error);
		return libcdoc::CRYPTO_ERROR;
	}
	std::vector<uint8_t> tag = priv->cipher->tag();

    LOG_DBG("tag: {}", toHex(tag));

	dst->write(tag.data(), tag.size());
	if (owned) dst->close();

	return libcdoc::OK;
}
