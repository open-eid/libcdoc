#define __CDOC2_WRITER_CPP__

#include "CDoc2Writer.h"

#include "header_generated.h"

#include "Crypto.h"
#include "CDoc2.h"
#include "ZStream.h"
#include "Tar.h"
#include "Utils.h"

#if defined(_WIN32) || defined(_WIN64)
#include <IntSafe.h>
#endif

#define OPENSSL_SUPPRESS_DEPRECATED

#include "openssl/evp.h"
#include <openssl/x509.h>

#include <iostream>

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
#ifndef NDEBUG
        std::cerr << "fmk: " << libcdoc::toHex(fmk) << std::endl;
        std::cerr << "cek: " << libcdoc::toHex(cek) << std::endl;
        std::cerr << "hhk: " << libcdoc::toHex(hhk) << std::endl;
        std::cerr << "nonce: " << libcdoc::toHex(hhk) << std::endl;
#endif
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

int
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
		return libcdoc::CRYPTO_ERROR;
	}
	std::vector<uint8_t> tag = priv->cipher->tag();
#ifndef NDEBUG
    std::cerr << "tag" << libcdoc::toHex(tag) << std::endl;
#endif
	dst->write(tag.data(), tag.size());
	return libcdoc::OK;
}

int
CDoc2Writer::writeHeader(const std::vector<uint8_t>& header, const std::vector<uint8_t>& hhk)
{
	std::vector<uint8_t> headerHMAC = libcdoc::Crypto::sign_hmac(hhk, header);
#ifndef NDEBUG
    std::cerr << "hmac" << libcdoc::toHex(headerHMAC) << std::endl;
    std::cerr << "nonce" << libcdoc::toHex(priv->nonce) << std::endl;
#endif

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
					return libcdoc::CRYPTO_ERROR;
				}
                auto publicKey = libcdoc::Crypto::fromRSAPublicKeyDer(rcpt.rcpt_key);
				if(!publicKey) {
					setLastError("Invalid RSA key");
					return libcdoc::CRYPTO_ERROR;
				}
				std::vector<uint8_t> encrytpedKek = libcdoc::Crypto::encrypt(publicKey.get(), RSA_PKCS1_OAEP_PADDING, kek);
#ifndef NDEBUG
                std::cerr << "publicKeyDer: " << libcdoc::toHex(rcpt.rcpt_key) << std::endl;
                std::cerr << "kek: " << libcdoc::toHex(kek) << std::endl;
                std::cerr << "fmk_xor_kek: " << libcdoc::toHex(xor_key) << std::endl;
                std::cerr << "enc_kek: " << libcdoc::toHex(encrytpedKek) << std::endl;
#endif
                if(rcpt.isKeyServer()) {
                    std::string send_url = conf->getValue(rcpt.server_id, libcdoc::Configuration::KEYSERVER_SEND_URL);
                    if (send_url.empty()) {
                        setLastError("Missing keyserver URL");
                        return libcdoc::CONFIGURATION_ERROR;
                    }
                    libcdoc::NetworkBackend::CapsuleInfo cinfo;
                    int result = network->sendKey(cinfo, send_url, rcpt.rcpt_key, encrytpedKek, "RSA");
                    if (result < 0) {
                        setLastError(network->getLastErrorStr(result));
                        return libcdoc::IO_ERROR;
                    }
#ifndef NDEBUG
                    std::cerr << "Keyserver Id:" << rcpt.server_id << std::endl;
                    std::cerr << "Transaction Id: " << cinfo.transaction_id << std::endl;
#endif
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
					return libcdoc::CRYPTO_ERROR;
				}
	#ifndef NDEBUG
                std::cerr << "info: " << libcdoc::toHex(std::vector<uint8_t>(info_str.cbegin(), info_str.cend())) << std::endl;
                std::cerr << "publicKeyDer: " << libcdoc::toHex(rcpt.rcpt_key) << std::endl;
                std::cerr << "ephPublicKeyDer: " << libcdoc::toHex(ephPublicKeyDer) << std::endl;
                std::cerr << "sharedSecret: " << libcdoc::toHex(sharedSecret) << std::endl;
                std::cerr << "kekPm: " << libcdoc::toHex(kekPm) << std::endl;
                std::cerr << "kek: " << libcdoc::toHex(kek) << std::endl;
                std::cerr << "xor: " << libcdoc::toHex(xor_key) << std::endl;
	#endif
                if(rcpt.isKeyServer()) {
                    std::string send_url = conf->getValue(rcpt.server_id, libcdoc::Configuration::KEYSERVER_SEND_URL);
                    if (send_url.empty()) {
                        setLastError("Missing keyserver URL");
                        return libcdoc::CONFIGURATION_ERROR;
                    }
                    libcdoc::NetworkBackend::CapsuleInfo cinfo;
                    int result = network->sendKey(cinfo, send_url, rcpt.rcpt_key, ephPublicKeyDer, "ecc_secp384r1");
                    if (result < 0) {
                        setLastError(network->getLastErrorStr(result));
                        return libcdoc::IO_ERROR;
                    }
#ifndef NDEBUG
                    std::cerr << "Keyserver Id:" << rcpt.server_id << std::endl;
                    std::cerr << "Transaction Id: " << cinfo.transaction_id << std::endl;
#endif
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
			crypto->random(salt, 32);
			std::vector<uint8_t> pw_salt;
			crypto->random(pw_salt, 32);
            crypto->extractHKDF(kek_pm, salt, pw_salt, rcpt.kdf_iter, rcpt_idx);
            std::vector<uint8_t> kek = libcdoc::Crypto::expand(kek_pm, std::vector<uint8_t>(info_str.cbegin(), info_str.cend()), 32);
#ifndef NDEBUG
            std::cerr << "Label: " << rcpt.label << std::endl;
            std::cerr << "KDF iter: " << rcpt.kdf_iter << std::endl;
            std::cerr << "info: " << libcdoc::toHex(std::vector<uint8_t>(info_str.cbegin(), info_str.cend())) << std::endl;
            std::cerr << "salt: " << libcdoc::toHex(salt) << std::endl;
            std::cerr << "pw_salt: " << libcdoc::toHex(pw_salt) << std::endl;
            std::cerr << "kek_pm: " << libcdoc::toHex(kek_pm) << std::endl;
            std::cerr << "kek: " << libcdoc::toHex(kek) << std::endl;
#endif
            if (kek.empty()) return libcdoc::CRYPTO_ERROR;
			if (libcdoc::Crypto::xor_data(xor_key, fmk, kek) != libcdoc::OK) {
				setLastError("Internal error");
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
			return libcdoc::UNSPECIFIED_ERROR;
		}
	}

    auto offset = cdoc20::header::CreateHeader(builder, builder.CreateVector(fb_rcpts),
											   cdoc20::header::PayloadEncryptionMethod::CHACHA20POLY1305);
	builder.Finish(offset);

	header.assign(builder.GetBufferPointer(), builder.GetBufferPointer() + builder.GetSize());
	return libcdoc::OK;
}

int
CDoc2Writer::beginEncryption()
{
	if (priv) {
		setLastError("Encryption workflow already started");
		return libcdoc::WORKFLOW_ERROR;
	}
	last_error.clear();
	priv = std::make_unique<Private>(dst);
	return libcdoc::OK;
}

int
CDoc2Writer::addRecipient(const libcdoc::Recipient& rcpt)
{
	if (!priv) {
		setLastError("Encryption workflow not started");
		return libcdoc::WORKFLOW_ERROR;
	}
	priv->recipients.push_back(rcpt);
	return libcdoc::OK;
}

int
CDoc2Writer::addFile(const std::string& name, size_t size)
{
	if (!priv) {
		setLastError("Encryption workflow not started");
		return libcdoc::WORKFLOW_ERROR;
	}
	if (priv->recipients.empty()) {
		setLastError("No recipients specified");
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
		return result;
	}
	return libcdoc::OK;
}

int64_t
CDoc2Writer::writeData(const uint8_t *src, size_t size)
{
	if (!priv) {
		setLastError("Encryption workflow not started");
		return libcdoc::WORKFLOW_ERROR;
	}
	if (!priv->header_written) {
		setLastError("No file added");
		return libcdoc::WORKFLOW_ERROR;
	}

	int64_t result = priv->tar->write(src, size);
	if (result != size) {
		setLastError(priv->tar->getLastErrorStr(result));
		return result;
	}

	return libcdoc::OK;
}

int
CDoc2Writer::finishEncryption()
{
	if (!priv) {
		setLastError("Encryption workflow not started");
		return libcdoc::WORKFLOW_ERROR;
	}
	if (!priv->header_written) {
		setLastError("No file added");
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
		return libcdoc::CRYPTO_ERROR;
	}
	std::vector<uint8_t> tag = priv->cipher->tag();
#ifndef NDEBUG
    std::cerr << "tag" << libcdoc::toHex(tag) << std::endl;
#endif
	dst->write(tag.data(), tag.size());
	if (owned) dst->close();

	return libcdoc::OK;
}
