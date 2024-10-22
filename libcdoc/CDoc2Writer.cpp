#define __CDOC2_WRITER_CPP__

#include "CDoc2Writer.h"

#include "header_generated.h"

#include "Crypto.h"
#include "CDoc2.h"
#include "ZStream.h"
#include "Tar.h"

#include "openssl/evp.h"
#include <openssl/x509.h>

#include <iostream>

struct CDoc2Writer::Private {
	Private(libcdoc::DataConsumer *_dst) : dst(_dst) {
		fmk = libcdoc::Crypto::extract(libcdoc::Crypto::random(libcdoc::CDoc2::KEY_LEN), std::vector<uint8_t>(libcdoc::CDoc2::SALT.cbegin(), libcdoc::CDoc2::SALT.cend()));
		cek = libcdoc::Crypto::expand(fmk, std::vector<uint8_t>(libcdoc::CDoc2::CEK.cbegin(), libcdoc::CDoc2::CEK.cend()));
		hhk = libcdoc::Crypto::expand(fmk, std::vector<uint8_t>(libcdoc::CDoc2::HMAC.cbegin(), libcdoc::CDoc2::HMAC.cend()));
		nonce = libcdoc::Crypto::random(libcdoc::CDoc2::NONCE_LEN);
		cipher = std::make_unique<libcdoc::Crypto::Cipher>(EVP_chacha20_poly1305(), cek, nonce, true);
		libcdoc::CipherConsumer *ccons = new libcdoc::CipherConsumer(dst, false, cipher.get());
		libcdoc::ZConsumer *zcons = new libcdoc::ZConsumer(ccons, true);
		tar = std::make_unique<libcdoc::TarConsumer>(zcons, true);
	}
	~Private() {
		std::fill(fmk.begin(), fmk.end(), 0);
		std::fill(cek.begin(), cek.end(), 0);
		std::fill(hhk.begin(), hhk.end(), 0);
		cipher.reset();
		tar.reset();
	}
	libcdoc::DataConsumer *dst;
	std::vector<uint8_t> fmk;
	std::vector<uint8_t> cek;
	std::vector<uint8_t> hhk;
	std::vector<uint8_t> nonce;
	std::unique_ptr<libcdoc::Crypto::Cipher> cipher;
	std::unique_ptr<libcdoc::TarConsumer> tar;
	std::vector<libcdoc::Recipient> recipients;
	bool header_written = false;
};

CDoc2Writer::CDoc2Writer()
	: CDocWriter(2)
{
}

CDoc2Writer::~CDoc2Writer()
{
}

int
CDoc2Writer::encrypt(libcdoc::DataConsumer& dst, libcdoc::MultiDataSource& src, const std::vector<libcdoc::Recipient>& keys)
{
	last_error.clear();
	priv = std::make_unique<Private>(&dst);
#ifndef NDEBUG
	std::cerr << "fmk: " << libcdoc::Crypto::toHex(priv->fmk) << std::endl;
	std::cerr << "cek: " << libcdoc::Crypto::toHex(priv->cek) << std::endl;
	std::cerr << "hhk: " << libcdoc::Crypto::toHex(priv->hhk) << std::endl;
#endif
	int result = encryptInternal(src, keys);
	priv.reset();
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
	while (src.next(name, size)) {
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
	std::cerr << "tag" << libcdoc::Crypto::toHex(tag) << std::endl;
#endif
	priv->dst->write(tag.data(), tag.size());
	priv->dst->close();
	return libcdoc::OK;
}

int
CDoc2Writer::writeHeader(const std::vector<uint8_t>& header, const std::vector<uint8_t>& hhk)
{
	std::vector<uint8_t> headerHMAC = libcdoc::Crypto::sign_hmac(hhk, header);
#ifndef NDEBUG
	std::cerr << "hmac" << libcdoc::Crypto::toHex(headerHMAC) << std::endl;
	std::cerr << "nonce" << libcdoc::Crypto::toHex(priv->nonce) << std::endl;
#endif

	std::vector<uint8_t> aad(libcdoc::CDoc2::PAYLOAD.cbegin(), libcdoc::CDoc2::PAYLOAD.cend());
	aad.insert(aad.end(), header.cbegin(), header.cend());
	aad.insert(aad.end(), headerHMAC.cbegin(), headerHMAC.cend());
	priv->cipher->updateAAD(aad);
	uint32_t hs = uint32_t(header.size());
	uint8_t header_len[] {uint8_t(hs >> 24), uint8_t((hs >> 16) & 0xff), uint8_t((hs >> 8) & 0xff), uint8_t(hs & 0xff)};

	priv->dst->write((const uint8_t *) libcdoc::CDoc2::LABEL.data(), libcdoc::CDoc2::LABEL.size());
	priv->dst->write((const uint8_t *) &header_len, 4);
	priv->dst->write(header.data(), header.size());
	priv->dst->write(headerHMAC.data(), headerHMAC.size());
	priv->dst->write(priv->nonce.data(), priv->nonce.size());
	return libcdoc::OK;
}

int
CDoc2Writer::buildHeader(std::vector<uint8_t>& header, const std::vector<libcdoc::Recipient>& keys, const std::vector<uint8_t>& fmk)
{
	flatbuffers::FlatBufferBuilder builder;
	std::vector<flatbuffers::Offset<cdoc20::header::RecipientRecord>> recipients;

	std::vector<uint8_t> xor_key(libcdoc::CDoc2::KEY_LEN);
	for(const libcdoc::Recipient& key: keys) {
		if (key.isPKI()) {
			const libcdoc::Recipient& pki = key;
			if(pki.pk_type == libcdoc::Recipient::PKType::RSA) {
				std::vector<uint8_t> kek = libcdoc::Crypto::random(libcdoc::CDoc2::KEY_LEN);
				if (libcdoc::Crypto::xor_data(xor_key, fmk, kek) != libcdoc::OK) {
					setLastError("Internal error");
					return libcdoc::CRYPTO_ERROR;
				}
				auto publicKey = libcdoc::Crypto::fromRSAPublicKeyDer(pki.rcpt_key);
				if(!publicKey) {
					setLastError("Invalid RSA key");
					return libcdoc::CRYPTO_ERROR;
				}
				std::vector<uint8_t> encrytpedKek = libcdoc::Crypto::encrypt(publicKey.get(), RSA_PKCS1_OAEP_PADDING, kek);
	#ifndef NDEBUG
				std::cerr << "publicKeyDer" << libcdoc::Crypto::toHex(pki.rcpt_key) << std::endl;
				std::cerr << "kek" << libcdoc::Crypto::toHex(kek) << std::endl;
				std::cerr << "xor" << libcdoc::Crypto::toHex(xor_key) << std::endl;
				std::cerr << "encrytpedKek" << libcdoc::Crypto::toHex(encrytpedKek) << std::endl;
	#endif
				if(!conf->getBoolean(libcdoc::Configuration::USE_KEYSERVER.data())) {
					auto rsaPublicKey = cdoc20::recipients::CreateRSAPublicKeyCapsule(builder,
																					  builder.CreateVector(pki.rcpt_key),
																					  builder.CreateVector(encrytpedKek));
					auto offs = cdoc20::header::CreateRecipientRecord(builder,
																	  cdoc20::recipients::Capsule::RSAPublicKeyCapsule,
																	  rsaPublicKey.Union(),
																	  builder.CreateString(pki.label),
																	  builder.CreateVector(xor_key),
																	  cdoc20::header::FMKEncryptionMethod::XOR);
					recipients.push_back(offs);
				} else {
					std::pair<std::string,std::string> serverinfo;
					int result = network->sendKey(serverinfo, pki.rcpt_key, std::vector<uint8_t>(encrytpedKek.cbegin(), encrytpedKek.cend()), "rsa");
					if (result < 0) {
						setLastError(network->getLastErrorStr(result));
						return libcdoc::IO_ERROR;
					}
					auto rsaKeyServer = cdoc20::recipients::CreateRsaKeyDetails(builder,
																				builder.CreateVector(pki.rcpt_key));
					auto keyServer = cdoc20::recipients::CreateKeyServerCapsule(builder,
																				cdoc20::recipients::KeyDetailsUnion::RsaKeyDetails,
																				rsaKeyServer.Union(),
																				builder.CreateString(serverinfo.first),
																				builder.CreateString(serverinfo.second));
					auto offs = cdoc20::header::CreateRecipientRecord(builder,
																	  cdoc20::recipients::Capsule::KeyServerCapsule,
																	  keyServer.Union(),
																	  builder.CreateString(pki.label),
																	  builder.CreateVector(xor_key),
																	  cdoc20::header::FMKEncryptionMethod::XOR);
					recipients.push_back(offs);
				}
			} else {
				auto publicKey = libcdoc::Crypto::fromECPublicKeyDer(pki.rcpt_key, NID_secp384r1);
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
						std::string(pki.rcpt_key.cbegin(), pki.rcpt_key.cend()) +
						std::string(ephPublicKeyDer.cbegin(), ephPublicKeyDer.cend());

				std::vector<uint8_t> kek = libcdoc::Crypto::expand(kekPm, std::vector<uint8_t>(info_str.cbegin(), info_str.cend()), fmk.size());
				if (libcdoc::Crypto::xor_data(xor_key, fmk, kek) != libcdoc::OK) {
					setLastError("Internal error");
					return libcdoc::CRYPTO_ERROR;
				}
	#ifndef NDEBUG
				std::cerr << "info" << libcdoc::Crypto::toHex(std::vector<uint8_t>(info_str.cbegin(), info_str.cend())) << std::endl;
				std::cerr << "publicKeyDer" << libcdoc::Crypto::toHex(pki.rcpt_key) << std::endl;
				std::cerr << "ephPublicKeyDer" << libcdoc::Crypto::toHex(ephPublicKeyDer) << std::endl;
				std::cerr << "sharedSecret" << libcdoc::Crypto::toHex(sharedSecret) << std::endl;
				std::cerr << "kekPm" << libcdoc::Crypto::toHex(kekPm) << std::endl;
				std::cerr << "kek" << libcdoc::Crypto::toHex(kek) << std::endl;
				std::cerr << "xor" << libcdoc::Crypto::toHex(xor_key) << std::endl;
	#endif
				if(!conf->getBoolean(libcdoc::Configuration::USE_KEYSERVER.data())) {
					auto eccPublicKey = cdoc20::recipients::CreateECCPublicKeyCapsule(builder,
																					  cdoc20::recipients::EllipticCurve::secp384r1,
																					  builder.CreateVector(pki.rcpt_key),
																					  builder.CreateVector(ephPublicKeyDer));
					auto offs = cdoc20::header::CreateRecipientRecord(builder,
																	  cdoc20::recipients::Capsule::ECCPublicKeyCapsule,
																	  eccPublicKey.Union(),
																	  builder.CreateString(pki.label),
																	  builder.CreateVector(xor_key),
																	  cdoc20::header::FMKEncryptionMethod::XOR);
					recipients.push_back(offs);
				} else {
					std::pair<std::string,std::string> serverinfo;
					int result = network->sendKey(serverinfo, pki.rcpt_key, ephPublicKeyDer, "ecc_secp384r1");
					if (result < 0) {
						setLastError(network->getLastErrorStr(result));
						return libcdoc::IO_ERROR;
					}
					auto eccKeyServer = cdoc20::recipients::CreateEccKeyDetails(builder,
																				cdoc20::recipients::EllipticCurve::secp384r1,
																				builder.CreateVector(pki.rcpt_key));
					auto keyServer = cdoc20::recipients::CreateKeyServerCapsule(builder,
																				cdoc20::recipients::KeyDetailsUnion::EccKeyDetails,
																				eccKeyServer.Union(),
																				builder.CreateString(serverinfo.first),
																				builder.CreateString(serverinfo.second));
					auto offs = cdoc20::header::CreateRecipientRecord(builder,
																	  cdoc20::recipients::Capsule::KeyServerCapsule,
																	  keyServer.Union(),
																	  builder.CreateString(pki.label),
																	  builder.CreateVector(xor_key),
																	  cdoc20::header::FMKEncryptionMethod::XOR);
					recipients.push_back(offs);
				}
			}
		} else if (key.isSymmetric()) {
			const libcdoc::Recipient& sk = key;
			std::string info_str = libcdoc::CDoc2::getSaltForExpand(sk.label);
			std::vector<uint8_t> kek_pm(32);
			std::vector<uint8_t> salt;
			crypto->random(salt, 32);
			std::vector<uint8_t> pw_salt;
			crypto->random(pw_salt, 32);
			crypto->extractHKDF(kek_pm, salt, pw_salt, sk.kdf_iter, libcdoc::CDoc2::KEY_LEN, sk.label);
			std::vector<uint8_t> kek = libcdoc::Crypto::expand(kek_pm, std::vector<uint8_t>(info_str.cbegin(), info_str.cend()), 32);
			if (kek.empty()) return libcdoc::CRYPTO_ERROR;
			if (libcdoc::Crypto::xor_data(xor_key, fmk, kek) != libcdoc::OK) {
				setLastError("Internal error");
				return libcdoc::CRYPTO_ERROR;
			}
			if (sk.kdf_iter > 0) {
				auto capsule = cdoc20::recipients::CreatePBKDF2Capsule(builder,
																	   builder.CreateVector(salt),
																	   builder.CreateVector(pw_salt),
																	   cdoc20::recipients::KDFAlgorithmIdentifier::PBKDF2WithHmacSHA256,
																	   sk.kdf_iter);
				auto offs = cdoc20::header::CreateRecipientRecord(builder,
																  cdoc20::recipients::Capsule::PBKDF2Capsule,
																  capsule.Union(),
																  builder.CreateString(sk.label),
																  builder.CreateVector(xor_key),
																  cdoc20::header::FMKEncryptionMethod::XOR);
				recipients.push_back(offs);
			} else {
				auto capsule = cdoc20::recipients::CreateSymmetricKeyCapsule(builder,
																			 builder.CreateVector(salt));
				auto offs = cdoc20::header::CreateRecipientRecord(builder,
																  cdoc20::recipients::Capsule::SymmetricKeyCapsule,
																  capsule.Union(),
																  builder.CreateString(sk.label),
																  builder.CreateVector(xor_key),
																  cdoc20::header::FMKEncryptionMethod::XOR);
				recipients.push_back(offs);
			}
		} else {
			setLastError("Invalid recipient type");
			return libcdoc::UNSPECIFIED_ERROR;
		}
	}

	auto offset = cdoc20::header::CreateHeader(builder, builder.CreateVector(recipients),
											   cdoc20::header::PayloadEncryptionMethod::CHACHA20POLY1305);
	builder.Finish(offset);

	header.assign(builder.GetBufferPointer(), builder.GetBufferPointer() + builder.GetSize());
	return libcdoc::OK;
}

int
CDoc2Writer::beginEncryption(libcdoc::DataConsumer& dst)
{
	if (priv) {
		setLastError("Encryption workflow already started");
		return libcdoc::WORKFLOW_ERROR;
	}
	last_error.clear();
	priv = std::make_unique<Private>(&dst);
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

int
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
CDoc2Writer::finishEncryption(bool close_dst)
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
	std::cerr << "tag" << libcdoc::Crypto::toHex(tag) << std::endl;
#endif
	priv->dst->write(tag.data(), tag.size());
	if (close_dst) priv->dst->close();

	return libcdoc::OK;
}
