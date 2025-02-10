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

#define NOMINMAX

#include <limits>
#include <fstream>
#include <iostream>

#define OPENSSL_SUPPRESS_DEPRECATED

#include "openssl/evp.h"
#include <openssl/x509.h>

#include "Certificate.h"
#include "Crypto.h"
#include "Tar.h"
#include "Utils.h"
#include "ZStream.h"
#include "CDoc2.h"

#include "header_generated.h"

#include "CDoc2Reader.h"

// fixme: Placeholder
#define t_(t) t

// Get salt bitstring for HKDF expand method

std::string
libcdoc::CDoc2::getSaltForExpand(const std::string& label)
{
	return std::string() + libcdoc::CDoc2::KEK.data() + cdoc20::header::EnumNameFMKEncryptionMethod(cdoc20::header::FMKEncryptionMethod::XOR) + label;
}

// Get salt bitstring for HKDF expand method
std::string
libcdoc::CDoc2::getSaltForExpand(const std::vector<uint8_t>& key_material, const std::vector<uint8_t>& rcpt_key)
{
	return std::string() + libcdoc::CDoc2::KEK.data() + cdoc20::header::EnumNameFMKEncryptionMethod(cdoc20::header::FMKEncryptionMethod::XOR) +
			std::string(rcpt_key.cbegin(), rcpt_key.cend()) +
			std::string(key_material.cbegin(), key_material.cend());
}

struct CDoc2Reader::Private {
	Private(libcdoc::DataSource *src, bool take_ownership) : _src(src), _owned(take_ownership) {
	}

	~Private() {
		if (_owned) delete _src;

        // Free memory allocated for locks
        for (libcdoc::Lock *lock : locks) {
            delete lock;
        }
        locks.clear();
	}

	libcdoc::DataSource *_src;
	bool _owned;
	size_t _nonce_pos = 0;
	bool _at_nonce = false;

	std::vector<uint8_t> header_data;
	std::vector<uint8_t> headerHMAC;

	std::vector<libcdoc::Lock *> locks;

	std::unique_ptr<libcdoc::Crypto::Cipher> cipher;
	std::unique_ptr<TaggedSource> tgs;
	std::unique_ptr<libcdoc::ZSource> zsrc;
	std::unique_ptr<libcdoc::TarSource> tar;

};

CDoc2Reader::~CDoc2Reader()
{
}

const std::vector<libcdoc::Lock>
CDoc2Reader::getLocks()
{
	std::vector<libcdoc::Lock> locks;
	for (libcdoc::Lock *l : priv->locks) locks.push_back(*l);
	return locks;
}

int
CDoc2Reader::getLockForCert(const std::vector<uint8_t>& cert){
	libcdoc::Certificate cc(cert);
	std::vector<uint8_t> other_key = cc.getPublicKey();
    for (int lock_idx = 0; lock_idx < priv->locks.size(); lock_idx++) {
        const libcdoc::Lock *ll = priv->locks.at(lock_idx);
		if (ll->hasTheSameKey(other_key)) {
            return lock_idx;
		}
	}
    return libcdoc::NOT_FOUND;
}

int
CDoc2Reader::getFMK(std::vector<uint8_t>& fmk, unsigned int lock_idx)
{
    std::cerr << "CDoc2Reader::getFMK: " << lock_idx << std::endl;
    std::cerr << "CDoc2Reader::locks: " << priv->locks.size() << std::endl;
    const libcdoc::Lock& lock = *priv->locks.at(lock_idx);
    std::vector<uint8_t> kek;
	if (lock.type == libcdoc::Lock::Type::PASSWORD) {
		// Password
        std::cerr << "password" << std::endl;
        std::string info_str = libcdoc::CDoc2::getSaltForExpand(lock.label);
		std::vector<uint8_t> kek_pm;
        crypto->extractHKDF(kek_pm, lock.getBytes(libcdoc::Lock::SALT), lock.getBytes(libcdoc::Lock::PW_SALT), lock.getInt(libcdoc::Lock::KDF_ITER), lock_idx);
        std::cerr << "password2" << std::endl;
        kek = libcdoc::Crypto::expand(kek_pm, std::vector<uint8_t>(info_str.cbegin(), info_str.cend()), 32);
		if (kek.empty()) return libcdoc::CRYPTO_ERROR;
        std::cerr << "password3" << std::endl;
    } else if (lock.type == libcdoc::Lock::Type::SYMMETRIC_KEY) {
		// Symmetric key
        std::cerr << "symmetric" << std::endl;
        std::string info_str = libcdoc::CDoc2::getSaltForExpand(lock.label);
		std::vector<uint8_t> kek_pm;
        crypto->extractHKDF(kek_pm, lock.getBytes(libcdoc::Lock::SALT), {}, 0, lock_idx);
		kek = libcdoc::Crypto::expand(kek_pm, std::vector<uint8_t>(info_str.cbegin(), info_str.cend()), 32);
#ifndef NDEBUG
        std::cerr << "Label: " << lock.label << std::endl;
        std::cerr << "info: " << libcdoc::toHex(std::vector<uint8_t>(info_str.cbegin(), info_str.cend())) << std::endl;
        std::cerr << "salt: " << libcdoc::toHex(lock.getBytes(libcdoc::Lock::SALT)) << std::endl;
        std::cerr << "kek_pm: " << libcdoc::toHex(kek_pm) << std::endl;
        std::cerr << "kek: " << libcdoc::toHex(kek) << std::endl;
#endif
        if (kek.empty()) return libcdoc::CRYPTO_ERROR;
	} else {
		// Public/private key
		std::vector<uint8_t> key_material;
		if(lock.type == libcdoc::Lock::Type::SERVER) {
            std::string server_id = lock.getString(libcdoc::Lock::Params::KEYSERVER_ID);
            std::string fetch_url = conf->getValue(server_id, libcdoc::Configuration::KEYSERVER_FETCH_URL);
            if (fetch_url.empty()) {
                setLastError("Missing keyserver URL");
                return libcdoc::CONFIGURATION_ERROR;
            }
            std::string transaction_id = lock.getString(libcdoc::Lock::Params::TRANSACTION_ID);
            int result = network->fetchKey(key_material, fetch_url, transaction_id);
			if (result < 0) {
				setLastError(network->getLastErrorStr(result));
				return result;
			}
		} else if (lock.type == libcdoc::Lock::PUBLIC_KEY) {
			key_material = lock.getBytes(libcdoc::Lock::Params::KEY_MATERIAL);
		}
#ifndef NDEBUG
        std::cerr << "Public key: " << libcdoc::toHex(lock.getBytes(libcdoc::Lock::Params::RCPT_KEY)) << std::endl;
        std::cerr << "Key material: " << libcdoc::toHex(key_material) << std::endl;
#endif
		if (lock.isRSA()) {
            int result = crypto->decryptRSA(kek, key_material, true, lock_idx);
			if (result < 0) {
				setLastError(crypto->getLastErrorStr(result));
				return result;
			}
		} else {
			std::vector<uint8_t> kek_pm;
            int result = crypto->deriveHMACExtract(kek_pm, key_material, std::vector<uint8_t>(libcdoc::CDoc2::KEKPREMASTER.cbegin(), libcdoc::CDoc2::KEKPREMASTER.cend()), lock_idx);
			if (result < 0) {
				setLastError(crypto->getLastErrorStr(result));
				return result;
			}
#ifndef NDEBUG
            std::cerr << "Key kekPm: " << libcdoc::toHex(kek_pm) << std::endl;
#endif
			std::string info_str = libcdoc::CDoc2::getSaltForExpand(key_material, lock.getBytes(libcdoc::Lock::Params::RCPT_KEY));
#ifndef NDEBUG
            std::cerr << "info" << libcdoc::toHex(std::vector<uint8_t>(info_str.cbegin(), info_str.cend())) << std::endl;
#endif
			kek = libcdoc::Crypto::expand(kek_pm, std::vector<uint8_t>(info_str.cbegin(), info_str.cend()), libcdoc::CDoc2::KEY_LEN);
		}
	}
#ifndef NDEBUG
    std::cerr << "KEK: " << libcdoc::toHex(kek) << std::endl;
#endif

	if(kek.empty()) {
		setLastError(t_("Failed to derive key"));
		return false;
	}
    if (libcdoc::Crypto::xor_data(fmk, lock.encrypted_fmk, kek) != libcdoc::OK) {
		setLastError(t_("Failed to decrypt/derive fmk"));
		return libcdoc::CRYPTO_ERROR;
	}
	std::vector<uint8_t> hhk = libcdoc::Crypto::expand(fmk, std::vector<uint8_t>(libcdoc::CDoc2::HMAC.cbegin(), libcdoc::CDoc2::HMAC.cend()));
#ifndef NDEBUG
    std::cerr << "xor: " << libcdoc::toHex(lock.encrypted_fmk) << std::endl;
    std::cerr << "fmk: " << libcdoc::toHex(fmk) << std::endl;
    std::cerr << "hhk: " << libcdoc::toHex(hhk) << std::endl;
    std::cerr << "hmac: " << libcdoc::toHex(priv->headerHMAC) << std::endl;
#endif
	if(libcdoc::Crypto::sign_hmac(hhk, priv->header_data) != priv->headerHMAC) {
		setLastError(t_("CDoc 2.0 hash mismatch"));
		return libcdoc::HASH_MISMATCH;
	}
	setLastError({});
    return libcdoc::OK;
}

int
CDoc2Reader::decrypt(const std::vector<uint8_t>& fmk, libcdoc::MultiDataConsumer *consumer)
{
	int result = beginDecryption(fmk);
    if (result != libcdoc::OK) return result;
	bool warning = false;
	std::string name;
	int64_t size;
	result = nextFile(name, size);
    while (result == libcdoc::OK) {
		consumer->open(name, size);
		consumer->writeAll(*priv->tar);
		result = nextFile(name, size);
	}
	if (result != libcdoc::END_OF_STREAM) {
		setLastError(priv->tar->getLastErrorStr(result));
		return result;
	}
	return finishDecryption();
}

int
CDoc2Reader::beginDecryption(const std::vector<uint8_t>& fmk)
{
	if (!priv->_at_nonce) {
		int result = priv->_src->seek(priv->_nonce_pos);
        if (result != libcdoc::OK) {
			setLastError(priv->_src->getLastErrorStr(result));
			return libcdoc::IO_ERROR;
		}
	}
	priv->_at_nonce = false;
	std::vector<uint8_t> cek = libcdoc::Crypto::expand(fmk, std::vector<uint8_t>(libcdoc::CDoc2::CEK.cbegin(), libcdoc::CDoc2::CEK.cend()));
	std::vector<uint8_t> nonce(libcdoc::CDoc2::NONCE_LEN);
	if (priv->_src->read(nonce.data(), libcdoc::CDoc2::NONCE_LEN) != libcdoc::CDoc2::NONCE_LEN) {
		setLastError("Error reading nonce");
		return libcdoc::IO_ERROR;
	}
#ifndef NDEBUG
    std::cerr << "cek: " << libcdoc::toHex(cek) << std::endl;
    std::cerr << "nonce: " << libcdoc::toHex(nonce) << std::endl;
#endif
	priv->cipher = std::make_unique<libcdoc::Crypto::Cipher>(EVP_chacha20_poly1305(), cek, nonce, false);
	std::vector<uint8_t> aad(libcdoc::CDoc2::PAYLOAD.cbegin(), libcdoc::CDoc2::PAYLOAD.cend());
	aad.insert(aad.end(), priv->header_data.cbegin(), priv->header_data.cend());
	aad.insert(aad.end(), priv->headerHMAC.cbegin(), priv->headerHMAC.cend());
	if(!priv->cipher->updateAAD(aad)) {
		setLastError("OpenSSL error");
		return libcdoc::UNSPECIFIED_ERROR;
	}

	priv->tgs = std::make_unique<TaggedSource>(priv->_src, false, 16);
	libcdoc::CipherSource *csrc = new libcdoc::CipherSource(priv->tgs.get(), false, priv->cipher.get());
	priv->zsrc = std::make_unique<libcdoc::ZSource>(csrc, false);
	priv->tar = std::make_unique<libcdoc::TarSource>(priv->zsrc.get(), false);

    return libcdoc::OK;
}

int
CDoc2Reader::nextFile(std::string& name, int64_t& size)
{
	if (!priv->tar) return libcdoc::WORKFLOW_ERROR;
	return priv->tar->next(name, size);
}

int64_t
CDoc2Reader::readData(uint8_t *dst, size_t size)
{
	if (!priv->tar) return libcdoc::WORKFLOW_ERROR;
	return priv->tar->read(dst, size);
}

int
CDoc2Reader::finishDecryption()
{
	if (!priv->zsrc->isEof()) {
		setLastError(t_("CDoc contains additional payload data that is not part of content"));
	}

#ifndef NDEBUG
    std::cerr << "tag: " << libcdoc::toHex(priv->tgs->tag) << std::endl;
#endif
	priv->cipher->setTag(priv->tgs->tag);
	if (!priv->cipher->result()) {
		setLastError("Stream tag does not match");
		return libcdoc::UNSPECIFIED_ERROR;
	}
	setLastError({});
    return libcdoc::OK;
	priv->tar.reset();
    return libcdoc::OK;
}

CDoc2Reader::CDoc2Reader(libcdoc::DataSource *src, bool take_ownership)
    : CDocReader(2), priv(std::make_unique<Private>(src, take_ownership))
{

	using namespace cdoc20::recipients;
	using namespace cdoc20::header;

	setLastError(t_("Invalid CDoc 2.0 header"));

	uint8_t in[libcdoc::CDoc2::LABEL.size()];
	if (priv->_src->read(in, libcdoc::CDoc2::LABEL.size()) != libcdoc::CDoc2::LABEL.size()) return;
	if (memcmp(libcdoc::CDoc2::LABEL.data(), in, libcdoc::CDoc2::LABEL.size())) return;
	//if (libcdoc::CDoc2::LABEL.compare(0, libcdoc::CDoc2::LABEL.size(), (const char *) in)) return;

	// Read 32-bit header length in big endian order
	uint8_t c[4];
	if (priv->_src->read(c, 4) != 4) return;
	uint32_t header_len = (c[0] << 24) | (c[1] << 16) | c[2] << 8 | c[3];
	priv->header_data.resize(header_len);
	if (priv->_src->read(priv->header_data.data(), header_len) != header_len) return;
	priv->headerHMAC.resize(libcdoc::CDoc2::KEY_LEN);
	if (priv->_src->read(priv->headerHMAC.data(), libcdoc::CDoc2::KEY_LEN) != libcdoc::CDoc2::KEY_LEN) return;

	priv->_nonce_pos = libcdoc::CDoc2::LABEL.size() + 4 + header_len + libcdoc::CDoc2::KEY_LEN;
	priv->_at_nonce = true;

	flatbuffers::Verifier verifier(priv->header_data.data(), priv->header_data.size());
	if(!VerifyHeaderBuffer(verifier)) return;
	const auto *header = GetHeader(priv->header_data.data());
	if(!header) return;
	if(header->payload_encryption_method() != PayloadEncryptionMethod::CHACHA20POLY1305) return;
	const auto *recipients = header->recipients();
	if(!recipients) return;

	setLastError({});

	for(const auto *recipient: *recipients){
		if(recipient->fmk_encryption_method() != FMKEncryptionMethod::XOR)
		{
			std::cerr << "Unsupported FMK encryption method: skipping" << std::endl;
			continue;
		}
		auto fillRecipientPK = [&] (libcdoc::Lock::PKType pk_type, auto key) {
			libcdoc::Lock *k = new libcdoc::Lock(libcdoc::Lock::Type::PUBLIC_KEY);
			k->pk_type = pk_type;
			k->setBytes(libcdoc::Lock::Params::RCPT_KEY, std::vector<uint8_t>(key->recipient_public_key()->cbegin(), key->recipient_public_key()->cend()));
			k->label = recipient->key_label()->str();
			k->encrypted_fmk.assign(recipient->encrypted_fmk()->cbegin(), recipient->encrypted_fmk()->cend());
			return k;
		};
		switch(recipient->capsule_type())
		{
		case Capsule::ECCPublicKeyCapsule:
			if(const auto *key = recipient->capsule_as_ECCPublicKeyCapsule()) {
				if(key->curve() != EllipticCurve::secp384r1) {
					std::cerr << "Unsupported ECC curve: skipping" << std::endl;
					continue;
				}
				libcdoc::Lock *k = fillRecipientPK(libcdoc::Lock::PKType::ECC, key);
				k->setBytes(libcdoc::Lock::Params::KEY_MATERIAL, std::vector<uint8_t>(key->sender_public_key()->cbegin(), key->sender_public_key()->cend()));
                std::cerr << "Load PK: " << libcdoc::toHex(k->getBytes(libcdoc::Lock::Params::RCPT_KEY)) << std::endl;
				priv->locks.push_back(k);
			}
			break;
		case Capsule::RSAPublicKeyCapsule:
			if(const auto *key = recipient->capsule_as_RSAPublicKeyCapsule())
			{
				libcdoc::Lock *k = fillRecipientPK(libcdoc::Lock::PKType::ECC, key);
				k->setBytes(libcdoc::Lock::Params::KEY_MATERIAL, std::vector<uint8_t>(key->encrypted_kek()->cbegin(), key->encrypted_kek()->cend()));
				priv->locks.push_back(k);
			}
			break;
		case Capsule::KeyServerCapsule:
			if (const KeyServerCapsule *server = recipient->capsule_as_KeyServerCapsule()) {
				KeyDetailsUnion details = server->recipient_key_details_type();
				libcdoc::Lock *ckey = nullptr;
				switch (details) {
				case KeyDetailsUnion::EccKeyDetails:
					if(const EccKeyDetails *eccDetails = server->recipient_key_details_as_EccKeyDetails()) {
						if(eccDetails->curve() == EllipticCurve::secp384r1) {
							ckey = new libcdoc::Lock(libcdoc::Lock::Type::SERVER);
							ckey->pk_type = libcdoc::Lock::PKType::ECC;
							ckey->setBytes(libcdoc::Lock::Params::RCPT_KEY, std::vector<uint8_t>(eccDetails->recipient_public_key()->cbegin(), eccDetails->recipient_public_key()->cend()));
						} else {
							std::cerr << "Unsupported elliptic curve key type" << std::endl;
						}
					} else {
						std::cerr << "Invalid file format" << std::endl;
					}
					break;
				case KeyDetailsUnion::RsaKeyDetails:
					if(const RsaKeyDetails *rsaDetails = server->recipient_key_details_as_RsaKeyDetails()) {
						ckey = new libcdoc::Lock(libcdoc::Lock::Type::SERVER);
						ckey->pk_type = libcdoc::Lock::PKType::RSA;
						ckey->setBytes(libcdoc::Lock::Params::RCPT_KEY, std::vector<uint8_t>(rsaDetails->recipient_public_key()->cbegin(), rsaDetails->recipient_public_key()->cend()));
					} else {
						std::cerr << "Invalid file format" << std::endl;
					}
					break;
				default:
					std::cerr << "Unsupported Key Server Details: skipping" << std::endl;
				}
				if (ckey) {
					ckey->label = recipient->key_label()->c_str();
					ckey->encrypted_fmk.assign(recipient->encrypted_fmk()->cbegin(), recipient->encrypted_fmk()->cend());
					ckey->setString(libcdoc::Lock::Params::KEYSERVER_ID, server->keyserver_id()->str());
					ckey->setString(libcdoc::Lock::Params::TRANSACTION_ID, server->transaction_id()->str());
					priv->locks.push_back(ckey);
				}
			} else {
				std::cerr << "Invalid file format" << std::endl;
			}
			break;
		case Capsule::SymmetricKeyCapsule:
			if(const auto *capsule = recipient->capsule_as_SymmetricKeyCapsule())
			{
				libcdoc::Lock *key = new libcdoc::Lock(libcdoc::Lock::SYMMETRIC_KEY);
				key->label = recipient->key_label()->str();
				key->encrypted_fmk.assign(recipient->encrypted_fmk()->cbegin(), recipient->encrypted_fmk()->cend());
				key->setBytes(libcdoc::Lock::SALT, std::vector<uint8_t>(capsule->salt()->cbegin(), capsule->salt()->cend()));
				priv->locks.push_back(key);
			}
			break;
		case Capsule::PBKDF2Capsule:
			if(const auto *capsule = recipient->capsule_as_PBKDF2Capsule()) {
				KDFAlgorithmIdentifier kdf_id = capsule->kdf_algorithm_identifier();
				if (kdf_id != KDFAlgorithmIdentifier::PBKDF2WithHmacSHA256) {
					std::cerr << "Unsupported KDF algorithm: skipping" << std::endl;
					continue;
				}
				libcdoc::Lock *key = new libcdoc::Lock(libcdoc::Lock::PASSWORD);
				key->label = recipient->key_label()->str();
				key->encrypted_fmk.assign(recipient->encrypted_fmk()->cbegin(), recipient->encrypted_fmk()->cend());
				key->setBytes(libcdoc::Lock::SALT, std::vector<uint8_t>(capsule->salt()->cbegin(), capsule->salt()->cend()));
				key->setBytes(libcdoc::Lock::PW_SALT, std::vector<uint8_t>(capsule->password_salt()->cbegin(), capsule->password_salt()->cend()));
				key->setInt(libcdoc::Lock::KDF_ITER, capsule->kdf_iterations());
				priv->locks.push_back(key);
			}
			break;
		default:
			std::cerr << "Unsupported Key Details: skipping" << std::endl;
		}
	}
}

CDoc2Reader::CDoc2Reader(const std::string &path)
	: CDoc2Reader(new libcdoc::IStreamSource(path), true)
{
}

bool
CDoc2Reader::isCDoc2File(libcdoc::DataSource *src)
{
    uint8_t in[libcdoc::CDoc2::LABEL.size()];
	constexpr size_t len = libcdoc::CDoc2::LABEL.size();
    if (src->read(&in[0], len) != len) return false;
    if (libcdoc::CDoc2::LABEL.compare(0, len, (char *) &in[0], len)) return false;
	return true;
}

bool
CDoc2Reader::isCDoc2File(const std::string& path)
{
    std::ifstream fb(path);
    char in[libcdoc::CDoc2::LABEL.size()];
    constexpr size_t len = libcdoc::CDoc2::LABEL.size();
    if (!fb.read(&in[0], len) || (fb.gcount() != len)) return false;
    if (libcdoc::CDoc2::LABEL.compare(0, len, &in[0], len)) return false;
    return true;
}

