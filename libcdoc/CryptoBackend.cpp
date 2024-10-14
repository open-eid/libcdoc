#define __CRYPTOBACKEND_CPP__

#include <openssl/rand.h>

#include "Crypto.h"
#include "CryptoBackend.h"

namespace libcdoc {

std::string
CryptoBackend::getLastErrorStr(int code) const
{
	switch (code) {
	case OK:
		return "";
	case NOT_IMPLEMENTED:
		return "CryptoBackend: Method not implemented";
	case INVALID_PARAMS:
		return "CryptoBackend: Invalid parameters";
	case OPENSSL_ERROR:
		return "CryptoBackend: OpenSSL error";
	default:
		break;
	}
	return "Internal error";
}

int
CryptoBackend::random(std::vector<uint8_t>& dst, uint32_t size)
{
	dst.resize(size);
	int result = RAND_bytes(dst.data(), size);
	return (result < 0) ? OPENSSL_ERROR : OK;
}

int
CryptoBackend::deriveConcatKDF(std::vector<uint8_t>& dst, const std::vector<uint8_t> &publicKey, const std::string &digest, int keySize,
	const std::vector<uint8_t> &algorithmID, const std::vector<uint8_t> &partyUInfo, const std::vector<uint8_t> &partyVInfo)
{
	std::vector<uint8_t> shared_secret;
	int result = derive(shared_secret, publicKey);
	if (result != OK) return result;
	dst = libcdoc::Crypto::concatKDF(digest, keySize, shared_secret, algorithmID, partyUInfo, partyVInfo);
	return (dst.empty()) ? OPENSSL_ERROR : OK;
}

int
CryptoBackend::deriveHMACExtract(std::vector<uint8_t>& dst, const std::vector<uint8_t> &publicKey, const std::vector<uint8_t> &salt, int keySize)
{
	std::vector<uint8_t> shared_secret;
	int result = derive(shared_secret, publicKey);
	if (result != OK) return result;
	dst = libcdoc::Crypto::extract(shared_secret, salt, keySize);
	return (dst.empty()) ? OPENSSL_ERROR : OK;
}

int
CryptoBackend::getKeyMaterial(std::vector<uint8_t>& key_material, const std::vector<uint8_t> pw_salt, int32_t kdf_iter, const std::string& label)
{
	if (kdf_iter > 0) {
		if (pw_salt.empty()) return INVALID_PARAMS;
		std::vector<uint8_t> secret;
		int result = getSecret(secret, label);
		if (result < 0) return result;
#ifdef LOCAL_DEBUG
		std::cerr << "Secret: " << Crypto::toHex(secret) << std::endl;
#endif
		key_material = libcdoc::Crypto::pbkdf2_sha256(secret, pw_salt, kdf_iter);
		std::fill(secret.begin(), secret.end(), 0);
		if (key_material.empty()) return OPENSSL_ERROR;
	} else {
		int result = getSecret(key_material, label);
		if (result < 0) return result;
	}
#ifdef LOCAL_DEBUG
	std::cerr << "Key material: " << Crypto::toHex(key_material) << std::endl;
#endif
	return OK;
}

int
CryptoBackend::getKEK(std::vector<uint8_t>& kek, const std::vector<uint8_t>& salt, const std::vector<uint8_t> pw_salt, int32_t kdf_iter,
			const std::string& label, const std::string& expand_salt)
{
	if (salt.empty() || expand_salt.empty()) return INVALID_PARAMS;
	if ((kdf_iter > 0) && pw_salt.empty()) return INVALID_PARAMS;
	std::vector<uint8_t> key_material;
	int result = getKeyMaterial(key_material, pw_salt, kdf_iter, label);
	if (result) return result;
	std::vector<uint8_t> tmp = libcdoc::Crypto::extract(key_material, salt, 32);
	std::fill(key_material.begin(), key_material.end(), 0);
	if (tmp.empty()) return OPENSSL_ERROR;
#ifdef LOCAL_DEBUG
	std::cerr << "Extract: " << Crypto::toHex(tmp) << std::endl;
#endif
	kek = libcdoc::Crypto::expand(tmp, std::vector<uint8_t>(expand_salt.cbegin(), expand_salt.cend()), 32);
	if (kek.empty()) return OPENSSL_ERROR;
#ifdef LOCAL_DEBUG
	std::cerr << "KEK: " << Crypto::toHex(kek) << std::endl;
#endif
	return OK;
}

} // namespace libcdoc

