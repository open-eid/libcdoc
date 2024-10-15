#ifndef __CRYPTOBACKEND_H__
#define __CRYPTOBACKEND_H__

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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <libcdoc/CDoc.h>

#include <string>
#include <vector>

namespace libcdoc {

/**
 * @brief An authentication provider
 * Implements cryptographic methods that potentially need either user action (supplying password) or external communication (PKCS11).
 *
 */
struct CryptoBackend {
	static constexpr int INVALID_PARAMS = -201;
	static constexpr int OPENSSL_ERROR = -202;

	virtual std::string getLastErrorStr(int code) const;

	/**
	 * @brief Fill vector with random bytes
	 *
	 * Trim vector to requested size and fill it with random bytes. The default implementation uses OpenSSL randomness generator.
	 * @param dst the destination container for randomness
	 * @param size the requested amount of random data
	 * @return  error code or OK
	 */
	virtual int random(std::vector<uint8_t>& dst, uint32_t size);
	/**
	 * @brief Derive shared secret
	 * @param dst the destination container for shared key
	 * @param public_key ECDH public Key used to derive shared secret
	 * @return error code or OK
	 */
	virtual int derive(std::vector<uint8_t>& dst, const std::vector<uint8_t> &public_key) { return NOT_IMPLEMENTED; }
	/**
	 * @brief decryptRSA
	 * @param dst the destination container for decrypted data
	 * @param data encrypted data
	 * @param oaep
	 * @return error code or OK
	 */
	virtual int decryptRSA(std::vector<uint8_t>& dst, const std::vector<uint8_t> &data, bool oaep) const = 0;
	/**
	 * @brief Derive key by ConcatKDF algorithm
	 *
	 * The ConcatKDF key derivation algorithm is defined in Section 5.8.1 of NIST SP 800-56A.
	 * The default implementation calls derive and performs concatKDF
	 * @param dst the container for derived key
	 * @param public_key ECDH public Key used to derive shared secret
	 * @param digest Digest method to use for ConcatKDF algorithm
	 * @param key_size Key size to output
	 * @param algorithm_id OtherInfo info parameters to input
	 * @param party_uinfo OtherInfo info parameters to input
	 * @param party_vinfo OtherInfo info parameters to input
	 * @return error code or OK
	 */
	virtual int  deriveConcatKDF(std::vector<uint8_t>& dst, const std::vector<uint8_t> &public_key, const std::string &digest, int key_size,
		const std::vector<uint8_t> &algorithm_id, const std::vector<uint8_t> &party_uinfo, const std::vector<uint8_t> &party_vinfo);
	/**
	 * @brief deriveHMACExtract
	 *
	 * The default implementation calls derive and performs HMAC extract
	 * @param dst the container for derived key
	 * @param public_key
	 * @param salt
	 * @param key_size
	 * @return error code or OK
	 */
	virtual int deriveHMACExtract(std::vector<uint8_t>& dst, const std::vector<uint8_t> &public_key, const std::vector<uint8_t> &salt, int key_size);
	/**
	 * @brief Get secret value (either password or symmetric key)
	 * @param secret the destination container for secret
	 * @param label label the label of the capsule (key)
	 * @return error code or OK
	 */
	virtual int getSecret(std::vector<uint8_t>& secret, const std::string& label) { return NOT_IMPLEMENTED; }
	/**
	 * @brief Get CDoc2 key material for HKDF expansion
	 *
	 * Fetches key material for a given symmetric key (either password or key-based).
	 * The default implementation calls getSecret and performs PBKDF2_SHA256 if key is password-based.
	 * @param key_material the destination container for key material
	 * @param pw_salt the salt value for PBKDF
	 * @param kdf_iter kdf_iter the number of KDF iterations. If kdf_iter is 0, the key is plain symmetric key instead of password.
	 * @param label the label of the capsule (key)
	 * @return error code or OK
	 */
	virtual int getKeyMaterial(std::vector<uint8_t>& key_material, const std::vector<uint8_t> pw_salt, int32_t kdf_iter, const std::string& label);
	/**
	 * @brief Get CDoc2 KEK for symmetric key
	 *
	 * Fetches KEK (Key Encryption Key) for a given symmetric key (either password or key-based).
	 * The default implementation calls getKeyMaterial and performs HKDF extract + expand.
	 * @param kek the destination container for KEK
	 * @param salt the salt value for HKDF extract
	 * @param pw_salt the salt value for PBKDF
	 * @param kdf_iter the number of KDF iterations. If kdf_iter is 0, the key is plain symmetric key instead of password.
	 * @param label the label of the capsule (key)
	 * @param expand_salt the salt for HKDF expand
	 * @return error code or OK
	 */
	virtual int getKEK(std::vector<uint8_t>& kek, const std::vector<uint8_t>& salt, const std::vector<uint8_t> pw_salt, int32_t kdf_iter,
				const std::string& label, const std::string& expand_salt);
};

} // namespace libcdoc

#endif // CRYPTOBACKEND_H
