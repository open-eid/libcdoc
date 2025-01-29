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
#include <libcdoc/Exports.h>
#include <libcdoc/Lock.h>

#include <string>
#include <vector>

namespace libcdoc {

/**
 * @brief An authentication provider
 *
 * Implements cryptographic methods that may need either user action (supplying password) or external communication (PKCS11).
 * At minimum one should implement deriveECDH1 for ECC keys, decryptRSA for RSA keys and getSecret for symmetric keys. ECC and
 * symmetric keys have also frontend methods; implementing these allows the program to perform certain cryptographic procedures in controlled
 * environment and (in case of symmetric keys) avoid exposing secret keys/passwords.
 */
struct CDOC_EXPORT CryptoBackend {
	static constexpr int INVALID_PARAMS = -201;
	static constexpr int OPENSSL_ERROR = -202;

	static constexpr int ECC_KEY_LEN = 32;

    enum HashAlgorithm : uint32_t {
        SHA_224,
        SHA_256,
        SHA_384,
        SHA_512
    };

	CryptoBackend() = default;
	virtual ~CryptoBackend() = default;

	virtual std::string getLastErrorStr(int code) const;

	/**
	 * @brief Fill vector with random bytes
	 *
	 * Trim vector to requested size and fill it with random bytes. The default implementation uses OpenSSL randomness generator.
	 * @param dst the destination container for randomness
	 * @param size the requested amount of random data
	 * @return  error code or OK
	 */
    virtual int random(std::vector<uint8_t>& dst, unsigned int size);
    /**
	 * @brief Derive shared secret
	 *
	 * Derive a shared secret from private key of given lock label and public key using ECDH1 algorithm.
	 * @param dst the container for shared secret
	 * @param public_key ECDH public key used to derive shared secret
     * @param idx lock index (0-based) in container
	 * @return error code or OK
	 */
    virtual int deriveECDH1(std::vector<uint8_t>& dst, const std::vector<uint8_t> &public_key, unsigned int idx) { return NOT_IMPLEMENTED; }
	/**
	 * @brief decryptRSA
	 * @param dst the destination container for decrypted data
	 * @param data encrypted data
	 * @param oaep
	 * @param label Label of the lock
	 * @return error code or OK
	 */
    virtual int decryptRSA(std::vector<uint8_t>& dst, const std::vector<uint8_t>& data, bool oaep, unsigned int idx) { return NOT_IMPLEMENTED; };
	/**
	 * @brief Derive key by ConcatKDF algorithm
	 *
	 * The ConcatKDF key derivation algorithm is defined in Section 5.8.1 of NIST SP 800-56A.
	 * The default implementation calls deriveECDH1 and performs local concatKDF
	 * @param dst the container for derived key
	 * @param public_key ECDH public Key used to derive shared secret
	 * @param digest Digest method to use for ConcatKDF algorithm
	 * @param algorithm_id OtherInfo info parameters to input
	 * @param party_uinfo OtherInfo info parameters to input
	 * @param party_vinfo OtherInfo info parameters to input
     * @param idx lock index (0-based) in container
	 * @return error code or OK
	 */
	virtual int deriveConcatKDF(std::vector<uint8_t>& dst, const std::vector<uint8_t> &public_key, const std::string &digest,
								 const std::vector<uint8_t> &algorithm_id, const std::vector<uint8_t> &party_uinfo,
                                 const std::vector<uint8_t> &party_vinfo, unsigned int idx);
	/**
	 * @brief Get CDoc2 KEK pre-master from ECC key
	 *
	 * Calculates KEK (Key Encryption Key) pre-master from an ECC public key.
	 * The default implementation calls deriveECDH1 and performs local HMAC extract
	 * @param dst the container for derived key
	 * @param public_key
	 * @param salt
     * @param idx lock index (0-based) in container
	 * @return error code or OK
	 */
    virtual int deriveHMACExtract(std::vector<uint8_t>& dst, const std::vector<uint8_t> &public_key, const std::vector<uint8_t> &salt, unsigned int idx);
	/**
	 * @brief Get secret value (either password or symmetric key) for a lock.
	 * @param secret the destination container for secret
     * @param idx lock or recipient index (0-based) in container
	 * @return error code or OK
	 */
    virtual int getSecret(std::vector<uint8_t>& dst, unsigned int idx) { return NOT_IMPLEMENTED; };
	/**
	 * @brief Get CDoc2 key material for HKDF expansion
	 *
	 * Fetches key material for a symmetric key (either password or key-based).
	 * The default implementation calls getSecret and performs PBKDF2_SHA256 if key is password-based.
	 * @param key_material the destination container for key material
	 * @param pw_salt the salt value for PBKDF
	 * @param kdf_iter kdf_iter the number of KDF iterations. If kdf_iter is 0, the key is plain symmetric key instead of password.
     * @param idx lock or recipient index (0-based) in container
	 * @return error code or OK
	 */
    virtual int getKeyMaterial(std::vector<uint8_t>& dst, const std::vector<uint8_t>& pw_salt,
                               int32_t kdf_iter, unsigned int idx);
	/**
	 * @brief Get CDoc2 KEK pre-master from symmetric key
	 *
	 * Calculates KEK (Key Encryption Key) pre-master from a symmetric key (either password or key-based).
	 * The default implementation calls getKeyMaterial and performs local HKDF extract.
	 * @param dst the destination container for KEK pre-master
	 * @param salt the salt value for HKDF extract
	 * @param pw_salt the salt value for PBKDF
	 * @param kdf_iter the number of KDF iterations. If kdf_iter is 0, the key is plain symmetric key instead of password.
     * @param idx lock or recipient index (0-based) in container
	 * @return error code or OK
	 */
    virtual int extractHKDF(std::vector<uint8_t>& dst, const std::vector<uint8_t>& salt, const std::vector<uint8_t>& pw_salt,
                            int32_t kdf_iter, unsigned int idx);

    virtual int test(libcdoc::Lock& lock) { return NOT_IMPLEMENTED; }

	CryptoBackend (const CryptoBackend&) = delete;
	CryptoBackend& operator= (const CryptoBackend&) = delete;
};

} // namespace libcdoc

#endif // CRYPTOBACKEND_H
