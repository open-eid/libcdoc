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

#ifndef __PKCS11_BACKEND_H__
#define __PKCS11_BACKEND_H__

#include <cdoc/CryptoBackend.h>

#include <memory>

namespace libcdoc {

struct CDOC_EXPORT PKCS11Backend : public CryptoBackend {
	struct Handle {
		uint32_t slot = 0;
		std::vector<uint8_t> id;
	};

	PKCS11Backend(const std::string &path);
	~PKCS11Backend();

	std::vector<Handle> findCertificates(const std::string& label, const std::string& serial);
	std::vector<Handle> findSecretKeys(const std::string& label, const std::string& serial);

    /**
     * @brief find all certificates for given public key
     * @param public_key public key (short form)
     * @return a list of handles
     */
    std::vector<Handle> findCertificates(const std::vector<uint8_t>& public_key);

    /**
     * @brief loads secret key
     *
     * Opens slots, logs in with pin and finds the correct secret key. Both key id and label have to match,
     * unless either is empty.
     * @param slot a PKCS11 slot to use
     * @param pin a user pin
     * @param id the key id
     * @param label the key label
     * @return error code or OK
     */
    result_t useSecretKey(int slot, const std::vector<uint8_t>& pin, const std::vector<uint8_t>& id, const std::string& label);
    /**
     * @brief loads private key
     *
     * Opens slots, logs in with pin and finds the correct private key. Both key id and label have to match,
     * unless either is empty.
     * @param slot a PKCS11 slot to use
     * @param pin a user pin
     * @param id the key id
     * @param label the key label
     * @return error code or OK
     */
    result_t usePrivateKey(int slot, const std::vector<uint8_t>& pin, const std::vector<uint8_t>& id, const std::string& label);

    result_t getCertificate(std::vector<uint8_t>& val, bool& rsa, int slot, const std::vector<uint8_t>& pin, const std::vector<uint8_t>& id, const std::string& label);
    result_t getPublicKey(std::vector<uint8_t>& val, bool& rsa, int slot, const std::vector<uint8_t>& pin, const std::vector<uint8_t>& id, const std::string& label);

    /**
     * @brief loads key for encryption/decryption
     *
     * A method to load the correct private/secret key for given capsule or reciever. The subclass implementation should
     * use either useSecretKey or usePrivateKey with proper label and/or id.
     * @param idx lock or recipient index (0-based) in CDoc container
     * @param priv whether to connect to private or secret key
     * @return error code or OK
     */
    virtual result_t connectToKey(int idx, bool priv) = 0;
    virtual result_t usePSS(int idx) {return true;}

    virtual result_t deriveECDH1(std::vector<uint8_t>& dst, const std::vector<uint8_t> &public_key, unsigned int idx) override;
    virtual result_t decryptRSA(std::vector<uint8_t>& dst, const std::vector<uint8_t> &data, bool oaep, unsigned int idxl) override;
    virtual result_t extractHKDF(std::vector<uint8_t>& kek, const std::vector<uint8_t>& salt, const std::vector<uint8_t>& pw_salt, int32_t kdf_iter, unsigned int idx) override;
    virtual result_t sign(std::vector<uint8_t>& dst, HashAlgorithm algorithm, const std::vector<uint8_t> &digest, unsigned int idx) override;
private:
	struct Private;
	std::unique_ptr<Private> d;
};

} // namespace libcdoc

#endif // PKCS11BACKEND_H
