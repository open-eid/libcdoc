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
    int useSecretKey(int slot, const std::vector<uint8_t>& pin, const std::vector<uint8_t>& id, const std::string& label);
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
    int usePrivateKey(int slot, const std::vector<uint8_t>& pin, const std::vector<uint8_t>& id, const std::string& label);

    int getCertificate(std::vector<uint8_t>& val, bool& rsa, int slot, const std::vector<uint8_t>& pin, const std::vector<uint8_t>& id, const std::string& label);
    int getPublicKey(std::vector<uint8_t>& val, bool& rsa, int slot, const std::vector<uint8_t>& pin, const std::vector<uint8_t>& id, const std::string& label);

    /**
     * @brief loads key for encryption/decryption
     *
     * A method to load the correct private/secret key for given capsule or reciever. The subclass implementation should
     * use either useSecretKey or usePrivateKey with proper label and/or id.
     * @param idx lock or recipient index (0-based) in CDoc container
     * @param priv whether to connect to private or secret key
     * @return error code or OK
     */
    virtual int connectToKey(int idx, bool priv) = 0;

    virtual int deriveECDH1(std::vector<uint8_t>& dst, const std::vector<uint8_t> &public_key, unsigned int idx) override;
    virtual int decryptRSA(std::vector<uint8_t>& dst, const std::vector<uint8_t> &data, bool oaep, unsigned int idxl) override;
    virtual int extractHKDF(std::vector<uint8_t>& kek, const std::vector<uint8_t>& salt, const std::vector<uint8_t>& pw_salt, int32_t kdf_iter, unsigned int idx) override;
    virtual int sign(std::vector<uint8_t>& dst, HashAlgorithm algorithm, const std::vector<uint8_t> &digest, unsigned int idx) override;
private:
	struct Private;
	std::unique_ptr<Private> d;
};

} // namespace libcdoc

#endif // PKCS11BACKEND_H
