#ifndef __PKCS11_BACKEND_H__
#define __PKCS11_BACKEND_H__

#include "CryptoBackend.h"

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

    int useSecretKey(int slot, const std::vector<uint8_t>& pin, const std::vector<uint8_t>& id, const std::string& label);
    int usePrivateKey(int slot, const std::vector<uint8_t>& pin, const std::vector<uint8_t>& id, const std::string& label);
    int getCertificate(std::vector<uint8_t>& val, bool& rsa, int slot, const std::vector<uint8_t>& pin, const std::vector<uint8_t>& id, const std::string& label);
    int getPublicKey(std::vector<uint8_t>& val, bool& rsa, int slot, const std::vector<uint8_t>& pin, const std::vector<uint8_t>& id, const std::string& label);

    virtual int connectToKey(int idx, bool priv) = 0;

    virtual int deriveECDH1(std::vector<uint8_t>& dst, const std::vector<uint8_t> &public_key, unsigned int idx) override;
    virtual int decryptRSA(std::vector<uint8_t>& dst, const std::vector<uint8_t> &data, bool oaep, unsigned int idxl) override;
    virtual int extractHKDF(std::vector<uint8_t>& kek, const std::vector<uint8_t>& salt, const std::vector<uint8_t>& pw_salt, int32_t kdf_iter, unsigned int idx) override;
    virtual int sign(std::vector<uint8_t>& dst, HashAlgorithm algorithm, const std::vector<uint8_t> &digest, unsigned int idx);
private:
	struct Private;
	std::unique_ptr<Private> d;
};

} // namespace libcdoc

#endif // PKCS11BACKEND_H
