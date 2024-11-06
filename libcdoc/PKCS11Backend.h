#ifndef __PKCS11_BACKEND_H__
#define __PKCS11_BACKEND_H__

#include <libcdoc/CryptoBackend.h>

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
	int useSecretKey(int slot, const std::string& pin, uint32_t idx, const std::string& id, const std::string& label);

	virtual int connectToKey(const std::string& label) = 0;

	virtual int deriveECDH1(std::vector<uint8_t>& dst, const std::vector<uint8_t> &public_key, const std::string& label) override;
	virtual int decryptRSA(std::vector<uint8_t>& dst, const std::vector<uint8_t> &data, bool oaep, const std::string& label) override;
	virtual int extractHKDF(std::vector<uint8_t>& kek, const std::vector<uint8_t>& salt, const std::vector<uint8_t> pw_salt, int32_t kdf_iter, const std::string& label) override;
private:
	struct Private;
	std::unique_ptr<Private> d;
};

} // namespace libcdoc

#endif // PKCS11BACKEND_H