#ifndef __LIBCDOC_WINBACKEND_H__
#define __LIBCDOC_WINBACKEND_H__

#include "CryptoBackend.h"

#include <memory>

namespace libcdoc {

struct CDOC_EXPORT WinBackend : public CryptoBackend {
    int useKey(const std::string& name, const std::string& pin);

    virtual int connectToKey(int idx, bool priv) = 0;

    virtual int decryptRSA(std::vector<uint8_t>& dst, const std::vector<uint8_t>& data, bool oaep, unsigned int idx);
	virtual int deriveConcatKDF(std::vector<uint8_t>& dst, const std::vector<uint8_t> &public_key, const std::string &digest,
								 const std::vector<uint8_t> &algorithm_id, const std::vector<uint8_t> &party_uinfo,
                                 const std::vector<uint8_t> &party_vinfo, unsigned int idx);
    virtual int deriveHMACExtract(std::vector<uint8_t>& dst, const std::vector<uint8_t> &public_key, const std::vector<uint8_t> &salt, unsigned int idx);
    virtual int extractHKDF(std::vector<uint8_t>& dst, const std::vector<uint8_t>& salt, const std::vector<uint8_t>& pw_salt, int32_t kdf_iter, unsigned int idx);

    virtual int sign(std::vector<uint8_t>& dst, HashAlgorithm algorithm, const std::vector<uint8_t> &digest, unsigned int idx);

    WinBackend(const std::string& provider);
    virtual ~WinBackend();
private:
	struct Private;
	std::unique_ptr<Private> d;
};

} // namespace libcdoc

#endif
