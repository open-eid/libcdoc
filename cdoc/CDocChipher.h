#ifndef CDOCCHIPHER_H
#define CDOCCHIPHER_H

#include <cstdint>
#include <map>
#include "CDocReader.h"
#include "CDocWriter.h"
#include "RcptInfo.h"
#include "ToolConf.h"

namespace libcdoc
{

typedef typename std::map<std::string, RcptInfo> RecipientInfoLabelMap;
typedef typename std::map<int, RcptInfo>         RecipientInfoIdMap;
typedef typename std::vector<RcptInfo>           RecipientInfoVector;

class CDocChipher
{
public:
    CDocChipher() = default;
    CDocChipher(const CDocChipher&) = delete;
    CDocChipher(CDocChipher&&) = delete;

    int Encrypt(ToolConf& conf, RecipientInfoVector& recipients, const std::vector<std::vector<uint8_t>>& certs);

    int Decrypt(ToolConf& conf, int idx_base_1, const RcptInfo& recipient, const std::vector<std::vector<uint8_t>>& certs);
    int Decrypt(ToolConf& conf, const std::string& label, const RcptInfo& recipient, const std::vector<std::vector<uint8_t>>& certs);

    void Locks(const char* file) const;

private:
    int writer_push(CDocWriter& writer, const std::vector<libcdoc::Recipient>& keys, const std::vector<std::string>& files);
    int Decrypt(const std::unique_ptr<CDocReader>& rdr, unsigned int lock_idx, const std::string& base_path);

    std::string GenerateRandomSequence() const;
};

}

#endif // CDOCCHIPHER_H
