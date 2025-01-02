#ifndef CDOCCHIPHER_H
#define CDOCCHIPHER_H

#include <map>
#include "CDocWriter.h"
#include "RcptInfo.h"
#include "ToolConf.h"

namespace libcdoc
{

typedef typename std::map<std::string, RcptInfo> Recipients;

class CDocChipher
{
public:
    CDocChipher() {}

    int Encrypt(ToolConf& conf, const Recipients& recipients, const std::vector<std::vector<uint8_t>>& certs);

    int Decrypt(ToolConf& conf, const Recipients& recipients, const std::vector<std::vector<uint8_t>>& certs);

    void Locks(const char* file) const;

private:
    int writer_push(CDocWriter& writer, const std::vector<libcdoc::Recipient>& keys, const std::vector<std::string>& files);
};

}

#endif // CDOCCHIPHER_H
