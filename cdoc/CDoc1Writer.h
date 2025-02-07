#pragma once

#include <string>
#include <vector>

#include "CDocWriter.h"

class CDoc1Writer : public libcdoc::CDocWriter
{
public:
	CDoc1Writer(libcdoc::DataConsumer *dst, bool take_ownership, const std::string &method = "http://www.w3.org/2009/xmlenc11#aes256-gcm");
	~CDoc1Writer();

    libcdoc::result_t beginEncryption() override final;
    libcdoc::result_t addRecipient(const libcdoc::Recipient& rcpt) override final;
    libcdoc::result_t addFile(const std::string& name, size_t size) override final;
    libcdoc::result_t writeData(const uint8_t *src, size_t size) override final;
    libcdoc::result_t finishEncryption() override final;

    libcdoc::result_t encrypt(libcdoc::MultiDataSource& src, const std::vector<libcdoc::Recipient>& keys) final;
private:
	CDoc1Writer(const CDoc1Writer &) = delete;
	CDoc1Writer &operator=(const CDoc1Writer &) = delete;
	class Private;
	Private *d;
};
