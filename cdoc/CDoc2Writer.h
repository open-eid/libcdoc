#ifndef __CDOC2_WRITER_H__
#define __CDOC2_WRITER_H__

#include "CDocWriter.h"

class CDoc2Writer final: public libcdoc::CDocWriter {
public:
	explicit CDoc2Writer(libcdoc::DataConsumer *dst, bool take_ownership);
	~CDoc2Writer();

	int beginEncryption() override final;
	int addRecipient(const libcdoc::Recipient& rcpt) override final;
	int addFile(const std::string& name, size_t size) override final;
	int64_t writeData(const uint8_t *src, size_t size) override final;
	int finishEncryption() override final;

	int encrypt(libcdoc::MultiDataSource& src, const std::vector<libcdoc::Recipient>& keys) override final;
private:
	struct Private;

	std::unique_ptr<Private> priv;

	int encryptInternal(libcdoc::MultiDataSource& src, const std::vector<libcdoc::Recipient>& keys);
	int writeHeader(const std::vector<uint8_t>& header, const std::vector<uint8_t>& hhk);
	int buildHeader(std::vector<uint8_t>& header, const std::vector<libcdoc::Recipient>& keys, const std::vector<uint8_t>& fmk);
};

#endif
