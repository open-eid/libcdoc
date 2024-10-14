#pragma once

#include <string>
#include <vector>

#include "CDocReader.h"

class Token;

class CDoc1Reader : public libcdoc::CDocReader
{
public:
	CDoc1Reader(const std::string &file);
	~CDoc1Reader();

	const libcdoc::Lock *getDecryptionLock(const std::vector<uint8_t>& cert) override final;
	int getFMK(std::vector<uint8_t>& fmk, const libcdoc::Lock *lock) override final;
	int decrypt(const std::vector<uint8_t>& fmk, libcdoc::MultiDataConsumer *dst) override final;

	const std::vector<libcdoc::Lock *>& getLocks() override;
private:
	CDoc1Reader(const CDoc1Reader &) = delete;
	CDoc1Reader &operator=(const CDoc1Reader &) = delete;
	std::vector<unsigned char> decryptData(const std::vector<unsigned char> &key);
	class Private;
	Private *d;
};
