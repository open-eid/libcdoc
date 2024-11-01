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

	std::vector<libcdoc::Lock> getLocks() override final;
	bool getLockForCert(libcdoc::Lock& lock, const std::vector<uint8_t>& cert) override final;
	int getFMK(std::vector<uint8_t>& fmk, const libcdoc::Lock& lock) override final;
	int decrypt(const std::vector<uint8_t>& fmk, libcdoc::MultiDataConsumer *dst) override final;

	// Pull interface
	int beginDecryption(const std::vector<uint8_t>& fmk) override final;
	int nextFile(std::string& name, int64_t& size) override final;
	int64_t readData(uint8_t *dst, size_t size) override final;
	int finishDecryption() override final;
private:
	CDoc1Reader(const CDoc1Reader &) = delete;
	CDoc1Reader &operator=(const CDoc1Reader &) = delete;
	std::vector<unsigned char> decryptData(const std::vector<unsigned char> &key);
	class Private;
	Private *d;
};
