#define __LOCK_CPP__

#include "Lock.h"

#include "Certificate.h"

#include <string_view>

namespace libcdoc {

std::string
Lock::getString(Params key) const
{
	const std::vector<uint8_t>& bytes = params.at(key);
	return std::string((const char *) bytes.data(), bytes.size());
}

int32_t
Lock::getInt(Params key) const
{
	const std::vector<uint8_t>& bytes = params.at(key);
	int32_t val = 0;
	for (int i = 0; (i < bytes.size()) && (i < 4); i++) {
		val = (val << 8) | bytes.at(i);
	}
	return val;
}

void
Lock::setInt(Params key, int32_t val)
{
	std::vector<uint8_t> bytes(4);
	for (int i = 0; i < 4; i++) {
		bytes[3 - i] = (val & 0xff);
		val = val >> 8;
	}
	params[key] = bytes;
}

bool
Lock::hasTheSameKey(const Lock& other) const
{
	if (!isPKI()) return false;
	if (!other.isPKI()) return false;
	if (!params.contains(Params::RCPT_KEY)) return false;
	if (!other.params.contains(Params::RCPT_KEY)) return false;
	std::vector<uint8_t> pki = getBytes(Params::RCPT_KEY);
	if (pki.empty()) return false;
	std::vector<uint8_t> other_pki = other.getBytes(Params::RCPT_KEY);
	if (other_pki.empty()) return false;
	return pki == other_pki;
}

bool
Lock::hasTheSameKey(const std::vector<uint8_t>& public_key) const
{
	if (!isPKI()) return false;
	if (!params.contains(Params::RCPT_KEY)) return false;
	if (public_key.empty()) return false;
	std::vector<uint8_t> pki = getBytes(Params::RCPT_KEY);
	if (pki.empty()) return false;
	return pki == public_key;
}

void
Lock::setCertificate(const std::vector<uint8_t> &_cert)
{
	setBytes(Params::CERT, _cert);
	Certificate ssl(_cert);
	std::vector<uint8_t> pkey = ssl.getPublicKey();
	Certificate::Algorithm algo = ssl.getAlgorithm();

	setBytes(Params::RCPT_KEY, pkey);
	pk_type = (algo == libcdoc::Certificate::RSA) ? PKType::RSA : PKType::ECC;
}

} // namespace libcdoc

