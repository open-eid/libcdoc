#define __RECIPIENT_CPP__

#include "Certificate.h"

#include "Recipient.h"

namespace libcdoc {

Recipient
Recipient::makeSymmetric(const std::string& label, int32_t kdf_iter)
{
	Recipient rcpt(Type::SYMMETRIC_KEY);
	rcpt.label = label;
	rcpt.kdf_iter = kdf_iter;
	return rcpt;
}

Recipient
Recipient::makePublicKey(const std::string& label, const std::vector<uint8_t>& public_key, PKType pk_type)
{
	Recipient rcpt(Type::PUBLIC_KEY);
	rcpt.label = label;
	rcpt.rcpt_key = public_key;
	rcpt.pk_type = pk_type;
	return rcpt;
}

Recipient
Recipient::makeCertificate(const std::string& label, const std::vector<uint8_t>& cert)
{
	Recipient rcpt(Type::CERTIFICATE);
	rcpt.label = label;
	rcpt.cert = cert;
	Certificate ssl(cert);
	std::vector<uint8_t> pkey = ssl.getPublicKey();
	Certificate::Algorithm algo = ssl.getAlgorithm();
	rcpt.rcpt_key = pkey;
	rcpt.pk_type = (algo == libcdoc::Certificate::RSA) ? PKType::RSA : PKType::ECC;
	return rcpt;
}

bool
Recipient::isTheSameRecipient(const Recipient& other) const
{
	if (!isPKI()) return false;
	if (!other.isPKI()) return false;
	return rcpt_key == other.rcpt_key;
}

bool
Recipient::isTheSameRecipient(const std::vector<uint8_t>& public_key) const
{
	if (!isPKI()) return false;
	if (rcpt_key.empty() || public_key.empty()) return false;
	return rcpt_key == public_key;
}

} // namespace libcdoc

