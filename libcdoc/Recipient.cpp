#define __RECIPIENT_CPP__

#include "Recipient.h"

#include "Certificate.h"
#include "Crypto.h"

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
    if (public_key.empty()) return Recipient(Type::NONE);
    Recipient rcpt(Type::PUBLIC_KEY);
    rcpt.label = label;
    rcpt.pk_type = pk_type;
    if ((pk_type == PKType::ECC) && (public_key[0] == 0x30)) {
        auto evp = Crypto::fromECPublicKeyDer(public_key);
        rcpt.rcpt_key = Crypto::toPublicKeyDer(evp.get());
    } else {
        rcpt.rcpt_key = public_key;
    }
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

