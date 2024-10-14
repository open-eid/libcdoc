#define __LOCK_CPP__

#include "Certificate.h"

#include "Lock.h"

namespace libcdoc {

bool
Lock::hasTheSameKey(const Lock& other) const
{
	if (!isPKI()) return false;
	if (!other.isPKI()) return false;
	const LockPKI& pki = static_cast<const LockPKI&>(*this);
	const LockPKI& other_pki = static_cast<const LockPKI&>(other);
	return pki.rcpt_key == other_pki.rcpt_key;
}

bool
Lock::hasTheSameKey(const std::vector<uint8_t>& public_key) const
{
	if (!isPKI()) return false;
	const LockPKI& pki = static_cast<const LockPKI&>(*this);
	if (pki.rcpt_key.empty() || public_key.empty()) return false;
	return pki.rcpt_key == public_key;
}

LockCert::LockCert(Type _type, const std::string& _label, const std::vector<uint8_t> &c)
	: LockPKI(_type)
{
	label = _label;
	setCert(c);
}

void
LockCert::setCert(const std::vector<uint8_t> &_cert)
{
	cert = _cert;
	Certificate ssl(_cert);
	std::vector<uint8_t> pkey = ssl.getPublicKey();
	Certificate::Algorithm algo = ssl.getAlgorithm();

	rcpt_key = pkey;
	pk_type = (algo == libcdoc::Certificate::RSA) ? PKType::RSA : PKType::ECC;
}

LockServer *
LockServer::fromKey(const std::vector<uint8_t> _key, PKType _pk_type) {
	return new LockServer(_key, _pk_type);
}

} // namespace libcdoc

