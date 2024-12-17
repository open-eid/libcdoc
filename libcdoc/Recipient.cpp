#define __RECIPIENT_CPP__

#include "Recipient.h"

#include "Certificate.h"
#include "Crypto.h"
#include "Utils.h"

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
    if (pk_type == PKType::ECC && public_key[0] == 0x30)
    {
        // 0x30 identifies SEQUENCE tag in ASN.1 encoding
        auto evp = Crypto::fromECPublicKeyDer(public_key);
        rcpt.rcpt_key = Crypto::toPublicKeyDer(evp.get());
    }
    else
    {
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

static constexpr std::string_view type_strs[] = {
    "ID-card",
    "Digi-ID",
    "Digi-ID E-RESIDENT"
};

std::string
Recipient::buildLabel(std::vector<std::pair<std::string_view, std::string_view>> components)
{
    std::ostringstream ofs;
    ofs << "data:";
    bool first = true;
    for (auto& c : components) {
        if (!c.second.empty()) {
            if (!first) ofs << '&';
            ofs << libcdoc::urlEncode(c.first) << '=' << libcdoc::urlEncode(c.second);
            first = false;
        }
    }
    return ofs.str();
}

std::string
Recipient::BuildLabelEID(int version, EIDType type, const std::string& cn, const std::string& serial_number, const std::string& last_name, const std::string& first_name)
{
    return buildLabel({
        {"v", std::to_string(version)},
        {"type", type_strs[type]},
        {"serial_number", serial_number},
        {"last_name", last_name},
        {"first_name", first_name}
    });
}

std::string
Recipient::BuildLabelCertificate(int version, const std::string file, const std::string& cn, const std::vector<uint8_t>& cert_sha1)
{
    return buildLabel({
        {"v", std::to_string(version)},
        {"type", "cert"},
        {"file", file},
        {"cn", cn},
        {"cert_sha1", toHex(cert_sha1)}
    });
}

std::string
Recipient::BuildLabelPublicKey(int version, const std::string file)
{
    return buildLabel({
        {"v", std::to_string(version)},
        {"type", "pub_key"},
        {"file", file}
    });
}

std::string
Recipient::BuildLabelSymmetricKey(int version, const std::string& label, const std::string file)
{
    return buildLabel({
        {"v", std::to_string(version)},
        {"type", "secret"},
        {"label", label},
        {"file", file}
    });
}

std::string
Recipient::BuildLabelPassword(int version, const std::string& label)
{
    return buildLabel({
        {"v", std::to_string(version)},
        {"type", "pw"},
        {"label", label}
    });
}

} // namespace libcdoc

