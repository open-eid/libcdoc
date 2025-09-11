/*
 * libcdoc
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "Recipient.h"

#include "CDoc2.h"
#include "Certificate.h"
#include "Crypto.h"
#include "ILogger.h"
#include "Utils.h"

using namespace std;

namespace libcdoc {

/**
 * @brief Prefix with what starts machine generated Lock's label.
 */
constexpr string_view LABELPREFIX{"data:"};

/**
 * @brief String after label prefix indicating, the rest of the label is Base64 encoded.
 */
constexpr string_view LABELBASE64IND{";base64,"};

/**
 * @brief EID type values for machine-readable label
 */
static constexpr std::string_view eid_strs[] = {
    "Unknown",
    "ID-card",
    "Digi-ID",
    "Digi-ID E-RESIDENT"
};

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
    if (pk_type == PKType::ECC && public_key[0] == 0x30) {
        // 0x30 identifies SEQUENCE tag in ASN.1 encoding
        auto evp = Crypto::fromECPublicKeyDer(public_key);
        rcpt.rcpt_key = Crypto::toPublicKeyDer(evp.get());
    } else {
        rcpt.rcpt_key = public_key;
    }
	return rcpt;
}

Recipient
Recipient::makeCertificate(std::string label, std::vector<uint8_t> cert)
{
	Recipient rcpt(Type::PUBLIC_KEY);
	rcpt.label = std::move(label);
    rcpt.cert = std::move(cert);
	Certificate ssl(rcpt.cert);
    rcpt.rcpt_key = ssl.getPublicKey();
    rcpt.pk_type = (ssl.getAlgorithm() == libcdoc::Certificate::RSA) ? PKType::RSA : PKType::ECC;
	return rcpt;
}

Recipient
Recipient::makeServer(std::string label, std::vector<uint8_t> public_key, PKType pk_type, std::string server_id)
{
    Recipient rcpt(Type::PUBLIC_KEY);
    rcpt.label = std::move(label);
    rcpt.pk_type = pk_type;
    if (pk_type == PKType::ECC && public_key[0] == 0x30) {
        // 0x30 identifies SEQUENCE tag in ASN.1 encoding
        auto evp = Crypto::fromECPublicKeyDer(public_key);
        rcpt.rcpt_key = Crypto::toPublicKeyDer(evp.get());
    } else {
        rcpt.rcpt_key = std::move(public_key);
    }
    rcpt.server_id = std::move(server_id);
    return rcpt;
}

Recipient
Recipient::makeServer(std::string label, std::vector<uint8_t> cert, std::string server_id)
{
    Certificate x509(cert);
    Recipient rcpt = makeServer(std::move(label), x509.getPublicKey(), x509.getAlgorithm() == Certificate::Algorithm::RSA ? RSA : ECC, std::move(server_id));
    rcpt.cert = cert;
    return std::move(rcpt);
}

Recipient
Recipient::makeShare(const std::string& label, const std::string& server_id, const std::string& recipient_id)
{
    Recipient rcpt(Type::KEYSHARE);
    rcpt.label = label;
    rcpt.server_id = server_id;
    rcpt.id = recipient_id;
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

static std::string
buildLabel(std::vector<std::pair<std::string_view, std::string_view>> components)
{
    std::ostringstream ofs;
    ofs << LABELPREFIX;
    bool first = true;
    for (auto& [key, value] : components) {
        if (!value.empty()) {
            if (!first) ofs << '&';
            ofs << libcdoc::urlEncode(key) << '=' << libcdoc::urlEncode(value);
            first = false;
        }
    }
    return ofs.str();
}

static Recipient::EIDType
getEIDType(const std::vector<std::string>& policies)
{
    for (std::vector<std::string>::const_reference policy : policies)
    {
        if (policy.starts_with("1.3.6.1.4.1.51361.1.1.3") ||
            policy.starts_with("1.3.6.1.4.1.51361.1.2.3")) {
            return Recipient::EIDType::DigiID;
        }

        if (policy.starts_with("1.3.6.1.4.1.51361.1.1.4") ||
            policy.starts_with("1.3.6.1.4.1.51361.1.2.4")) {
            return Recipient::EIDType::DigiID_EResident;
        }

        if (policy.starts_with("1.3.6.1.4.1.51361.1.1") ||
            policy.starts_with("1.3.6.1.4.1.51455.1.1") ||
            policy.starts_with("1.3.6.1.4.1.51361.1.2") ||
            policy.starts_with("1.3.6.1.4.1.51455.1.2")) {
            return Recipient::EIDType::IDCard;
        }
    }

    // If the execution reaches so far then EID type determination failed.
    return Recipient::EIDType::Unknown;
}

static std::string
BuildLabelEID(const std::vector<uint8_t>& cert)
{
    Certificate x509(cert);
    Recipient::EIDType type = getEIDType(x509.policies());
    std::string cn = x509.getCommonName();
    std::string sn = x509.getSerialNumber();
    std::string gn = x509.getGivenName();
    if (!gn.empty()) {
        return buildLabel({
            {"v", std::to_string(CDoc2::KEYLABELVERSION)},
            {"type", eid_strs[type]},
            {"cn", cn},
            {"serial_number", sn}
        });
    } else {
        return buildLabel({
            {"v", std::to_string(CDoc2::KEYLABELVERSION)},
            {"type", eid_strs[type]},
            {"cn", cn},
            {"serial_number", sn},
            {"last_name", x509.getSurname()},
            {"first_name", gn}
        });
    }
}

static std::string
BuildLabelCertificate(std::string_view file, const std::vector<uint8_t>& cert)
{
    Certificate x509(cert);
    return buildLabel({
        {"v", std::to_string(CDoc2::KEYLABELVERSION)},
        {"type", "cert"},
        {"file", file},
        {"cn", x509.getCommonName()},
        {"cert_sha1", toHex(x509.getDigest())}
    });
}

static std::string
BuildLabelPublicKey(int version, const std::string file)
{
    return buildLabel({
        {"v", std::to_string(version)},
        {"type", "pub_key"},
        {"file", file}
    });
}

static std::string
BuildLabelSymmetricKey(int version, const std::string& label, const std::string file)
{
    return buildLabel({
        {"v", std::to_string(version)},
        {"type", "secret"},
        {"label", label},
        {"file", file}
    });
}

static std::string
BuildLabelPassword(int version, const std::string& label)
{
    return buildLabel({
        {"v", std::to_string(version)},
        {"type", "pw"},
        {"label", label}
    });
}

std::string
Recipient::getLabel(std::vector<std::pair<std::string_view, std::string_view>> extra) const
{
    LOG_DBG("Generating label");
    if (!label.empty()) return label;
    std::ostringstream ofs;
    switch(type) {
		case NONE:
            LOG_DBG("The recipient is not initialized");
            break;
        case SYMMETRIC_KEY:
            if (kdf_iter > 0) {
                ofs << BuildLabelPassword(CDoc2::KEYLABELVERSION, key_name);
            } else {
                ofs << BuildLabelSymmetricKey(CDoc2::KEYLABELVERSION, key_name, file_name);
            }
        case PUBLIC_KEY:
            if (!cert.empty()) {
                Certificate x509(cert);
                EIDType eid_type = getEIDType(x509.policies());
                if (eid_type != EIDType::Unknown) {
                    ofs << BuildLabelEID(cert);
                } else {
                    ofs << BuildLabelCertificate(file_name, cert);
                }
            } else {
                ofs << BuildLabelPublicKey(CDoc2::KEYLABELVERSION, file_name);
            }
        case KEYSHARE:
            break;
    }
    for (auto& [key, value] : extra) {
        if (!value.empty()) {
            ofs << '&';
            ofs << libcdoc::urlEncode(key) << '=' << libcdoc::urlEncode(value);
        }
    }
    LOG_DBG("Generated label: {}", ofs.str());
    return ofs.str();
}

map<string, string> Recipient::parseLabel(const string& label)
{
    // Check if provided label starts with the machine generated label prefix.
    if (!label.starts_with(LABELPREFIX))
    {
        return {};
    }

    string label_wo_prefix(label.substr(LABELPREFIX.size()));

    // Label to be processed
    string label_to_prcss;

    // We ignore mediatype part

    // Check, if the label is Base64 encoded
    string::size_type base64IndPos = label_wo_prefix.find(LABELBASE64IND);
    if (base64IndPos == string::npos)
    {
        label_to_prcss = std::move(label_wo_prefix);
    }
    else
    {
        string base64_label(label_wo_prefix.substr(base64IndPos + LABELBASE64IND.size()));
        vector<uint8_t> decodedLabel(fromBase64(base64_label));
        label_to_prcss.assign(decodedLabel.cbegin(), decodedLabel.cend());
    }

    map<string, string> parsed_label;
    vector<string> label_parts(split(label_to_prcss, '&'));
    for (vector<string>::const_reference part : label_parts)
    {
        vector<string> label_data_parts(split(part, '='));
        if (label_data_parts.size() != 2)
        {
            // Invalid label data. We just ignore them.
            LOG_ERROR("The label '{}' is invalid", label);
        }
        else
        {
            parsed_label[urlDecode(label_data_parts[0])] = urlDecode(label_data_parts[1]);
        }
    }

    return parsed_label;
}

} // namespace libcdoc

