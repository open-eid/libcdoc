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
Recipient::makeSymmetric(std::string label, int32_t kdf_iter)
{
	Recipient rcpt(Type::SYMMETRIC_KEY);
	rcpt.label = std::move(label);
	rcpt.kdf_iter = kdf_iter;
	return rcpt;
}

Recipient
Recipient::makePublicKey(std::string label, const std::vector<uint8_t>& public_key, PKType pk_type)
{
    if (public_key.empty()) return Recipient(Type::NONE);
    Recipient rcpt(Type::PUBLIC_KEY);
    rcpt.label = std::move(label);
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
    Certificate x509(rcpt.cert);
    rcpt.rcpt_key = x509.getPublicKey();
    rcpt.pk_type = (x509.getAlgorithm() == libcdoc::Certificate::RSA) ? PKType::RSA : PKType::ECC;
    rcpt.expiry_ts = x509.getNotAfter();
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

static Recipient::EIDType
getEIDType(const std::vector<std::string>& policies)
{
    for (const auto& policy : policies)
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

static void
buildLabel(std::ostream& ofs, std::string_view type, const std::initializer_list<std::pair<std::string_view, std::string_view>> &components)
{
    ofs << LABELPREFIX;
    ofs << "v" << '=' << std::to_string(CDoc2::KEYLABELVERSION) << '&'
        << "type" << '=' << type;
    for (auto& [key, value] : components) {
        if (value.empty())
            continue;
        ofs << '&';
        ofs << urlEncode(key) << '=' << urlEncode(value);
    }
}

static void
BuildLabelEID(std::ostream& ofs, Recipient::EIDType type, const Certificate& x509)
{
    buildLabel(ofs, eid_strs[type], {
        {"cn", x509.getCommonName()},
        {"serial_number", x509.getSerialNumber()},
        {"last_name", x509.getSurname()},
        {"first_name", x509.getGivenName()},
    });
}

static void
BuildLabelCertificate(std::ostream &ofs, std::string_view file, const Certificate& x509)
{
    buildLabel(ofs, "cert", {
        {"file", file},
        {"cn", x509.getCommonName()},
        {"cert_sha1", toHex(x509.getDigest())}
    });
}

static void
BuildLabelPublicKey(std::ostream &ofs, const std::string file)
{
    buildLabel(ofs, "pub_key", {
        {"file", file}
    });
}

static void
BuildLabelSymmetricKey(std::ostream &ofs, const std::string& label, const std::string file)
{
    buildLabel(ofs, "secret", {
        {"label", label},
        {"file", file}
    });
}

static void
BuildLabelPassword(std::ostream &ofs, const std::string& label)
{
    buildLabel(ofs, "pw", {
        {"label", label}
    });
}

std::string
Recipient::getLabel(const std::vector<std::pair<std::string_view, std::string_view>> &extra) const
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
                BuildLabelPassword(ofs, key_name);
            } else {
                BuildLabelSymmetricKey(ofs, key_name, file_name);
            }
            break;
        case PUBLIC_KEY:
            if (!cert.empty()) {
                Certificate x509(cert);
                if (auto type = getEIDType(x509.policies()); type != EIDType::Unknown) {
                    BuildLabelEID(ofs, type, x509);
                } else {
                    BuildLabelCertificate(ofs, file_name, x509);
                }
            } else {
                BuildLabelPublicKey(ofs, file_name);
            }
            break;
        case KEYSHARE:
            break;
    }
    for (auto& [key, value] : extra) {
        if (value.empty())
            continue;
        ofs << '&';
        ofs << urlEncode(key) << '=' << urlEncode(value);
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

