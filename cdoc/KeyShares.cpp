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

#define __KEYSHARES_CPP__

#include "KeyShares.h"

#include "Crypto.h"
#include "CryptoBackend.h"
#include "ILogger.h"
#include "Utils.h"
#include "json/jwt.h"

#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/sha.h>

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"

#include <chrono>
#include <thread>
#include <iostream>

//
// https://github.com/SK-EID/smart-id-documentation
//

struct SIDResponse {
    // End result of the transaction
    enum EndResult {
        NONE,
        // session was completed successfully, there is a certificate, document number and possibly signature in return structure
        OK,
        // user refused the session
        USER_REFUSED,
        // there was a timeout, i.e. end user did not confirm or refuse the operation within given timeframe
        TIMEOUT,
        // for some reason, this RP request cannot be completed. User must either check his/her Smart-ID mobile application or turn to customer support for getting the exact reason
        DOCUMENT_UNUSABLE,
        // in case the multiple-choice verification code was requested, the user did not choose the correct verification code
        WRONG_VC,
        // user app version does not support any of the allowedInteractionsOrder interactions
        REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP,
        // user has multiple accounts and pressed Cancel on device choice screen on any device
        USER_REFUSED_CERT_CHOICE,
        // user pressed Cancel on PIN screen. Can be from the most common displayTextAndPIN flow or from verificationCodeChoice flow when user chosen the right code and then pressed cancel on PIN screen
        USER_REFUSED_DISPLAYTEXTANDPIN,
        // user cancelled verificationCodeChoice screen
        USER_REFUSED_VC_CHOICE,
        // user cancelled on confirmationMessage screen
        USER_REFUSED_CONFIRMATIONMESSAGE,
        // user cancelled on confirmationMessageAndVerificationCodeChoice screen
        USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE
    };

    static EndResult parseEndResult(std::string_view val) {
        if (val == "OK") return OK;
        else if (val == "USER_REFUSED") return USER_REFUSED;
        else if (val == "TIMEOUT") return TIMEOUT;
        else if (val == "DOCUMENT_UNUSABLE") return DOCUMENT_UNUSABLE;
        else if (val == "WRONG_VC") return WRONG_VC;
        else if (val == "REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP") return REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP;
        else if (val == "USER_REFUSED_CERT_CHOICE") return USER_REFUSED_CERT_CHOICE;
        else if (val == "USER_REFUSED_DISPLAYTEXTANDPIN") return USER_REFUSED_DISPLAYTEXTANDPIN;
        else if (val == "USER_REFUSED_VC_CHOICE") return USER_REFUSED_VC_CHOICE;
        else if (val == "USER_REFUSED_CONFIRMATIONMESSAGE") return USER_REFUSED_CONFIRMATIONMESSAGE;
        else if (val == "USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE") return USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE;
        return NONE;
    }

    struct Signature {
        // Signature value, base64 encoded
        std::string value;
        // Signature algorithm, in the form of sha256WithRSAEncryption
        std::string algorithm;
    };

    // End result of the transaction
    EndResult endResult = NONE;
    // Document number, can be used in further signature and authentication requests to target the same device
    std::string documentNumber;
    std::string cert;

    Signature signature;
};

namespace libcdoc {

static result_t
waitForResult(SIDResponse& dst, httplib::SSLClient& cli, const std::string& path, const std::string& session_id, double seconds)
{
    double end = libcdoc::getTime() + seconds;
    std::string full = path + "/session/" + session_id + "?timeoutMs=" + std::to_string((int) (seconds * 1000));
    LOG_DBG("SID dession query path: {}", full);
    while (libcdoc::getTime() < end) {
        httplib::Result res = cli.Get(full);
        if (!res) {
            LOG_WARN("SID session query failed");
            return UNSPECIFIED_ERROR;
        }
        auto status = res->status;
        LOG_DBG("SID session query status: {}", status);
        if ((status < 200) || (status >= 300)) return UNSPECIFIED_ERROR;
        httplib::Response response = res.value();
        LOG_DBG("SID session query response: {}", response.body);

        picojson::value rsp;
        picojson::parse(rsp, response.body);
        if (!rsp.is<picojson::object>()) {
            LOG_WARN("Response is not a JSON object");
            return UNSPECIFIED_ERROR;
        }
        // State
        picojson::value v = rsp.get("state");
        if (!v.is<std::string>()) {
            LOG_WARN("State is not a string");
            return UNSPECIFIED_ERROR;
        }
        std::string str = v.get<std::string>();
        if (str == "RUNNING") {
            // Puse for 0.5 seconds and repeat
            std::chrono::milliseconds duration(500);
            std::this_thread::sleep_for(duration);
            continue;
        } else if (str != "COMPLETE") {
            LOG_WARN("Invalid SmartID state: {}", str);
            return UNSPECIFIED_ERROR;
        }
        // State is complete, check for end result
        v = rsp.get("result");
        if (!v.is<picojson::object>()) {
            LOG_WARN("Result is not a JSON object");
            return UNSPECIFIED_ERROR;
        }
        str = v.get("endResult").get<std::string>();
        dst.endResult = SIDResponse::parseEndResult(str);
        if (dst.endResult != SIDResponse::OK) {
            LOG_WARN("EndResult is not OK: {}", str);
            return UNSPECIFIED_ERROR;
        }
        // End result is OK
        dst.documentNumber = v.get("documentNumber").get<std::string>();
        // Signature
        v = rsp.get("signature");
        if (v.is<picojson::object>()) {
            dst.signature.value = v.get("value").get<std::string>();
            dst.signature.algorithm = v.get("algorithm").get<std::string>();
        }
        // Certificate
        v = rsp.get("cert");
        if (v.is<picojson::object>()) {
            dst.cert = v.get("value").get<std::string>();
        }
        return OK;
    }
    // Timeout
    return UNSPECIFIED_ERROR;
}

}

static std::string
toBase64URL(const std::string& data)
{
    return jwt::base::details::encode(data, jwt::alphabet::base64url::data(), "");
}

static std::string
toBase64URL(const std::vector<uint8_t>& data)
{
    return toBase64URL(std::string((const char *) data.data(), data.size()));
}

libcdoc::result_t
libcdoc::signSID(std::vector<uint8_t>& dst, std::vector<uint8_t>& cert,
    const std::string& url, const std::string& rp_uuid, const std::string& rp_name,
    const std::string& rcpt_id, const std::vector<uint8_t>& digest, CryptoBackend::HashAlgorithm algo)
{
    std::string certificateLevel = "QUALIFIED";
    std::string nonce = toBase64URL(Crypto::random(16));

    picojson::object obj = {
        {"relyingPartyUUID", picojson::value(rp_uuid)},
        {"relyingPartyName", picojson::value(rp_name)},
        {"certificateLevel", picojson::value(certificateLevel)},
        {"nonce", picojson::value(nonce)}
    };
    picojson::value query(obj);
    LOG_DBG("JSON:{}", query.serialize());

    std::string host, path;
    int port;
    int result = libcdoc::parseURL(url, host, port, path);
    if (result != libcdoc::OK) return result;
    if (path == "/") path.clear();
    LOG_DBG("URL:{}", url);
    LOG_DBG("HOST:{}", host);
    LOG_DBG("PORT:{}", port);
    LOG_DBG("PATH:{}", path);

    LOG_DBG("Starting client: {} {}", host, port);
    httplib::SSLClient cli(host, port);

    std::vector<std::vector<uint8_t>> certs;
    LOG_DBG("Fetching certs");
    //getPeerTLSCertificates(certs);
    if (!certs.empty()) {
        LOG_DBG("Loading certs");
        SSL_CTX *ctx = cli.ssl_context();
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
        X509_STORE *store = SSL_CTX_get_cert_store(ctx);
        X509_STORE_set_flags(store, X509_V_FLAG_TRUSTED_FIRST | X509_V_FLAG_PARTIAL_CHAIN);
        for (const std::vector<uint8_t>& c : certs) {
            auto x509 = Crypto::toX509(c);
            if (!x509) return CRYPTO_ERROR;
            X509_STORE_add_cert(store, x509.get());
        }
        cli.enable_server_certificate_verification(true);
        cli.enable_server_hostname_verification(true);
    } else {
        LOG_WARN("SmartID server's certificate list is empty");
        cli.enable_server_certificate_verification(false);
        cli.enable_server_hostname_verification(false);
    }

    //
    // Let user choose certificate (if multiple)
    //
    std::string full = path + "/certificatechoice/" + rcpt_id;
    LOG_DBG("SmartID path: {}", full);
    httplib::Result res = cli.Post(full, query.serialize(), "application/json");
    if (!res) {
        LOG_WARN("SmartID query failed");
        return UNSPECIFIED_ERROR;
    }
    auto status = res->status;
    LOG_DBG("Status: {}", status);
    if ((status < 200) || (status >= 300)) return UNSPECIFIED_ERROR;
    httplib::Response rsp = res.value();
    LOG_DBG("Response: {}", rsp.body);
    picojson::value v;
    picojson::parse(v, rsp.body);
    std::string sessionID  = v.get("sessionID").get<std::string>();
    LOG_DBG("SessionID: {}", sessionID);

    SIDResponse sidrsp;
    result = waitForResult(sidrsp, cli, path, sessionID, 60);
    if (result != OK) {
        LOG_WARN("Wait for response failed: {}", result);
        return UNSPECIFIED_ERROR;
    }
    LOG_DBG("Document number: {}", sidrsp.documentNumber);
    LOG_DBG("Certificate: {}", sidrsp.cert);

    //
    // Sign
    //
    std::string algo_names[] = {"SHA224", "SHA256", "SHA384", "SHA512"};
    std::string algo_name = algo_names[(int) algo];

    // Generate code
    uint8_t b[32];
    SHA256(digest.data(), digest.size(), b);
	unsigned int code = ((b[30] << 8) | b[31]) % 10000;
    LOG_DBG("Code: {}", code);

    picojson::object aio1 = {
        {"type", picojson::value("confirmationMessageAndVerificationCodeChoice")},
        {"displayText200", picojson::value("Do you want to decrypt the document")}
    };
    picojson::array aio = {
        picojson::value(aio1)
    };
    picojson::object qobj = {
        {"relyingPartyUUID", picojson::value(rp_uuid)},
        {"relyingPartyName", picojson::value(rp_name)},
		{"hash", picojson::value(toBase64(digest))},
		{"hashType", picojson::value(algo_name)},
        {"allowedInteractionsOrder",
            picojson::value(aio)
        }
    };
    query = picojson::value(qobj);
    LOG_DBG("JSON:{}", query.serialize());
    //
    // Sign digest
    //
    full = path + "/authentication/" + rcpt_id;
    LOG_DBG("SmartID path: {}", full);
    res = cli.Post(full, query.serialize(), "application/json");
    if (!res) {
        LOG_WARN("SmartID query failed");
        return UNSPECIFIED_ERROR;
    }
    status = res->status;
    LOG_DBG("Status: {}", status);
    if ((status < 200) || (status >= 300)) return UNSPECIFIED_ERROR;
    rsp = res.value();
    LOG_DBG("Response: {}", rsp.body);
    picojson::parse(v, rsp.body);
    sessionID  = v.get("sessionID").get<std::string>();
    LOG_DBG("SessionID: {}", sessionID);

    sidrsp = {};
    result = waitForResult(sidrsp, cli, path, sessionID, 60);
    if (result != OK) {
        LOG_WARN("Wait for response failed: {}", result);
        return UNSPECIFIED_ERROR;
    }
    LOG_DBG("Document number: {}", sidrsp.documentNumber);
    LOG_DBG("Certificate: {}", sidrsp.cert);
    LOG_DBG("Signature: {}", sidrsp.signature.value);
    LOG_DBG("Algorithm: {}", sidrsp.signature.algorithm);

    dst = fromBase64(sidrsp.signature.value);
    cert = fromBase64(sidrsp.cert);

    return OK;
}

using namespace libcdoc;


struct SIDJWTSigner {
    libcdoc::SIDSigner *parent;

    SIDJWTSigner(libcdoc::SIDSigner *_parent) : parent(_parent) {}

    std::string sign(const std::string& data, std::error_code& ec) const;
    void verify(const std::string& data, const std::string& signature, std::error_code& ec) const;
    std::string name() const { return "RS256"; }
};

std::string
SIDJWTSigner::sign(const std::string& data, std::error_code& ec) const
{
    // RIA proxy for SmartID
    std::string url ="https://sid.demo.sk.ee/smart-id-rp/v2";
    std::string relyingPartyUUID = "00000000-0000-0000-0000-000000000000";
    std::string relyingPartyName = "DEMO";
    libcdoc::CryptoBackend::HashAlgorithm algo = libcdoc::CryptoBackend::SHA_256;

    LOG_DBG("Signing: {} {}", data.size(), data);
    ec.clear();

    std::vector<uint8_t> dst;
    std::vector<uint8_t> b(32);
    SHA256((uint8_t *) data.c_str(), data.size(), b.data());
    // The const cast is nasty, think about it
    signSID(dst, parent->cert, url, relyingPartyUUID, relyingPartyName, parent->rcpt_id, b, algo);

    ///std::vector<uint8_t> b(32);
    //SHA256((uint8_t *) data.c_str(), data.size(), b.data());
    LOG_DBG("Signature:{}", toHex(dst));
    LOG_DBG("SignatureB64:{}", toBase64URL(dst));
    return std::string((const char *) dst.data(), dst.size());
}

void
SIDJWTSigner::verify(const std::string& data, const std::string& signature, std::error_code& ec) const
{
    ec.clear();
    std::vector<uint8_t> b(32);
    SHA256((uint8_t *) data.c_str(), data.size(), b.data());
    std::string sig = toBase64URL(b);
    if (sig != signature) {
        LOG_WARN("Signature does not match!");
    } else {
        LOG_INFO("Signature is correct!");
    }
}

result_t
libcdoc::SIDSigner::generateTickets(std::vector<std::string>& dst, std::vector<libcdoc::ShareData>& shares)
{
    SIDJWTSigner jwtsig(this);

    // Create list of individual disclosures
    std::vector<Disclosure> disclosures;
    for (auto share : shares) {
        Disclosure d({}, share.getURL());
        std::cerr << "Disclosure:" << d.json << std::endl;
        disclosures.push_back(d);
    }
    // Disclosure of the whole list
    Disclosure aud("aud", disclosures);
    std::cerr << "aud:" << aud.json << std::endl;

    // Create JWT container
    picojson::array _sd({picojson::value(aud.getHash())});
	std::string token = jwt::create()
						   .set_type("vnd.cdoc2.auth-token.v1+sd-jwt")
                           .set_algorithm("RS256")
						   .set_payload_claim("iss", picojson::value(rcpt_id))
						   .set_payload_claim("_sd", picojson::value(_sd))
						   .set_payload_claim("_sd_alg", picojson::value("sha-256"))
						   .sign(jwtsig);
    std::cerr << "Token:" << token << std::endl;

    // Append aud disclosure
    std::string jwt = token + "~" + toBase64URL(aud.json);

    // Create individual tickets by appending corresponding disclosures
    for (unsigned int i = 0; i < disclosures.size(); i++) {
        std::string disclosed = jwt + "~" + toBase64URL(disclosures[i].json) + "~";
        dst.push_back(disclosed);
        std::cerr << "disclosed:" << disclosed << std::endl;
    }

    //cert = signer.cert;
    return OK;
}

libcdoc::ShareData::ShareData(const std::string& _base_url, const std::string& _share_id, const std::string& _nonce)
: base_url(_base_url), share_id(_share_id), nonce(_nonce)
{
}

std::string
libcdoc::ShareData::getURL()
{
    return base_url + "key-shares/" + share_id + "?nonce=" + nonce;
}

libcdoc::Disclosure::Disclosure(const std::string name, const std::string& val)
{
    salt64 = toBase64URL(libcdoc::Crypto::random(18));
    //
    // [SALT, HASH]
    // [SALT, NAME, HASH]
    //
    std::vector<picojson::value> v;
    if (name.empty()) {
        v = {
            picojson::value(salt64),
            picojson::value(val)
        };
    } else {
        v = {
            picojson::value(salt64),
            picojson::value(name),
            picojson::value(val)
        };
    }
    json = picojson::value(v).serialize();
}

libcdoc::Disclosure::Disclosure(const std::string name, std::vector<Disclosure>& val)
{
    salt64 = toBase64URL(libcdoc::Crypto::random(18));
    //
    // [SALT, [{..., HASH}, {..., HASH}...]
    // [SALT, NAME, [{..., HASH}, {..., HASH}...]
    //
    std::vector<picojson::value> l;
    for (auto d : val) {
        picojson::object o({
            {"...", picojson::value(d.getHash())}
        });
        l.push_back(picojson::value(o));
        std::cerr << picojson::value(o).serialize() << std::endl;
    }
    std::vector<picojson::value> v;
    if (name.empty()) {
        v = {
            picojson::value(salt64),
            picojson::value(l)
        };
    } else {
        v = {
            picojson::value(salt64),
            picojson::value(name),
            picojson::value(l)
        };
    }
    json = picojson::value(v).serialize();
}

std::string
libcdoc::Disclosure::getHash()
{
    std::string b64 = toBase64URL(json);
    std::vector<uint8_t> b(32);
    SHA256((uint8_t *) b64.c_str(), b64.size(), b.data());
    return toBase64URL(b);
}
