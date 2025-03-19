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

libcdoc::result_t
libcdoc::authKeyshares(const std::string& rcpt_id, const std::vector<uint8_t>& digest)
{
    std::string relyingPartyUUID = "00000000-0000-0000-0000-000000000000";
    std::string relyingPartyName = "RIA DigiDoc";
    std::string certificateLevel = "QUALIFIED";
    std::string nonce = "SID_NONCE";

    picojson::value query((std::map<std::string, picojson::value>) {
        {"relyingPartyUUID", picojson::value(relyingPartyUUID)},
        {"relyingPartyName", picojson::value(relyingPartyName)},
        {"certificateLevel", picojson::value(certificateLevel)},
        {"nonce", picojson::value(nonce)}
    });
    LOG_DBG("JSON:{}", query.serialize());

    // RIA proxy for SmartID
    std::string url ="https://eid-dd.ria.ee/sid/v2";
    LOG_DBG("URL:{}", url);

    std::string host, path;
    int port;
    int result = libcdoc::parseURL(url, host, port, path);
    if (result != libcdoc::OK) return result;
    if (path == "/") path.clear();
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
    CryptoBackend::HashAlgorithm algo = CryptoBackend::SHA_256;
    std::string algo_names[] = {"SHA224", "SHA256", "SHA384", "SHA512"};
    std::string algo_name = algo_names[(int) algo];

    // Generate code
    uint8_t dst[32];
    SHA256(digest.data(), digest.size(), dst);
	uint code = ((dst[30] << 8) | dst[31]) % 10000;
    LOG_DBG("Code: {}", code);

    query.set((picojson::object) {
        {"relyingPartyUUID", picojson::value(relyingPartyUUID)},
        {"relyingPartyName", picojson::value(relyingPartyName)},
        {"certificateLevel", picojson::value(certificateLevel)},
		{"hash", picojson::value(libcdoc::toBase64(digest))},
		{"hashType", picojson::value(algo_name)},
        {"allowedInteractionsOrder",
            picojson::value((picojson::array) {
                picojson::value((picojson::object) {
                    {"type", picojson::value("confirmationMessageAndVerificationCodeChoice")},
                    {"displayText200", picojson::value("Do you want to decrypt the document")}
                })
            })
        }
    });
    LOG_DBG("JSON:{}", query.serialize());
    //
    // Sign digest
    //
    full = path + "/signature/document/" + sidrsp.documentNumber;
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

    return OK;
}

void
libcdoc::fetchKeyShare(const libcdoc::ShareAccessData& acc)
{
    LOG_DBG("Share data: {} {} {}", acc.base_url, acc.share_id, acc.nonce);
}
