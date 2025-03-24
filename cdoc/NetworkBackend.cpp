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

#include "NetworkBackend.h"

#include "Crypto.h"
#include "CryptoBackend.h"
#include "Utils.h"
#include "utils/memory.h"
#include "ILogger.h"

#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/bio.h>
#include <openssl/http.h>
#include <openssl/ssl.h>

#include "json.hpp"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"

#include <chrono>

#if defined(_WIN32) || defined(_WIN64)
#include <Windows.h>
#endif

#define keyserver_id "00000000-0000-0000-0000-000000000000";
#define GET_HOST "cdoc2-keyserver.test.riaint.ee"
#define GET_PORT 8444
#define POST_HOST "cdoc2-keyserver.test.riaint.ee"
#define POST_PORT 8443

using namespace std::literals::chrono_literals;

using EC_KEY_sign = int (*)(int type, const unsigned char *dgst, int dlen, unsigned char *sig, unsigned int *siglen, const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey);
using EC_KEY_sign_setup = int (*)(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp);

static ECDSA_SIG* ecdsa_do_sign(const unsigned char *dgst, int dgst_len, const BIGNUM *inv, const BIGNUM *rp, EC_KEY *eckey);
static int rsa_sign(int type, const unsigned char *m, unsigned int m_len, unsigned char *sigret, unsigned int *siglen, const ::RSA *rsa);

struct Private {
    libcdoc::unique_free_t<X509> x509{nullptr, X509_free};
    EVP_PKEY *pkey = nullptr;

    RSA_METHOD *rsamethod = nullptr;
    EC_KEY_METHOD *ecmethod = nullptr;

    explicit Private(libcdoc::NetworkBackend *backend, std::vector<uint8_t> client_cert) {
        if (client_cert.empty()) return;
        x509 = libcdoc::Crypto::toX509(client_cert);
        if (!x509) return;
        pkey = X509_get_pubkey(x509.get());
        if (!pkey) return;
        int id = EVP_PKEY_get_id(pkey);
        if (id == EVP_PKEY_EC) {
            ecmethod = EC_KEY_METHOD_new(EC_KEY_get_default_method());
            EC_KEY_sign sign = nullptr;
            EC_KEY_sign_setup sign_setup = nullptr;
            EC_KEY_METHOD_get_sign(ecmethod, &sign, &sign_setup, nullptr);
            EC_KEY_METHOD_set_sign(ecmethod, sign, sign_setup, ecdsa_do_sign);

            auto *ec = (EC_KEY *) EVP_PKEY_get1_EC_KEY(pkey);
            EC_KEY_set_method(ec, ecmethod);
            EC_KEY_set_ex_data(ec, 0, backend);
            EVP_PKEY_set1_EC_KEY(pkey, ec);
        } else if (id == EVP_PKEY_RSA) {
            rsamethod = RSA_meth_dup(RSA_get_default_method());
            RSA_meth_set1_name(rsamethod, "libcdoc");
            RSA_meth_set_sign(rsamethod, rsa_sign);

            RSA *rsa = (RSA *) EVP_PKEY_get1_RSA(pkey);
            RSA_set_method(rsa, rsamethod);
            RSA_set_ex_data(rsa, 0, backend);
            EVP_PKEY_set1_RSA(pkey, rsa);
        }
    }

    ~Private() {
        if (pkey) EVP_PKEY_free(pkey);
        if (rsamethod) RSA_meth_free(rsamethod);
        if (ecmethod) EC_KEY_METHOD_free(ecmethod);
    }
};


std::string
libcdoc::NetworkBackend::getLastErrorStr(result_t code) const
{
	switch (code) {
	case OK:
		return "";
	case NOT_IMPLEMENTED:
		return "NetworkBackend: Method not implemented";
	case INVALID_PARAMS:
		return "NetworkBackend: Invalid parameters";
	case NETWORK_ERROR:
		return "NetworkBackend: Network error";
	default:
		break;
	}
	return "Internal error";
}

#if LIBCDOC_TESTING
int64_t
libcdoc::NetworkBackend::test(std::vector<std::vector<uint8_t>> &dst)
{
    LOG_TRACE("NetworkBackend::test::Native superclass");
    return OK;
}
#endif

libcdoc::result_t
libcdoc::NetworkBackend::sendKey (CapsuleInfo& dst, const std::string& url, const std::vector<uint8_t>& rcpt_key, const std::vector<uint8_t> &key_material, const std::string& type)
{
    nlohmann::json req_json = {
        {"recipient_id", libcdoc::toBase64(rcpt_key)},
        {"ephemeral_key_material", libcdoc::toBase64(key_material)},
        {"capsule_type", type }
    };
    std::string req_str = req_json.dump();

    std::string host, path;
    int port;
    int result = libcdoc::parseURL(url, host, port, path);
    if (result != libcdoc::OK) return result;
    if (path == "/") path.clear();

    httplib::SSLClient cli(host, port);

    std::vector<std::vector<uint8_t>> certs;
    getPeerTLSCertificates(certs);
    if (!certs.empty()) {
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
        cli.enable_server_certificate_verification(false);
        cli.enable_server_hostname_verification(false);
    }

    std::string full = path + "/key-capsules";
    httplib::Result res = cli.Post(full, req_str, "application/json");
    if (!res) return NETWORK_ERROR;
    auto status = res->status;
    if ((status < 200) || (status >= 300)) return NETWORK_ERROR;

    httplib::Response rsp = res.value();
    std::string location = rsp.get_header_value("Location");
    if (location.empty()) return libcdoc::IO_ERROR;
    /* Remove /key-capsules/ */
    dst.transaction_id = location.substr(14);

    auto now = std::chrono::system_clock::now();
    // Get a days-precision chrono::time_point
    auto sd = floor<std::chrono::days>(now);
    // Record the time of day
    auto time_of_day = now - sd;
    // Convert to a y/m/d calendar data structure
    std::chrono::year_month_day ymd = sd;
    // Add the months
    ymd += std::chrono::months{6};
    // Add some policy for overflowing the day-of-month if desired
    if (!ymd.ok())
        ymd = ymd.year()/ymd.month()/std::chrono::last;
    // Convert back to system_clock::time_point
    std::chrono::system_clock::time_point later = std::chrono::sys_days{ymd} + time_of_day;
    auto ttt = std::chrono::system_clock::to_time_t(later);

    dst.expiry_time = ttt;

    return OK;
}

libcdoc::result_t
libcdoc::NetworkBackend::sendShare(std::string& dst, const std::string& url, const std::string& recipient, const std::vector<uint8_t>& share)
{
    // Create KeyShare container
    nlohmann::json req_json = {
        {"share", libcdoc::toBase64(share)},
        {"recipient", recipient}
    };
    std::string req_str = req_json.dump();
    LOG_DBG("POST keyshare to: {}", url);
    LOG_DBG("{}", req_str);

    std::string host, path;
    int port;
    int result = libcdoc::parseURL(url, host, port, path);
    if (result != libcdoc::OK) return result;
    if (path == "/") path.clear();

    LOG_DBG("Starting client: {} {}", host, port);
    httplib::SSLClient cli(host, port);

    std::vector<std::vector<uint8_t>> certs;
    LOG_DBG("Fetching certs");
    getPeerTLSCertificates(certs);
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
        LOG_WARN("Share servers' certificate list is empty");
        cli.enable_server_certificate_verification(false);
        cli.enable_server_hostname_verification(false);
    }

    // Build url and send request
    std::string full = path + "/key-shares";
    LOG_DBG("Full url: {}", full);
    httplib::Result res = cli.Post(full, req_str, "application/json");
    if (!res) return NETWORK_ERROR;
    auto status = res->status;
    LOG_DBG("Status: {}", status);
    if ((status < 200) || (status >= 300)) return NETWORK_ERROR;

    httplib::Response rsp = res.value();
    std::string location = rsp.get_header_value("Location");
    LOG_DBG("Location: {}", location);
    if (location.empty()) return libcdoc::IO_ERROR;
    /* Remove /key-shares/ */
    dst = location.substr(12);
    LOG_DBG("Share: {}", dst);

    return OK;
}

libcdoc::result_t
libcdoc::NetworkBackend::fetchKey (std::vector<uint8_t>& dst, const std::string& url, const std::string& transaction_id)
{
    std::string host, path;
    int port;
    int result = libcdoc::parseURL(url, host, port, path);
    if (path == "/") path.clear();
    if (result != libcdoc::OK) return result;

    std::vector<uint8_t> cert;
    result = getClientTLSCertificate(cert);
    if (result != OK) return result;
    std::unique_ptr<Private> d = std::make_unique<Private>(this, cert);
    if (!cert.empty() && (!d->x509 || !d->pkey)) return CRYPTO_ERROR;

    httplib::SSLClient cli(host, port, d->x509.get(), d->pkey);

    std::vector<std::vector<uint8_t>> certs;
    getPeerTLSCertificates(certs);
    if (!certs.empty()) {
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
        cli.enable_server_certificate_verification(false);
        cli.enable_server_hostname_verification(false);
    }

    std::string full = path + "/key-capsules/" + transaction_id;
    httplib::Result res = cli.Get(full);
    if (!res) return NETWORK_ERROR;
    httplib::Response rsp = res.value();
    auto status = rsp.status;
    if ((status < 200) || (status >= 300)) return NETWORK_ERROR;
    nlohmann::json rsp_json = nlohmann::json::parse(rsp.body);
    std::string ks = rsp_json["ephemeral_key_material"];
    std::vector<uint8_t> key_material = Crypto::decodeBase64((const uint8_t *) ks.c_str());
    dst.assign(key_material.cbegin(), key_material.cend());

    return libcdoc::OK;
}

libcdoc::result_t
libcdoc::NetworkBackend::fetchNonce(std::vector<uint8_t>& dst, const std::vector<uint8_t>& share_id)
{
    return libcdoc::NOT_IMPLEMENTED;
}

libcdoc::result_t
libcdoc::NetworkBackend::fetchShare(ShareInfo& share, const std::string& url, const std::string& share_id)
{
    return libcdoc::NOT_IMPLEMENTED;
}

ECDSA_SIG *
ecdsa_do_sign(const unsigned char *dgst, int dgst_len, const BIGNUM * /*inv*/, const BIGNUM * /*rp*/, EC_KEY *eckey)
{
    auto *backend = (libcdoc::NetworkBackend *) EC_KEY_get_ex_data(eckey, 0);
    std::vector<uint8_t> dst;
    std::vector<uint8_t> digest(dgst, dgst + dgst_len);
    int result = backend->signTLS(dst, libcdoc::CryptoBackend::SHA_512, digest);
    if (result != libcdoc::OK) {
        return nullptr;
    }
    int size_2 = (int) dst.size() / 2;
    ECDSA_SIG *sig = ECDSA_SIG_new();
    ECDSA_SIG_set0(sig,
                   BN_bin2bn(dst.data(), size_2, nullptr),
                   BN_bin2bn(dst.data() + size_2, size_2, nullptr));
    return sig;
}

int
rsa_sign(int type, const unsigned char *m, unsigned int m_len, unsigned char *sigret, unsigned int *siglen, const RSA *rsa)
{
    auto *backend = (libcdoc::NetworkBackend *) RSA_get_ex_data(rsa, 0);
    auto algo = libcdoc::CryptoBackend::SHA_512;
    switch (type) {
    case NID_sha224:
        algo = libcdoc::CryptoBackend::SHA_224;
        break;
    case NID_sha256:
        algo = libcdoc::CryptoBackend::SHA_256;
        break;
    case NID_sha384:
        algo = libcdoc::CryptoBackend::SHA_384;
        break;
    case NID_sha512:
        break;
    default:
        return 0;
    }
    std::vector<uint8_t> dst;
    std::vector<uint8_t> digest(m, m + m_len);
    int result = backend->signTLS(dst, algo, digest);
    if (result != libcdoc::OK) {
        return 0;
    }
    if (sigret && (*siglen >= dst.size())) {
        memcpy(sigret, dst.data(), dst.size());
    }
    *siglen = (unsigned int) dst.size();
    return 1;
}
