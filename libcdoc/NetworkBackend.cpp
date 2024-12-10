#define __NETWORK_BACKEND_CPP__

#include "NetworkBackend.h"

#include "CDoc.h"
#include "Crypto.h"
#include "CryptoBackend.h"
#include "json.hpp"
#include "Utils.h"

#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/bio.h>
#include <openssl/http.h>
#include "openssl/ssl.h"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"

#define GET_HOST "cdoc2-keyserver.test.riaint.ee"
#define GET_PORT 8444
#define POST_HOST "cdoc2-keyserver.test.riaint.ee"
#define POST_PORT 8443

struct libcdoc::DefaultNetworkBackend::Private {
    static ECDSA_SIG* ecdsa_do_sign(const unsigned char *dgst, int dgst_len, const BIGNUM *inv, const BIGNUM *rp, EC_KEY *eckey);
    static int rsa_sign(int type, const unsigned char *m, unsigned int m_len, unsigned char *sigret, unsigned int *siglen, const RSA *rsa);

    std::vector<X509 *> certs;

    RSA_METHOD *rsamethod = RSA_meth_dup(RSA_get_default_method());
    EC_KEY_METHOD *ecmethod = EC_KEY_METHOD_new(EC_KEY_get_default_method());

    explicit Private() {
        RSA_meth_set1_name(rsamethod, "libcdoc");
        RSA_meth_set_sign(rsamethod, Private::rsa_sign);
        using EC_KEY_sign = int (*)(int type, const unsigned char *dgst, int dlen, unsigned char *sig, unsigned int *siglen, const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey);
        using EC_KEY_sign_setup = int (*)(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp);
        EC_KEY_sign sign = nullptr;
        EC_KEY_sign_setup sign_setup = nullptr;
        EC_KEY_METHOD_get_sign(ecmethod, &sign, &sign_setup, nullptr);
        EC_KEY_METHOD_set_sign(ecmethod, sign, sign_setup, Private::ecdsa_do_sign);
    }
    ~Private() {
        for (auto cert : certs) {
            X509_free(cert);
        }
        //if (cert) X509_free(cert);
        //if (key) EVP_PKEY_free(key);
    }
};

ECDSA_SIG *
libcdoc::DefaultNetworkBackend::Private::ecdsa_do_sign(const unsigned char *dgst, int dgst_len, const BIGNUM * /*inv*/, const BIGNUM * /*rp*/, EC_KEY *eckey)
{
    auto *backend = (DefaultNetworkBackend *) EC_KEY_get_ex_data(eckey, 0);
    std::vector<uint8_t> dst;
    std::vector<uint8_t> digest(dgst, dgst + dgst_len);
    int result = backend->signTLS(dst, CryptoBackend::SHA_512, digest);
    if (result != OK) {
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
libcdoc::DefaultNetworkBackend::Private::rsa_sign(int type, const unsigned char *m, unsigned int m_len, unsigned char *sigret, unsigned int *siglen, const RSA *rsa)
{
    auto *backend = (DefaultNetworkBackend *) RSA_get_ex_data(rsa, 0);
    auto algo = CryptoBackend::SHA_512;
    switch (type) {
        case NID_sha224:
            algo = CryptoBackend::SHA_224;
            break;
        case NID_sha256:
            algo = CryptoBackend::SHA_256;
            break;
        case NID_sha384:
            algo = CryptoBackend::SHA_384;
            break;
        case NID_sha512:
            break;
        default:
            return 0;
    }
    std::vector<uint8_t> dst;
    std::vector<uint8_t> digest(m, m + m_len);
    int result = backend->signTLS(dst, algo, digest);
    if (result != OK) {
        return 0;
    }
    if (sigret && (*siglen >= dst.size())) {
        memcpy(sigret, dst.data(), dst.size());
    }
    *siglen = (unsigned int) dst.size();
    return 1;
}

libcdoc::DefaultNetworkBackend::DefaultNetworkBackend()
    : d(new Private)
{
}

libcdoc::DefaultNetworkBackend::~DefaultNetworkBackend()
{
    delete d;
}

int
libcdoc::DefaultNetworkBackend::sendKey (std::pair<std::string,std::string>& result, const Recipient& recipient, const std::vector<uint8_t> &key_material, const std::string &type)
{
    std::string keyserver_id = "00000000-0000-0000-0000-000000000000";
    /* Create request JSON */
    nlohmann::json req_json = {
        {"recipient_id", libcdoc::toBase64(recipient.rcpt_key)},
        {"ephemeral_key_material", libcdoc::toBase64(key_material)},
        {"capsule_type", type}
    };

    std::string req_str = req_json.dump();

    httplib::SSLClient cli(POST_HOST, POST_PORT);
    // Disable cert verification
    cli.enable_server_certificate_verification(false);
    // Disable host verification
    cli.enable_server_hostname_verification(false);

    httplib::Result res = cli.Post("/key-capsules", req_str, "application/json");
    auto status = res->status;
    if ((status < 200) || (status >= 300)) return NETWORK_ERROR;

    httplib::Response rsp = res.value();
    std::string transaction_id = rsp.get_header_value("Location");
    if (!transaction_id.empty()) {
        result.first = keyserver_id;
        /* Remove /key-capsules/ */
        result.second = transaction_id.substr(14);
        return OK;
    }
    return libcdoc::IO_ERROR;
}

int
libcdoc::DefaultNetworkBackend::fetchKey (std::vector<uint8_t>& dst, const std::string& keyserver_id, const std::string& transaction_id)
{
    std::vector<uint8_t> cert;
    int result = getTLSCertificate(cert);
    if (result != OK) return result;
    X509 *x509 = Crypto::toX509(cert);
    EVP_PKEY *pkey = EVP_PKEY_dup(X509_get0_pubkey(x509));
    int id = EVP_PKEY_get_id(pkey);
    if (id == EVP_PKEY_EC) {
        auto *ec = (EC_KEY *) EVP_PKEY_get1_EC_KEY(pkey);
        EC_KEY_set_method(ec, d->ecmethod);
        EC_KEY_set_ex_data(ec, 0, this);
        EVP_PKEY_set1_EC_KEY(pkey, ec);
    } else if (id == EVP_PKEY_RSA) {
        RSA *rsa = (RSA *) EVP_PKEY_get1_RSA(pkey);
        RSA_set_method(rsa, d->rsamethod);
        RSA_set_ex_data(rsa, 0, this);
        EVP_PKEY_set1_RSA(pkey, rsa);
    }
    httplib::SSLClient cli(GET_HOST, GET_PORT, x509, pkey);

    X509_STORE *store = SSL_CTX_get_cert_store(cli.ssl_context());
    X509_STORE_set_flags(store, X509_V_FLAG_TRUSTED_FIRST | X509_V_FLAG_PARTIAL_CHAIN);
    for(X509 *cert: d->certs) {
        X509_STORE_add_cert(store, cert);
    }
    cli.set_ca_cert_store(store);

    // Disable cert verification
    cli.enable_server_certificate_verification(false);
    // Disable host verification
    cli.enable_server_hostname_verification(false);

    httplib::Result res = cli.Get("/key-capsules/" + transaction_id);
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
