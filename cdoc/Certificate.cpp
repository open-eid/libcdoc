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

#include <openssl/x509v3.h>

#include "Crypto.h"
#include "Certificate.h"

namespace libcdoc {

Certificate::Certificate(const std::vector<uint8_t>& cert) noexcept
    : cert(Crypto::toX509(cert))
{
}

static std::string
getName(const unique_free_t<X509>& cert, int NID)
{
    std::string cn;
    if(!cert)
        return cn;
    X509_NAME *name = X509_get_subject_name(cert.get());
    if(!name)
        return cn;
    int pos = X509_NAME_get_index_by_NID(name, NID, -1);
    if(pos == -1)
        return cn;
    X509_NAME_ENTRY *e = X509_NAME_get_entry(name, pos);
    if(!e)
        return cn;
    char *data = nullptr;
    int size = ASN1_STRING_to_UTF8((uint8_t**)&data, X509_NAME_ENTRY_get_data(e));
    cn.assign(data, size_t(size));
    OPENSSL_free(data);
    return cn;
}

std::string
Certificate::getCommonName() const
{
	return getName(cert, NID_commonName);
}

std::string
Certificate::getGivenName() const
{
	return getName(cert, NID_givenName);
}

std::string
Certificate::getSurname() const
{
	return getName(cert, NID_surname);
}

std::string
Certificate::getSerialNumber() const
{
	return getName(cert, NID_serialNumber);
}



std::vector<std::string>
Certificate::policies() const
{
    constexpr int PolicyBufferLen = 50;
    std::vector<std::string> list;

    if(!cert)
        return list;

    auto p = static_cast<CERTIFICATEPOLICIES *>(X509_get_ext_d2i(cert.get(), NID_certificate_policies, nullptr, nullptr));
    auto cp = std::unique_ptr<CERTIFICATEPOLICIES,decltype(&CERTIFICATEPOLICIES_free)>(p,CERTIFICATEPOLICIES_free);
    if(!cp)
        return list;

    for(int i = 0; i < sk_POLICYINFO_num(cp.get()); i++) {
        POLICYINFO *pi = sk_POLICYINFO_value(cp.get(), i);
        char buf[PolicyBufferLen + 1]{};
        int len = OBJ_obj2txt(buf, PolicyBufferLen, pi->policyid, 1);
        if(len != NID_undef) {
            list.push_back(std::string(buf));
        }
    }

    return list;
}

std::vector<uint8_t>
Certificate::getPublicKey() const
{
    if(cert)
        return Crypto::toPublicKeyDer(X509_get0_pubkey(cert.get()));
    return {};
}

Certificate::Algorithm
Certificate::getAlgorithm() const
{
    if(!cert)
        return {};

    EVP_PKEY *pkey = X509_get0_pubkey(cert.get());
	int alg = EVP_PKEY_get_base_id(pkey);

	return (alg == EVP_PKEY_RSA) ? Algorithm::RSA : Algorithm::ECC;
}

std::vector<uint8_t> Certificate::getDigest()
{
    if(!cert)
        return {};

    const EVP_MD* digest_type = EVP_get_digestbyname("sha1");

    std::vector<uint8_t> digest(EVP_MAX_MD_SIZE);
    unsigned int digest_len = 0;

    if (X509_digest(cert.get(), digest_type, digest.data(), &digest_len))
    {
        digest.resize(digest_len);
    }
    else
    {
        digest.clear();
    }

    return digest;
}

} // namespace libcdoc
