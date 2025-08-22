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

#include "CDoc1Writer.h"

#include "Crypto.h"
#include "DDocWriter.h"
#include "ILogger.h"
#include "Recipient.h"
#include "Utils.h"
#include "XmlWriter.h"
#include "utils/memory.h"

#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/x509.h>

using namespace libcdoc;

#define RET_ERROR(F) if (auto rv = F; rv < 0) return rv

struct FileEntry {
	std::string name;
	size_t size;
	std::vector<uint8_t> data;
};

/**
 * @class CDoc1Writer
 * @brief CDoc1Writer is used for encrypt data.
 */

struct CDoc1Writer::Private final: public XMLWriter
{
    static const XMLWriter::NS DENC, DS, XENC11, DSIG11;

    Private(DataConsumer &dst, std::string &last_error)
        : XMLWriter(dst)
        , lastError(last_error)
    {}

    std::string method = "http://www.w3.org/2009/xmlenc11#aes256-gcm";
    std::string documentFormat = "ENCDOC-XML|1.1";
    std::string &lastError;
    std::vector<FileEntry> files;
    std::vector<Recipient> rcpts;

    int64_t writeEncryptionProperties(bool use_ddoc);
    int64_t writeKeyInfo(bool use_ddoc, const Crypto::Key& transportKey);
    int64_t writeRecipient(const std::vector<uint8_t> &recipient, const Crypto::Key& transportKey);
};

const XMLWriter::NS CDoc1Writer::Private::DENC{ "denc", "http://www.w3.org/2001/04/xmlenc#" };
const XMLWriter::NS CDoc1Writer::Private::DS{ "ds", "http://www.w3.org/2000/09/xmldsig#" };
const XMLWriter::NS CDoc1Writer::Private::XENC11{ "xenc11", "http://www.w3.org/2009/xmlenc11#" };
const XMLWriter::NS CDoc1Writer::Private::DSIG11{ "dsig11", "http://www.w3.org/2009/xmldsig11#" };

CDoc1Writer::CDoc1Writer(DataConsumer *dst, bool take_ownership)
    : CDocWriter(1, dst, take_ownership)
{}

CDoc1Writer::~CDoc1Writer() noexcept = default;

int64_t CDoc1Writer::Private::writeEncryptionProperties(bool use_ddoc)
{
    RET_ERROR(writeElement(DENC, "EncryptionProperties", [&]() -> int64_t {
        RET_ERROR(writeTextElement(Private::DENC, "EncryptionProperty", {{"Name", "LibraryVersion"}}, "cdoc|0.0.1"));
        RET_ERROR(writeTextElement(Private::DENC, "EncryptionProperty", {{"Name", "DocumentFormat"}}, documentFormat));
        RET_ERROR(writeTextElement(Private::DENC, "EncryptionProperty", {{"Name", "Filename"}}, use_ddoc ? "tmp.ddoc" : files.at(0).name));
        for(const FileEntry &file: files)
        {
            RET_ERROR(writeTextElement(Private::DENC, "EncryptionProperty", {{"Name", "orig_file"}},
                file.name + "|" + std::to_string(file.size) + "|" + "application/octet-stream" + "|D0"));
        }
        return OK;
    }));
    return writeEndElement(Private::DENC); // EncryptedData
}

int64_t CDoc1Writer::Private::writeKeyInfo(bool use_ddoc, const Crypto::Key& transportKey)
{
    RET_ERROR(writeStartElement(Private::DENC, "EncryptedData", {{"MimeType", use_ddoc ? "http://www.sk.ee/DigiDoc/v1.3.0/digidoc.xsd" : "application/octet-stream"}}));
    RET_ERROR(writeElement(Private::DENC, "EncryptionMethod", {{"Algorithm", method}}));
    return writeElement(Private::DS, "KeyInfo", {}, [&]() -> int64_t {
        for (const Recipient& key : rcpts) {
            if (!key.isCertificate()) {
                lastError = "Invalid recipient type";
                LOG_ERROR("{}", lastError);
                return UNSPECIFIED_ERROR;
            }
            if(auto rv = writeRecipient(key.cert, transportKey); rv < 0) {
                lastError = "Failed to write Recipient info";
                LOG_ERROR("{}", lastError);
                return rv;
            }
        }
        return OK;
    });
}

int64_t CDoc1Writer::Private::writeRecipient(const std::vector<uint8_t> &recipient, const Crypto::Key& transportKey)
{
    auto peerCert = Crypto::toX509(recipient);
	if(!peerCert)
        return UNSPECIFIED_ERROR;
	std::string cn = [&]{
		std::string cn;
		X509_NAME *name = X509_get_subject_name(peerCert.get());
		if(!name)
			return cn;
		int pos = X509_NAME_get_index_by_NID(name, NID_commonName, 0);
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
	}();
    return writeElement(Private::DENC, "EncryptedKey", {{"Recipient", cn}}, [&]() -> int64_t {
		std::vector<uint8_t> encryptedData;
		auto *peerPKey = X509_get0_pubkey(peerCert.get());
		switch(EVP_PKEY_base_id(peerPKey))
		{
		case EVP_PKEY_RSA:
		{
			auto rsa = make_unique_ptr<RSA_free>(EVP_PKEY_get1_RSA(peerPKey));
			encryptedData.resize(size_t(RSA_size(rsa.get())));
			RSA_public_encrypt(int(transportKey.key.size()), transportKey.key.data(),
				encryptedData.data(), rsa.get(), RSA_PKCS1_PADDING);
            RET_ERROR(writeElement(Private::DENC, "EncryptionMethod", {{"Algorithm", Crypto::RSA_MTH}}));
            RET_ERROR(writeElement(Private::DS, "KeyInfo", [&] {
                return writeElement(Private::DS, "X509Data", [&] {
                    return writeBase64Element(Private::DS, "X509Certificate", recipient);
				});
            }));
			break;
		}
		case EVP_PKEY_EC:
		{
			auto *peerECKey = EVP_PKEY_get0_EC_KEY(peerPKey);
			int curveName = EC_GROUP_get_curve_name(EC_KEY_get0_group(peerECKey));
			auto priv = make_unique_ptr<EC_KEY_free>(EC_KEY_new_by_curve_name(curveName));
			EC_KEY_generate_key(priv.get());
			auto pkey = make_unique_ptr<EVP_PKEY_free>(EVP_PKEY_new());
			EVP_PKEY_set1_EC_KEY(pkey.get(), priv.get());
			std::vector<uint8_t> sharedSecret = libcdoc::Crypto::deriveSharedSecret(pkey.get(), peerPKey);

			std::string oid(50, 0);
			oid.resize(size_t(OBJ_obj2txt(&oid[0], int(oid.size()), OBJ_nid2obj(curveName), 1)));
			std::vector<uint8_t> SsDer = Crypto::toPublicKeyDer(pkey.get());

			std::string encryptionMethod(libcdoc::Crypto::KWAES256_MTH);
			std::string concatDigest = libcdoc::Crypto::SHA384_MTH;
			switch ((SsDer.size() - 1) / 2) {
			case 32: concatDigest = libcdoc::Crypto::SHA256_MTH; break;
			case 48: concatDigest = libcdoc::Crypto::SHA384_MTH; break;
			default: concatDigest = libcdoc::Crypto::SHA512_MTH; break;
			}

			std::vector<uint8_t> AlgorithmID(documentFormat.cbegin(), documentFormat.cend());
			std::vector<uint8_t> encryptionKey = libcdoc::Crypto::concatKDF(concatDigest, libcdoc::Crypto::keySize(encryptionMethod), sharedSecret,
				AlgorithmID, SsDer, recipient);
			encryptedData = libcdoc::Crypto::AESWrap(encryptionKey, transportKey.key, true);

            LOG_TRACE_KEY("Ss {}", SsDer);
            LOG_TRACE_KEY("Ksr {}", sharedSecret);
            LOG_TRACE_KEY("ConcatKDF {}", encryptionKey);
            LOG_TRACE_KEY("iv {}", transportKey.iv);
            LOG_TRACE_KEY("transport {}", transportKey.key);

            RET_ERROR(writeElement(Private::DENC, "EncryptionMethod", {{"Algorithm", encryptionMethod}}));
            RET_ERROR(writeElement(Private::DS, "KeyInfo", [&] {
                return writeElement(Private::DENC, "AgreementMethod", {{"Algorithm", Crypto::AGREEMENT_MTH}}, [&] {
                    RET_ERROR(writeElement(Private::XENC11, "KeyDerivationMethod", {{"Algorithm", Crypto::CONCATKDF_MTH}}, [&] {
                        return writeElement(Private::XENC11, "ConcatKDFParams", {
                            {"AlgorithmID", "00" + toHex(AlgorithmID)},
                            {"PartyUInfo", "00" + toHex(SsDer)},
                            {"PartyVInfo", "00" + toHex(recipient)}}, [&] {
                            return writeElement(Private::DS, "DigestMethod", {{"Algorithm", concatDigest}});
						});
                    }));
                    RET_ERROR(writeElement(Private::DENC, "OriginatorKeyInfo", [&] {
                        return writeElement(Private::DS, "KeyValue", [&] {
                            return writeElement(Private::DSIG11, "ECKeyValue", [&] {
                                RET_ERROR(writeElement(Private::DSIG11, "NamedCurve", {{"URI", "urn:oid:" + oid}}));
                                return writeBase64Element(Private::DSIG11, "PublicKey", SsDer);
							});
						});
                    }));
                    return writeElement(Private::DENC, "RecipientKeyInfo", [&] {
                        return writeElement(Private::DS, "X509Data", [&] {
                            return writeBase64Element(Private::DS, "X509Certificate", recipient);
						});
					});
				});
            }));
			break;
		}
        default:
            return UNSPECIFIED_ERROR;
        }

        if (encryptedData.empty())
            return UNSPECIFIED_ERROR;
        return writeElement(Private::DENC, "CipherData", [&] {
            return writeBase64Element(Private::DENC, "CipherValue", encryptedData);
		});
	});
}

/**
 * Encrypt data
 */
libcdoc::result_t
CDoc1Writer::encrypt(libcdoc::MultiDataSource& src, const std::vector<libcdoc::Recipient>& keys)
{
    RET_ERROR(beginEncryption());
    d->rcpts = keys;
    Crypto::Key transportKey = Crypto::generateKey(d->method);
	int n_components = src.getNumComponents();
	bool use_ddoc = (n_components > 1) || (n_components == libcdoc::NOT_IMPLEMENTED);

    RET_ERROR(d->writeKeyInfo(use_ddoc, transportKey));
    RET_ERROR(d->writeElement(Private::DENC, "CipherData", [&]() -> int64_t {
        std::vector<uint8_t> data;
        data.reserve(16384);
        VectorConsumer vcons(data);
        std::string name;
        int64_t size;
        if(use_ddoc) {
            DDOCWriter ddoc(vcons);
            result_t result;
            for (result = src.next(name, size); result == OK; result = src.next(name, size)) {
                std::vector<uint8_t> contents;
                VectorConsumer vcons(contents);
                RET_ERROR(src.readAll(vcons));
                RET_ERROR(vcons.close());
                RET_ERROR(ddoc.addFile(name, "application/octet-stream", contents));
                d->files.push_back({name, contents.size()});
            }
            if(result != END_OF_STREAM)
                return result;
        } else {
            RET_ERROR(src.next(name, size));
            if(auto rv = src.readAll(vcons); rv >= 0)
                d->files.push_back({std::move(name), size_t(rv)});
            else
                return rv;
        }
        RET_ERROR(vcons.close());
        return d->writeBase64Element(Private::DENC, "CipherValue", libcdoc::Crypto::encrypt(d->method, transportKey, data));
    }));
    RET_ERROR(d->writeEncryptionProperties(use_ddoc));
    d.reset();
    if (owned) return dst->close();
    return OK;
}

libcdoc::result_t
CDoc1Writer::beginEncryption()
{
    if(!dst)
        return WORKFLOW_ERROR;
    d = std::make_unique<Private>(*dst, last_error);
    return libcdoc::OK;
}

libcdoc::result_t
CDoc1Writer::addRecipient(const libcdoc::Recipient& rcpt)
{
    if(!d)
        return WORKFLOW_ERROR;
	d->rcpts.push_back(rcpt);
    return libcdoc::OK;
}

libcdoc::result_t
CDoc1Writer::addFile(const std::string& name, size_t size)
{
    if(!d)
        return WORKFLOW_ERROR;
	d->files.push_back({name, size, {}});
	return libcdoc::OK;
}

libcdoc::result_t
CDoc1Writer::writeData(const uint8_t *src, size_t size)
{
    if(!d)
        return WORKFLOW_ERROR;
	d->files.back().data.insert(d->files.back().data.end(), src, src + size);
    return libcdoc::OK;
}

libcdoc::result_t
CDoc1Writer::finishEncryption()
{
    if(!d || d->rcpts.empty() || d->files.empty())
        return WORKFLOW_ERROR;
	bool use_ddoc = d->files.size() > 1;
	libcdoc::Crypto::Key transportKey = libcdoc::Crypto::generateKey(d->method);

    RET_ERROR(d->writeKeyInfo(use_ddoc, transportKey));
    RET_ERROR(d->writeElement(Private::DENC, "CipherData", [&] {
        if(!use_ddoc)
            return d->writeBase64Element(Private::DENC, "CipherValue", libcdoc::Crypto::encrypt(d->method, transportKey, d->files.back().data));
        std::vector<uint8_t> data;
        data.reserve(16384);
        VectorConsumer vcons(data);
        for (DDOCWriter ddoc(vcons); const FileEntry& file : d->files) {
            RET_ERROR(ddoc.addFile(file.name, "application/octet-stream", file.data));
        }
        RET_ERROR(vcons.close());
        return d->writeBase64Element(Private::DENC, "CipherValue", libcdoc::Crypto::encrypt(d->method, transportKey, data));
    }));
    RET_ERROR(d->writeEncryptionProperties(use_ddoc));
    d.reset();
    if (owned) return dst->close();
    return libcdoc::OK;
}
