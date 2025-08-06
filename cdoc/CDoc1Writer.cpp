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

#define RET_ERROR(F) if (auto rv = F; rv != OK) return rv

struct FileEntry {
	std::string name;
	size_t size;
	std::vector<uint8_t> data;
};

/**
 * @class CDoc1Writer
 * @brief CDoc1Writer is used for encrypt data.
 */

class CDoc1Writer::Private
{
public:
	std::unique_ptr<XMLWriter> _xml;
	std::vector<FileEntry> files;
	std::vector<libcdoc::Recipient> rcpts;

	static const XMLWriter::NS DENC, DS, XENC11, DSIG11;
	std::string method, documentFormat = "ENCDOC-XML|1.1", lastError;

    uint64_t writeEncryptionProperties(bool use_ddoc);
    uint64_t writeKeyInfo(bool use_ddoc, const libcdoc::Crypto::Key& transportKey);
    uint64_t writeRecipient(const std::vector<uint8_t> &recipient, const libcdoc::Crypto::Key& transportKey);
};

const XMLWriter::NS CDoc1Writer::Private::DENC{ "denc", "http://www.w3.org/2001/04/xmlenc#" };
const XMLWriter::NS CDoc1Writer::Private::DS{ "ds", "http://www.w3.org/2000/09/xmldsig#" };
const XMLWriter::NS CDoc1Writer::Private::XENC11{ "xenc11", "http://www.w3.org/2009/xmlenc11#" };
const XMLWriter::NS CDoc1Writer::Private::DSIG11{ "dsig11", "http://www.w3.org/2009/xmldsig11#" };

CDoc1Writer::CDoc1Writer(libcdoc::DataConsumer *dst, bool take_ownership, const std::string &method)
	: CDocWriter(1, dst, take_ownership), d(new Private())
{
	d->method = method;
}

CDoc1Writer::~CDoc1Writer()
{
	delete d;
}

uint64_t CDoc1Writer::Private::writeEncryptionProperties(bool use_ddoc)
{
    RET_ERROR(_xml->writeElement(DENC, "EncryptionProperties", [&]() -> uint64_t {
        RET_ERROR(_xml->writeTextElement(Private::DENC, "EncryptionProperty", {{"Name", "LibraryVersion"}}, "cdoc|0.0.1"));
        RET_ERROR(_xml->writeTextElement(Private::DENC, "EncryptionProperty", {{"Name", "DocumentFormat"}}, documentFormat));
        RET_ERROR(_xml->writeTextElement(Private::DENC, "EncryptionProperty", {{"Name", "Filename"}}, use_ddoc ? "tmp.ddoc" : files.at(0).name));
        for(const FileEntry &file: files)
        {
            RET_ERROR(_xml->writeTextElement(Private::DENC, "EncryptionProperty", {{"Name", "orig_file"}},
                file.name + "|" + std::to_string(file.size) + "|" + "application/octet-stream" + "|D0"));
        }
        return OK;
    }));
    return _xml->writeEndElement(Private::DENC); // EncryptedData
}

uint64_t CDoc1Writer::Private::writeKeyInfo(bool use_ddoc, const libcdoc::Crypto::Key& transportKey)
{
    RET_ERROR(_xml->writeStartElement(Private::DENC, "EncryptedData", {{"MimeType", use_ddoc ? "http://www.sk.ee/DigiDoc/v1.3.0/digidoc.xsd" : "application/octet-stream"}}));
    RET_ERROR(_xml->writeElement(Private::DENC, "EncryptionMethod", {{"Algorithm", method}}));
    return _xml->writeElement(Private::DS, "KeyInfo", {}, [&]() -> uint64_t {
        for (const libcdoc::Recipient& key : rcpts) {
            if (!key.isCertificate()) {
                lastError = "Invalid recipient type";
                LOG_ERROR("{}", lastError);
                return libcdoc::UNSPECIFIED_ERROR;
            }
            if(auto rv = writeRecipient(key.cert, transportKey); rv != OK) {
                lastError = "Failed to write Recipient info";
                LOG_ERROR("{}", lastError);
                return rv;
            }
        }
        return OK;
    });
}

uint64_t CDoc1Writer::Private::writeRecipient(const std::vector<uint8_t> &recipient, const libcdoc::Crypto::Key& transportKey)
{
	auto peerCert = libcdoc::Crypto::toX509(recipient);
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
    return _xml->writeElement(Private::DENC, "EncryptedKey", {{"Recipient", cn}}, [&]() -> uint64_t {
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
            RET_ERROR(_xml->writeElement(Private::DENC, "EncryptionMethod", {{"Algorithm", libcdoc::Crypto::RSA_MTH}}));
            RET_ERROR(_xml->writeElement(Private::DS, "KeyInfo", [&]{
                return _xml->writeElement(Private::DS, "X509Data", [&]{
                    return _xml->writeBase64Element(Private::DS, "X509Certificate", recipient);
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

            RET_ERROR(_xml->writeElement(Private::DENC, "EncryptionMethod", {{"Algorithm", encryptionMethod}}));
            RET_ERROR(_xml->writeElement(Private::DS, "KeyInfo", [&]{
                return _xml->writeElement(Private::DENC, "AgreementMethod", {{"Algorithm", libcdoc::Crypto::AGREEMENT_MTH}}, [&]{
                    RET_ERROR(_xml->writeElement(Private::XENC11, "KeyDerivationMethod", {{"Algorithm", libcdoc::Crypto::CONCATKDF_MTH}}, [&]{
                        return _xml->writeElement(Private::XENC11, "ConcatKDFParams", {
                            {"AlgorithmID", "00" + libcdoc::toHex(AlgorithmID)},
                            {"PartyUInfo", "00" + libcdoc::toHex(SsDer)},
                            {"PartyVInfo", "00" + libcdoc::toHex(recipient)}}, [&]{
                            return _xml->writeElement(Private::DS, "DigestMethod", {{"Algorithm", concatDigest}});
						});
                    }));
                    RET_ERROR(_xml->writeElement(Private::DENC, "OriginatorKeyInfo", [&]{
                        return _xml->writeElement(Private::DS, "KeyValue", [&]{
                            return _xml->writeElement(Private::DSIG11, "ECKeyValue", [&]{
                                RET_ERROR(_xml->writeElement(Private::DSIG11, "NamedCurve", {{"URI", "urn:oid:" + oid}}));
                                return _xml->writeBase64Element(Private::DSIG11, "PublicKey", SsDer);
							});
						});
                    }));
                    return _xml->writeElement(Private::DENC, "RecipientKeyInfo", [&]{
                        return _xml->writeElement(Private::DS, "X509Data", [&]{
                            return _xml->writeBase64Element(Private::DS, "X509Certificate", recipient);
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
        return _xml->writeElement(Private::DENC, "CipherData", [&]{
            return _xml->writeBase64Element(Private::DENC, "CipherValue", encryptedData);
		});
	});
}

/**
 * Encrypt data
 */
libcdoc::result_t
CDoc1Writer::encrypt(libcdoc::MultiDataSource& src, const std::vector<libcdoc::Recipient>& keys)
{
	libcdoc::Crypto::Key transportKey = libcdoc::Crypto::generateKey(d->method);
	int n_components = src.getNumComponents();
	bool use_ddoc = (n_components > 1) || (n_components == libcdoc::NOT_IMPLEMENTED);
    d->rcpts = keys;

	d->_xml = std::make_unique<XMLWriter>(dst);
    RET_ERROR(d->writeKeyInfo(use_ddoc, transportKey));
    RET_ERROR(d->_xml->writeElement(Private::DENC, "CipherData", [&]() -> uint64_t {
        std::vector<uint8_t> data;
        if(use_ddoc) {
            data.reserve(16384);
			DDOCWriter ddoc(data);
			std::string name;
			int64_t size;
            for (auto result = src.next(name, size); result == libcdoc::OK; result = src.next(name, size)) {
				std::vector<uint8_t> contents;
				libcdoc::VectorConsumer vcons(contents);
                if (src.readAll(vcons) < 0)
                    return IO_ERROR;
                d->files.push_back({name, (size_t) result});
                if(auto rv = ddoc.addFile(name, "application/octet-stream", contents); rv != OK)
                    return rv;
			}
		} else {
			std::string name;
			int64_t size;
            if (src.next(name, size) < 0)
                return IO_ERROR;
			libcdoc::VectorConsumer vcons(data);
			auto result = src.readAll(vcons);
            if (result < 0)
                return IO_ERROR;
            d->files.push_back({std::move(name), (size_t) result});
        }
        return d->_xml->writeBase64Element(Private::DENC, "CipherValue", libcdoc::Crypto::encrypt(d->method, transportKey, data));
    }));
    RET_ERROR(d->writeEncryptionProperties(use_ddoc));
	d->_xml.reset();
    if (owned) return dst->close();
    return OK;
}

libcdoc::result_t
CDoc1Writer::beginEncryption()
{
	d->_xml = std::make_unique<XMLWriter>(dst);
    return libcdoc::OK;
}

libcdoc::result_t
CDoc1Writer::addRecipient(const libcdoc::Recipient& rcpt)
{
	d->rcpts.push_back(rcpt);
    return libcdoc::OK;
}

libcdoc::result_t
CDoc1Writer::addFile(const std::string& name, size_t size)
{
	d->files.push_back({name, size, {}});
	return libcdoc::OK;
}

libcdoc::result_t
CDoc1Writer::writeData(const uint8_t *src, size_t size)
{
	if (d->files.empty()) return libcdoc::WORKFLOW_ERROR;
	d->files.back().data.insert(d->files.back().data.end(), src, src + size);
    return libcdoc::OK;
}

libcdoc::result_t
CDoc1Writer::finishEncryption()
{
	if (!d->_xml) return libcdoc::WORKFLOW_ERROR;
	if (d->rcpts.empty()) return libcdoc::WORKFLOW_ERROR;
	if (d->files.empty()) return libcdoc::WORKFLOW_ERROR;
	bool use_ddoc = d->files.size() > 1;
	libcdoc::Crypto::Key transportKey = libcdoc::Crypto::generateKey(d->method);

    RET_ERROR(d->writeKeyInfo(use_ddoc, transportKey));
    RET_ERROR(d->_xml->writeElement(Private::DENC, "CipherData", [&]{
        if(!use_ddoc)
            return d->_xml->writeBase64Element(Private::DENC, "CipherValue", libcdoc::Crypto::encrypt(d->method, transportKey, d->files.back().data));
        std::vector<uint8_t> data;
        data.reserve(4096);
        for (DDOCWriter ddoc(data); const FileEntry& file : d->files) {
            ddoc.addFile(file.name, "application/octet-stream", file.data);
        }
        return d->_xml->writeBase64Element(Private::DENC, "CipherValue", libcdoc::Crypto::encrypt(d->method, transportKey, data));
    }));
    RET_ERROR(d->writeEncryptionProperties(use_ddoc));
	d->_xml.reset();
    if (owned) return dst->close();
    return libcdoc::OK;
}
