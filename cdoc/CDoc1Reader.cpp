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

#include "CDoc1Reader.h"

#include "CDoc.h"
#include "Certificate.h"
#include "Crypto.h"
#include "CryptoBackend.h"
#include "DDocReader.h"
#include "ILogger.h"
#include "Lock.h"
#include "XmlReader.h"
#include "ZStream.h"

#include <openssl/x509.h>

#include <map>
#include <set>

using namespace libcdoc;

static const std::string MIME_ZLIB = "http://www.isi.edu/in-noes/iana/assignments/media-types/application/zip";
static const std::string MIME_DDOC = "http://www.sk.ee/DigiDoc/v1.3.0/digidoc.xsd";
static const std::string MIME_DDOC_OLD = "http://www.sk.ee/DigiDoc/1.3.0/digidoc.xsd";

constexpr auto SUPPORTED_METHODS = std::to_array({
    libcdoc::Crypto::AES128CBC_MTH, libcdoc::Crypto::AES192CBC_MTH, libcdoc::Crypto::AES256CBC_MTH,
    libcdoc::Crypto::AES128GCM_MTH, libcdoc::Crypto::AES192GCM_MTH, libcdoc::Crypto::AES256GCM_MTH
});

constexpr auto SUPPORTED_KWAES = std::to_array({
    libcdoc::Crypto::KWAES128_MTH, libcdoc::Crypto::KWAES192_MTH, libcdoc::Crypto::KWAES256_MTH
});

/*
 * @class CDoc1Reader
 * @brief CDoc1Reader is used for decrypt data.
 */

class CDoc1Reader::Private
{
public:
    libcdoc::DataSource *dsrc = nullptr;
    bool src_owned = false;
    std::string mime, method;
    std::vector<Lock> locks;
    std::map<std::string,std::string> properties;

    std::vector<DDOCReader::File> files;
    int64_t f_pos = -1;
    std::unique_ptr<libcdoc::VectorSource> src;

    ~Private()
    {
        if (src_owned) delete dsrc;
    }
};

const std::vector<Lock>&
CDoc1Reader::getLocks()
{
    return d->locks;
}

libcdoc::result_t
CDoc1Reader::getLockForCert(const std::vector<uint8_t>& cert)
{
    if (std::find(SUPPORTED_METHODS.cbegin(), SUPPORTED_METHODS.cend(), d->method) == SUPPORTED_METHODS.cend()) return libcdoc::NOT_SUPPORTED;
	libcdoc::Certificate cc(cert);
    for (size_t i = 0; i < d->locks.size(); i++) {
        const Lock &ll = d->locks.at(i);
        if (!ll.isCDoc1() ||
            ll.getBytes(Lock::Params::CERT) != cert ||
            ll.encrypted_fmk.empty())
            continue;
        switch(cc.getAlgorithm()) {
        case libcdoc::Certificate::RSA:
            if (ll.getString(Lock::Params::METHOD) == libcdoc::Crypto::RSA_MTH) {
                return i;
            }
            break;
        case libcdoc::Certificate::ECC:
            if(!ll.getBytes(Lock::Params::KEY_MATERIAL).empty() &&
                std::find(SUPPORTED_KWAES.cbegin(), SUPPORTED_KWAES.cend(), ll.getString(Lock::Params::METHOD)) != SUPPORTED_KWAES.cend()) {
                return i;
            }
            break;
        default:
            return libcdoc::NOT_SUPPORTED;
        }
	}
    return libcdoc::NOT_FOUND;
}

libcdoc::result_t
CDoc1Reader::getFMK(std::vector<uint8_t>& fmk, unsigned int lock_idx)
{
    if (lock_idx >= d->locks.size()) return libcdoc::WRONG_ARGUMENTS;
    const Lock &lock = d->locks.at(lock_idx);
    if (lock.type != Lock::Type::CDOC1) {
		setLastError("Not a CDoc1 key");
        LOG_ERROR("{}", last_error);
		return libcdoc::UNSPECIFIED_ERROR;
	}
    setLastError({});
    if (lock.isRSA()) {
        int result = crypto->decryptRSA(fmk, lock.encrypted_fmk, false, lock_idx);
		if (result < 0) {
			setLastError(crypto->getLastErrorStr(result));
            LOG_ERROR("{}", last_error);
			return libcdoc::CRYPTO_ERROR;
		}
	} else {
        std::vector<uint8_t> key;
        int result = crypto->deriveConcatKDF(key,
            lock.getBytes(Lock::Params::KEY_MATERIAL),
            lock.getString(Lock::Params::CONCAT_DIGEST),
            lock.getBytes(Lock::Params::ALGORITHM_ID),
            lock.getBytes(Lock::Params::PARTY_UINFO),
            lock.getBytes(Lock::Params::PARTY_VINFO),
            lock_idx);
		if (result < 0) {
			setLastError(crypto->getLastErrorStr(result));
            LOG_ERROR("{}", last_error);
			return libcdoc::CRYPTO_ERROR;
		}
        fmk = libcdoc::Crypto::AESWrap(key, lock.encrypted_fmk, false);
	}
	if (fmk.empty()) {
		setLastError("Failed to decrypt/derive fmk");
        LOG_ERROR("{}", last_error);
		return libcdoc::CRYPTO_ERROR;
	}
	setLastError({});
    return libcdoc::OK;
}

libcdoc::result_t
CDoc1Reader::decrypt(const std::vector<uint8_t>& fmk, libcdoc::MultiDataConsumer *dst)
{
#ifdef USE_PULL
    int64_t result = beginDecryption(fmk);
    if (result != libcdoc::OK) return result;
    std::string name;
    int64_t size;
    result = nextFile(name, size);
    while (result == libcdoc::OK) {
        result = dst->open(name, size);
        if (result != libcdoc::OK) return result;
        std::vector<uint8_t> t(size);
        result = readData(t.data(), size);
        if (result < 0) return result;
        result = dst->write(t);
        if (result < 0) return result;
        result = nextFile(name, size);
    }
    if (result != libcdoc::END_OF_STREAM) return result;
    result = finishDecryption();
    return result;
#else
    std::string mime;
    std::vector<uint8_t> data;
    if (auto result = CDoc1Reader::decryptData(fmk, mime, data); result != OK) {
        return result;
    }
	libcdoc::VectorSource vsrc(data);
	if(mime == MIME_DDOC || mime == MIME_DDOC_OLD) {
        LOG_DBG("Contains DDoc content {}", mime);
        auto result = DDOCReader::parse(&vsrc, dst);
        if (result != libcdoc::OK) {
            setLastError("Failed to parse DDOC file");
            LOG_ERROR("{}", last_error);
        }
        return result;
    }
	dst->open(d->properties["Filename"], data.size());
	dst->writeAll(vsrc);
	dst->close();
    return libcdoc::OK;
#endif
}

libcdoc::result_t
CDoc1Reader::beginDecryption(const std::vector<uint8_t>& fmk)
{
    std::string mime;
    std::vector<uint8_t> data;
    if (auto result = CDoc1Reader::decryptData(fmk, mime, data); result != OK) {
        return result;
    }
    if(mime == MIME_DDOC || mime == MIME_DDOC_OLD) {
        LOG_DBG("Contains DDoc content {}", mime);
        d->files = DDOCReader::files(data);
    } else {
        d->files.push_back({
            d->properties["Filename"],
            "application/octet-stream",
            std::move(data)
        });
    }
    if (d->files.empty()) {
        setLastError("Cannot parse container");
        LOG_ERROR("{}", last_error);
        return libcdoc::IO_ERROR;
    }
    setLastError({});
    return libcdoc::OK;
}

libcdoc::result_t
CDoc1Reader::finishDecryption()
{
    d->src.reset();
    d->files.clear();
    return libcdoc::OK;
}

libcdoc::result_t
CDoc1Reader::nextFile(std::string& name, int64_t& size)
{
    if (d->files.empty()) {
        setLastError("Cannot parse container");
        LOG_ERROR("{}", last_error);
        return libcdoc::WORKFLOW_ERROR;
    }
    d->f_pos += 1;
    if ((d->f_pos < 0) || (d->f_pos >= (int64_t) d->files.size())) {
        return libcdoc::END_OF_STREAM;
    }
    name = d->files[d->f_pos].name;
    size = d->files[d->f_pos].data.size();
    d->src = std::make_unique<libcdoc::VectorSource>(d->files[d->f_pos].data);
    return libcdoc::OK;
}

libcdoc::result_t
CDoc1Reader::readData(uint8_t *dst, size_t size)
{
    if (!d->src) {
        setLastError("Cannot parse container");
        LOG_ERROR("{}", last_error);
        return libcdoc::WORKFLOW_ERROR;
    }
    return d->src->read(dst, size);
}

/*
 * CDoc1Reader constructor.
 * @param file File to open reading
 */
CDoc1Reader::CDoc1Reader(libcdoc::DataSource *src, bool delete_on_close)
	: CDocReader(1), d(new Private)
{
    d->dsrc = src;
    d->src_owned = delete_on_close;
	auto hex2bin = [](const std::string &in) {
		std::vector<uint8_t> out;
        out.reserve(in.size() / 2);
		char data[] = "00";
		for(std::string::const_iterator i = in.cbegin(); distance(i, in.cend()) >= 2;)
		{
			data[0] = *(i++);
			data[1] = *(i++);
			out.push_back(static_cast<uint8_t>(strtoul(data, 0, 16)));
		}
		if(out[0] == 0x00)
			out.erase(out.cbegin());
		return out;
	};

    XMLReader reader(d->dsrc, false);
	while (reader.read()) {
		if(reader.isEndElement())
			continue;
		// EncryptedData
        if(reader.isElement("EncryptedData"))
			d->mime = reader.attribute("MimeType");
		// EncryptedData/EncryptionMethod
		else if(reader.isElement("EncryptionMethod"))
			d->method = reader.attribute("Algorithm");
		// EncryptedData/EncryptionProperties/EncryptionProperty
        else if(reader.isElement("EncryptionProperty"))
        {
            auto name = reader.attribute("Name");
            d->properties[std::move(name)] = reader.readText();
        }
        // EncryptedData/KeyInfo/EncryptedKey
		else if(reader.isElement("EncryptedKey"))
		{
            Lock &key = d->locks.emplace_back(Lock::Type::CDOC1);
			//key.id = reader.attribute("Id");
            key.label = reader.attribute("Recipient");
			while(reader.read())
			{
				if(reader.isElement("EncryptedKey") && reader.isEndElement())
					break;
                if(reader.isEndElement())
					continue;
				// EncryptedData/KeyInfo/KeyName
				//if(reader.isElement("KeyName"))
				//	key.name = reader.readText();
				// EncryptedData/KeyInfo/EncryptedKey/EncryptionMethod
                if(reader.isElement("EncryptionMethod"))
                    key.setString(Lock::Params::METHOD, reader.attribute("Algorithm"));
				// EncryptedData/KeyInfo/EncryptedKey/KeyInfo/AgreementMethod
				//else if(reader.isElement("AgreementMethod"))
				//	key.agreement = reader.attribute("Algorithm");
				// EncryptedData/KeyInfo/EncryptedKey/KeyInfo/AgreementMethod/KeyDerivationMethod
				//else if(reader.isElement("KeyDerivationMethod"))
				//	key.derive = reader.attribute("Algorithm");
				// EncryptedData/KeyInfo/EncryptedKey/KeyInfo/AgreementMethod/KeyDerivationMethod/ConcatKDFParams
				else if(reader.isElement("ConcatKDFParams"))
				{
                    key.setBytes(Lock::Params::ALGORITHM_ID, hex2bin(reader.attribute("AlgorithmID")));
                    key.setBytes(Lock::Params::PARTY_UINFO, hex2bin(reader.attribute("PartyUInfo")));
                    key.setBytes(Lock::Params::PARTY_VINFO, hex2bin(reader.attribute("PartyVInfo")));
				}
				// EncryptedData/KeyInfo/EncryptedKey/KeyInfo/AgreementMethod/KeyDerivationMethod/ConcatKDFParams/DigestMethod
				else if(reader.isElement("DigestMethod"))
                    key.setString(Lock::Params::CONCAT_DIGEST, reader.attribute("Algorithm"));
				// EncryptedData/KeyInfo/EncryptedKey/KeyInfo/AgreementMethod/OriginatorKeyInfo/KeyValue/ECKeyValue/PublicKey
				else if(reader.isElement("PublicKey"))
                    key.setBytes(Lock::Params::KEY_MATERIAL, reader.readBase64());
				// EncryptedData/KeyInfo/EncryptedKey/KeyInfo/X509Data/X509Certificate
				else if(reader.isElement("X509Certificate"))
                    key.setCertificate(reader.readBase64());
				// EncryptedData/KeyInfo/EncryptedKey/KeyInfo/CipherData/CipherValue
				else if(reader.isElement("CipherValue"))
                    key.encrypted_fmk = reader.readBase64();
			}
		}
	}
}

CDoc1Reader::~CDoc1Reader()
{
	delete d;
}

CDoc1Reader::CDoc1Reader(const std::string &path)
    : CDoc1Reader(new libcdoc::IStreamSource(path), true)
{
}

bool
CDoc1Reader::isCDoc1File(libcdoc::DataSource *src)
{
    // fixme: better check
    static const std::string XML_TAG("<?xml");
    std::vector<uint8_t>buf(XML_TAG.size());
    if (src->read(buf.data(), XML_TAG.size()) != XML_TAG.size()) return false;
    if (XML_TAG.compare(0, XML_TAG.size(), (char *) buf.data())) return false;
    return true;
}

/*
 * Returns decrypted data
 * @param key Transport key to used for decrypt data
 * @param mime decrypted mime type
 * @param data decrypted data
 */
result_t CDoc1Reader::decryptData(const std::vector<uint8_t>& fmk, std::string& mime, std::vector<uint8_t>& data)
{
    if (fmk.empty()) {
        setLastError("FMK is missing");
        return libcdoc::WRONG_ARGUMENTS;
    }
    if (fmk.size() != 16 && fmk.size() != 24 && fmk.size() != 32) {
        setLastError("FMK must be AES key with size 128, 192, 256 bits");
        return libcdoc::WRONG_ARGUMENTS;
    }
    if (!d->files.empty() || (d->f_pos != -1)) {
        setLastError("Container is already parsed");
        LOG_ERROR("{}", last_error);
        return libcdoc::WORKFLOW_ERROR;
    }
    if (auto result = d->dsrc->seek(0); result != libcdoc::OK) {
        return result;
    }

    XMLReader reader(d->dsrc, false);
    int skipKeyInfo = 0;
    while (reader.read()) {
        // EncryptedData/KeyInfo
        if(reader.isElement("KeyInfo") && reader.isEndElement())
            --skipKeyInfo;
        else if(reader.isElement("KeyInfo"))
            ++skipKeyInfo;
        else if(skipKeyInfo > 0)
            continue;
        // EncryptedData/CipherData/CipherValue
        else if(reader.isElement("CipherValue"))
        {
            data = libcdoc::Crypto::decrypt(d->method, fmk, reader.readBase64());
            break;
        }
    }

    if(data.empty()) {
        setLastError("Failed to decrypt data, verify if FMK is correct");
        return libcdoc::CRYPTO_ERROR;
    }
    setLastError({});
    if (d->mime == MIME_ZLIB) {
        libcdoc::VectorSource vsrc(data);
        libcdoc::ZSource zsrc(&vsrc);
        std::vector<uint8_t> tmp;
        libcdoc::VectorConsumer vcons(tmp);
        vcons.writeAll(zsrc);
        data = std::move(tmp);
        mime = d->properties["OriginalMimeType"];
    }
    else
        mime = d->mime;
    return libcdoc::OK;
}
