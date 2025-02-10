#define __LIBCDOC_WINBACKEND_CPP__

#include <Windows.h>
#include <wincrypt.h>

#include "WinBackend.h"
#include "CDoc2.h"
#include "Crypto.h"
#include "ILogger.h"
#include "Utils.h"

struct libcdoc::WinBackend::Private {
    NCRYPT_PROV_HANDLE  prov = 0;
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key = 0;

    Private(const std::string& name) {
        std::wstring wname;
        if (name.empty()) {
            wname = MS_SMART_CARD_KEY_STORAGE_PROVIDER;
        } else {
            wname = toWide(name);
        }
        NCryptOpenStorageProvider(&prov, wname.c_str(), 0);
        if (prov) {
            NCryptKeyName *wkeyname = NULL;
            void *state = NULL;
            SECURITY_STATUS result = NCryptEnumKeys(prov, NULL, &wkeyname, &state, NCRYPT_SILENT_FLAG);
            while (result == ERROR_SUCCESS) {
                std::string name = toUTF8(wkeyname->pszName);
                std::string algo = toUTF8(wkeyname->pszAlgid);
                LOG_DBG("Name: {} Algo: {}", name, algo);
                NCryptFreeBuffer(wkeyname);
                result = NCryptEnumKeys(prov, NULL, &wkeyname, &state, NCRYPT_SILENT_FLAG);
            }
        }
    }
    ~Private() {
        if (key) NCryptFreeObject(key);
        if (prov) NCryptFreeObject(prov);
    }

    int derive(NCRYPT_PROV_HANDLE &prov, NCRYPT_KEY_HANDLE &publicKeyHandle, NCRYPT_SECRET_HANDLE &sharedSecret, const std::vector<uint8_t> &public_key);
};

int
libcdoc::WinBackend::Private::derive(NCRYPT_PROV_HANDLE &prov, NCRYPT_KEY_HANDLE &publicKeyHandle, NCRYPT_SECRET_HANDLE &sharedSecret, const std::vector<uint8_t> &public_key)
{
    uint32_t key_size = (public_key.size() - 1) / 2;
	BCRYPT_ECCKEY_BLOB oh = { BCRYPT_ECDH_PUBLIC_P384_MAGIC, key_size };
	switch (key_size * 8) {
	case 256:
        oh.dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
        break;
	case 384:
        oh.dwMagic = BCRYPT_ECDH_PUBLIC_P384_MAGIC;
        break;
	case 521:
        oh.dwMagic = BCRYPT_ECDH_PUBLIC_P521_MAGIC;
        break;
	default:
        return libcdoc::WRONG_ARGUMENTS;
	}
	std::vector<uint8_t> blob((uint8_t *)&oh, (uint8_t *)&oh + sizeof(BCRYPT_ECCKEY_BLOB));
	blob.insert(blob.cend(), public_key.cbegin() + 1, public_key.cend());

    SECURITY_STATUS err = 0;

	DWORD size = 0;
	err = NCryptGetProperty(key, NCRYPT_PROVIDER_HANDLE_PROPERTY, PBYTE(&prov), sizeof(prov), &size, 0);
    if (err != ERROR_SUCCESS) {
        return libcdoc::CRYPTO_ERROR;
    }

    err = NCryptImportKey(prov, 0, BCRYPT_ECCPUBLIC_BLOB, 0, &publicKeyHandle, PBYTE(blob.data()), DWORD(blob.size()), 0);
    if (err != ERROR_SUCCESS) {
		NCryptFreeObject(prov);
        return libcdoc::CRYPTO_ERROR;
    }
    err = NCryptSecretAgreement(key, publicKeyHandle, &sharedSecret, 0);
    if (err != ERROR_SUCCESS) {
		NCryptFreeObject(publicKeyHandle);
		NCryptFreeObject(prov);
		return libcdoc::CRYPTO_ERROR;
	}
    return libcdoc::OK;
}

libcdoc::WinBackend::WinBackend(const std::string& provider)
: d(std::make_unique<Private>(provider))
{
}

libcdoc::WinBackend::~WinBackend()
{
}

int
libcdoc::WinBackend::useKey(const std::string& name, const std::string& pin)
{
    if (!d->prov) return CRYPTO_ERROR;
    if (d->key) {
        NCryptFreeObject(d->key);
        d->key = 0;
    }
    std::wstring wname = toWide(name);
    SECURITY_STATUS err = NCryptOpenKey(d->prov, &d->key, wname.c_str(), 0, NCRYPT_SILENT_FLAG);
    if (err != ERROR_SUCCESS) return CRYPTO_ERROR;
    if (!pin.empty()) {
        std::wstring wpin = toWide(pin);
        err = NCryptSetProperty(d->key, NCRYPT_PIN_PROPERTY, PBYTE(wpin.data()), DWORD(wpin.size()), NCRYPT_SILENT_FLAG);
        if (err != ERROR_SUCCESS) {
            NCryptFreeObject(d->key);
            d->key = 0;
        }
    }
    return OK;
}

int
libcdoc::WinBackend::decryptRSA(std::vector<uint8_t>& dst, const std::vector<uint8_t>& data, bool oaep, unsigned int idx)
{
	if(!d->prov) return CRYPTO_ERROR;
    int result = connectToKey(idx, true);
    if (result != OK) return result;

	BCRYPT_OAEP_PADDING_INFO padding {BCRYPT_SHA256_ALGORITHM, nullptr, 0};
	PVOID paddingInfo = oaep ? &padding : nullptr;
	DWORD flags = oaep ? NCRYPT_PAD_OAEP_FLAG : NCRYPT_PAD_PKCS1_FLAG;
	DWORD size = 0;
	SECURITY_STATUS err = NCryptDecrypt(d->key, PBYTE(data.data()), DWORD(data.size()), paddingInfo, nullptr, 0, &size, flags);
    if (err != ERROR_SUCCESS) return CRYPTO_ERROR;
	dst.resize(size);
	err = NCryptDecrypt(d->key, PBYTE(data.data()), DWORD(data.size()), paddingInfo, PBYTE(dst.data()), DWORD(dst.size()), &size, flags);
    if (err != ERROR_SUCCESS) return CRYPTO_ERROR;
    return OK;
}

int
libcdoc::WinBackend::deriveConcatKDF(std::vector<uint8_t>& dst, const std::vector<uint8_t> &public_key, const std::string &digest,
								 const std::vector<uint8_t> &algorithm_id, const std::vector<uint8_t> &party_uinfo,
                                 const std::vector<uint8_t> &party_vinfo, unsigned int idx)
{
	if(!d->prov) return CRYPTO_ERROR;
    int result = connectToKey(idx, true);
    if (result != OK) return result;

	NCRYPT_PROV_HANDLE prov = 0;
	NCRYPT_KEY_HANDLE publicKeyHandle = 0;
	NCRYPT_SECRET_HANDLE sharedSecret = 0;

    result = d->derive(prov, publicKeyHandle, sharedSecret, public_key);
    if (result != OK) return result;

	std::vector<BCryptBuffer> paramValues{
		{ULONG(algorithm_id.size()), KDF_ALGORITHMID, PBYTE(algorithm_id.data())},
		{ULONG(party_uinfo.size()), KDF_PARTYUINFO, PBYTE(party_uinfo.data())},
		{ULONG(party_vinfo.size()), KDF_PARTYVINFO, PBYTE(party_vinfo.data())},
	};
	if(digest == "http://www.w3.org/2001/04/xmlenc#sha256") {
		paramValues.push_back({ULONG(sizeof(BCRYPT_SHA256_ALGORITHM)), KDF_HASH_ALGORITHM, PBYTE(BCRYPT_SHA256_ALGORITHM)});
    } else if(digest == "http://www.w3.org/2001/04/xmlenc#sha384") {
		paramValues.push_back({ULONG(sizeof(BCRYPT_SHA384_ALGORITHM)), KDF_HASH_ALGORITHM, PBYTE(BCRYPT_SHA384_ALGORITHM)});
    } else if(digest == "http://www.w3.org/2001/04/xmlenc#sha512") {
		paramValues.push_back({ULONG(sizeof(BCRYPT_SHA512_ALGORITHM)), KDF_HASH_ALGORITHM, PBYTE(BCRYPT_SHA512_ALGORITHM)});
    } else {
        NCryptFreeObject(publicKeyHandle);
        NCryptFreeObject(sharedSecret);
        NCryptFreeObject(prov);
        return CRYPTO_ERROR;
    }
	BCryptBufferDesc params;
	params.ulVersion = BCRYPTBUFFER_VERSION;
	params.cBuffers = ULONG(paramValues.size());
	params.pBuffers = paramValues.data();

    result = CRYPTO_ERROR;
	DWORD size = 0;
	SECURITY_STATUS err = NCryptDeriveKey(sharedSecret, BCRYPT_KDF_SP80056A_CONCAT, &params, nullptr, 0, &size, 0);
    if (err == ERROR_SUCCESS) {
		dst.resize(int(size));
		err = NCryptDeriveKey(sharedSecret, BCRYPT_KDF_SP80056A_CONCAT, &params, PBYTE(dst.data()), size, &size, 0);
        if (err == ERROR_SUCCESS) {
		    dst.resize(32);
            result = OK;
        }
	}

	NCryptFreeObject(publicKeyHandle);
	NCryptFreeObject(sharedSecret);
	NCryptFreeObject(prov);

    return result;
}

int
libcdoc::WinBackend::deriveHMACExtract(std::vector<uint8_t>& dst, const std::vector<uint8_t> &public_key, const std::vector<uint8_t> &salt, unsigned int idx)
{
	if(!d->prov) return CRYPTO_ERROR;
    int result = connectToKey(idx, true);
    if (result != OK) return result;

	NCRYPT_PROV_HANDLE prov = 0;
	NCRYPT_KEY_HANDLE publicKeyHandle = 0;
	NCRYPT_SECRET_HANDLE sharedSecret = 0;

    result = d->derive(prov, publicKeyHandle, sharedSecret, public_key);
    if (result != OK) return result;

    result = CRYPTO_ERROR;

	std::vector<BCryptBuffer> paramValues {
		{ULONG(salt.size()), KDF_HMAC_KEY, PBYTE(salt.data())},
		{ULONG(sizeof(BCRYPT_SHA256_ALGORITHM)), KDF_HASH_ALGORITHM, PBYTE(BCRYPT_SHA256_ALGORITHM)},
	};
	BCryptBufferDesc params{BCRYPTBUFFER_VERSION};
	params.cBuffers = ULONG(paramValues.size());
	params.pBuffers = paramValues.data();

	DWORD size = 0;
	SECURITY_STATUS err = 0;
	err = NCryptDeriveKey(sharedSecret, BCRYPT_KDF_HMAC, &params, nullptr, 0, &size, 0);
    if (err == ERROR_SUCCESS) {
		dst.resize(int(size));
		err = NCryptDeriveKey(sharedSecret, BCRYPT_KDF_HMAC, &params, PBYTE(dst.data()), size, &size, 0);
        if (err == ERROR_SUCCESS) {
		    dst.resize(CDoc2::KEY_LEN);
            result = OK;
        }
    }

	NCryptFreeObject(publicKeyHandle);
	NCryptFreeObject(sharedSecret);
	NCryptFreeObject(prov);

    return result;
}

int
libcdoc::WinBackend::extractHKDF(std::vector<uint8_t>& dst, const std::vector<uint8_t>& salt, const std::vector<uint8_t>& pw_salt, int32_t kdf_iter, unsigned int idx)
{
	if (salt.empty()) return INVALID_PARAMS;
	if ((kdf_iter > 0) && pw_salt.empty()) return INVALID_PARAMS;
#if 0
	if (kdf_iter > 0) {
		std::vector<uint8_t> secret;
        int result = getSecret(secret, idx);
		if (result < 0) return result;
#ifdef LOCAL_DEBUG
        LOG_DBG("Secret: {}", toHex(secret));
#endif
	    std::vector<uint8_t> key_material = libcdoc::Crypto::pbkdf2_sha256(secret, pw_salt, kdf_iter);
		std::fill(secret.begin(), secret.end(), 0);
		if (key_material.empty()) return OPENSSL_ERROR;
	    dst = libcdoc::Crypto::extract(key_material, salt);
	    std::fill(key_material.begin(), key_material.end(), 0);
	    if (dst.empty()) return OPENSSL_ERROR;
#ifdef LOCAL_DEBUG
        LOG_DBG("Extract: {}", toHex(dst));
#endif
	} else {
	    if(!d->prov) return CRYPTO_ERROR;
        int result = connectToKey(idx, true);
        if (result != OK) return result;

	    kek_pm = libcdoc::Crypto::extract(key_material, salt);
	    std::fill(key_material.begin(), key_material.end(), 0);
	    if (kek_pm.empty()) return OPENSSL_ERROR;
#ifdef LOCAL_DEBUG
        LOG_DBG("Extract: {}", toHex(kek_pm));
#endif
	}
    
    return OK;
#endif
    return NOT_IMPLEMENTED;
}

int
libcdoc::WinBackend::sign(std::vector<uint8_t>& dst, HashAlgorithm algorithm, const std::vector<uint8_t> &digest, unsigned int idx)
{
    return NOT_IMPLEMENTED;
}
