#define __PKCS11_BACKEND_CPP__

#include "PKCS11Backend.h"

#include "pkcs11.h"

#ifdef _WIN32
#include <Windows.h>
#include <wincrypt.h>
#include <cryptuiapi.h>
#else
#include <dlfcn.h>
#endif

struct libcdoc::PKCS11Backend::Private
{
public:
	int login(int slot, const std::string& pin);
	int logout();
	std::vector<CK_BYTE> attribute(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_TYPE type) const;
	std::vector<CK_OBJECT_HANDLE> findObject(CK_SESSION_HANDLE session, CK_OBJECT_CLASS cls, const std::vector<CK_BYTE> &id = {}) const;
	std::vector<libcdoc::PKCS11Backend::Handle> findAllObjects(CK_OBJECT_CLASS klass, const std::string& label, const std::string& serial);

#ifdef _WIN32
	bool load(const std::string &driver)
	{
#if WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
		return (h = LoadLibraryW(filesystem::u8path(driver).c_str())) != 0;
#else
		return false;
#endif
	}

	void* resolve(const char *symbol) const
	{ return h ? (void*)GetProcAddress(h, symbol) : nullptr; }

	void unload()
	{ if(h) FreeLibrary(h); h = {}; }

	HINSTANCE h {};
#else
	bool load(const std::string &driver) {
		return (h = dlopen(driver.c_str(), RTLD_LAZY));
	}

	void *resolve(const char *symbol) const {
		return h ? dlsym(h, symbol) : nullptr;
	}

	void unload() {
		if(h) dlclose(h); h = {};
	}

	void *h {};
#endif

	CK_FUNCTION_LIST *f {};
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
};

int
libcdoc::PKCS11Backend::Private::login(int slot, const std::string& pin)
{
	if (!f || session) return PKCS11_ERROR;
	if(f->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session) != CKR_OK) return PKCS11_ERROR;
	switch(f->C_Login(session, CKU_USER, CK_BYTE_PTR(pin.c_str()), CK_ULONG(pin.size()))) {
	case CKR_OK:
	case CKR_USER_ALREADY_LOGGED_IN:
		break;
	case CKR_CANCEL:
	case CKR_FUNCTION_CANCELED:
	default:
		f->C_CloseSession(session);
		session = CK_INVALID_HANDLE;
		return PKCS11_ERROR;
	}
	return OK;
}

int
libcdoc::PKCS11Backend::Private::logout()
{
	if (!f || !session) return PKCS11_ERROR;
	f->C_Logout(session);
	f->C_CloseSession(session);
	session = CK_INVALID_HANDLE;
	key = CK_INVALID_HANDLE;
	return true;
}

std::vector<CK_BYTE>
libcdoc::PKCS11Backend::Private::attribute(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_TYPE type) const
{
	CK_ATTRIBUTE attr { type, nullptr, 0 };
	if(f->C_GetAttributeValue(session, obj, &attr, 1) != CKR_OK)
		return {};
	std::vector<CK_BYTE> value(size_t(attr.ulValueLen));
	attr.pValue = value.data();
	if(f->C_GetAttributeValue(session, obj, &attr, 1) != CKR_OK)
		return {};
	return value;
}

std::vector<CK_OBJECT_HANDLE>
libcdoc::PKCS11Backend::Private::findObject(CK_SESSION_HANDLE session, CK_OBJECT_CLASS cls, const std::vector<CK_BYTE> &id) const
{
	CK_BBOOL _true = CK_TRUE;
	std::vector<CK_ATTRIBUTE> attrs {
		{ CKA_CLASS, &cls, sizeof(cls) },
		{ CKA_TOKEN, &_true, sizeof(_true) }
	};
	if(!id.empty())
		attrs.push_back({ CKA_ID, CK_VOID_PTR(id.data()), CK_ULONG(id.size()) });
	if(f->C_FindObjectsInit(session, attrs.data(), CK_ULONG(attrs.size())) != CKR_OK)
		return {};

	CK_ULONG count = 32;
	std::vector<CK_OBJECT_HANDLE> result(count);
	CK_RV err = f->C_FindObjects(session, result.data(), CK_ULONG(result.size()), &count);
	result.resize(err == CKR_OK ? count : 0);
	f->C_FindObjectsFinal(session);
	return result;
}

std::vector<libcdoc::PKCS11Backend::Handle>
libcdoc::PKCS11Backend::Private::findAllObjects(CK_OBJECT_CLASS klass, const std::string& id, const std::string& label)
{
	// Load all slots.
	CK_ULONG size = 0;
	if(f->C_GetSlotList(true, nullptr, &size) != CKR_OK) return {};
	std::vector<CK_SLOT_ID> slots(size);
	if(size && f->C_GetSlotList(true, slots.data(), &size) != CKR_OK) return {};

	std::vector<libcdoc::PKCS11Backend::Handle> objs;
	// Iterate over all found slots
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	for(const CK_SLOT_ID &slot: slots) {
		if(session) f->C_CloseSession(session);
		if(f->C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session) != CKR_OK) continue;
		for(CK_OBJECT_HANDLE obj: findObject(session, klass)) {
			std::vector<CK_BYTE> v = attribute(session, obj, CKA_ID);
			if (!id.empty()) {
				if (id.compare(0, id.size(), (const char *) v.data(), v.size())) continue;
			}
			if (!label.empty()) {
				std::vector<CK_BYTE> v = attribute(session, obj, CKA_LABEL);
				if (label.compare(0, label.size(), (const char *) v.data(), v.size())) continue;
			}
			// Id and label match
			if (v.empty()) continue;
			objs.push_back({(uint32_t) slot, std::vector<uint8_t>(v.cbegin(), v.cend())});
		}
	}
	if(session) f->C_CloseSession(session);
	return std::move(objs);
}

/**
 * Loads PKCS#11 token.
 *
 * @param path full path to the PKCS#11 driver (e.g. /usr/lib/opensc-pkcs11.so)
 * @param password token password
 */
libcdoc::PKCS11Backend::PKCS11Backend(const std::string &driver)
	: d(nullptr)
{
	std::unique_ptr<Private> p = std::make_unique<Private>();
	if(!p->load(driver)) return;
	CK_C_GetFunctionList l = CK_C_GetFunctionList(d->resolve("C_GetFunctionList"));
	if (!l || l(&p->f) != CKR_OK || !p->f) return;
	if (p->f->C_Initialize(nullptr) != CKR_OK) return;
	d = std::move(p);
}

libcdoc::PKCS11Backend::~PKCS11Backend()
{
	if(d->f) {
		d->f->C_Finalize(nullptr);
		d->f = nullptr;
	}
#ifdef _WIN32
	if(d->h) FreeLibrary(d->h);
#else
	if(d->h) dlclose(d->h);
#endif
}

std::vector<libcdoc::PKCS11Backend::Handle>
libcdoc::PKCS11Backend::findCertificates(const std::string& label, const std::string& serial)
{
	if (!d) return {};
	return d->findAllObjects(CKO_CERTIFICATE, label, serial);
}

std::vector<libcdoc::PKCS11Backend::Handle>
libcdoc::PKCS11Backend::findSecretKeys(const std::string& label, const std::string& serial)
{
	if (!d) return {};
	return d->findAllObjects(CKO_SECRET_KEY, label, serial);
}

int
libcdoc::PKCS11Backend::useSecretKey(int slot, const std::string& pin, uint32_t idx, const std::string& id, const std::string& label)
{
	if(!d) return CRYPTO_ERROR;
	int result = d->login(slot, pin);
	if (result != OK) return result;
	if (idx > 0) {
		d->key = idx;
		return OK;
	} else {
		std::vector<Handle> handles = d->findAllObjects(CKO_SECRET_KEY, id, label);
	}

	return NOT_IMPLEMENTED;
}

int
libcdoc::PKCS11Backend::decryptRSA(std::vector<uint8_t> &dst, const std::vector<uint8_t> &data, bool oaep, const std::string& label)
{
	if(!d) return CRYPTO_ERROR;

	int result = connectToKey(label);
	if (result != OK) return result;

	CK_RSA_PKCS_OAEP_PARAMS params { CKM_SHA256, CKG_MGF1_SHA256, 0, nullptr, 0 };
	auto mech = oaep ? CK_MECHANISM{ CKM_RSA_PKCS_OAEP, &params, sizeof(params) } : CK_MECHANISM{ CKM_RSA_PKCS, nullptr, 0 };
	if(d->f->C_DecryptInit(d->session, &mech, d->key) != CKR_OK) {
		d->logout();
		return CRYPTO_ERROR;
	}
	CK_ULONG size = 0;
	if(d->f->C_Decrypt(d->session, CK_CHAR_PTR(data.data()), CK_ULONG(data.size()), 0, &size) != CKR_OK) {
		d->logout();
		return CRYPTO_ERROR;
	}
	dst.resize(size);
	if(d->f->C_Decrypt(d->session, CK_CHAR_PTR(data.data()), CK_ULONG(data.size()), dst.data(), &size) != CKR_OK) return CRYPTO_ERROR;
	d->logout();
	return OK;
}

int
libcdoc::PKCS11Backend::deriveECDH1(std::vector<uint8_t>& dst, const std::vector<uint8_t> &public_key, const std::string& label)
{
	if(!d) return CRYPTO_ERROR;

	int result = connectToKey(label);
	if (result != OK) return result;

	std::vector<uint8_t> sharedSecret;

	CK_ECDH1_DERIVE_PARAMS ecdh_parms = { CKD_NULL, 0, nullptr, CK_ULONG(public_key.size()), CK_BYTE_PTR(public_key.data()) };
	CK_MECHANISM mech = { CKM_ECDH1_DERIVE, &ecdh_parms, sizeof(CK_ECDH1_DERIVE_PARAMS) };
	CK_BBOOL _false = CK_FALSE;
	CK_OBJECT_CLASS newkey_class = CKO_SECRET_KEY;
	CK_KEY_TYPE newkey_type = CKK_GENERIC_SECRET;
	std::vector<CK_ATTRIBUTE> newkey_template{
		{CKA_TOKEN, &_false, sizeof(_false)},
		{CKA_CLASS, &newkey_class, sizeof(newkey_class)},
		{CKA_KEY_TYPE, &newkey_type, sizeof(newkey_type)}
	};
	CK_OBJECT_HANDLE newkey = CK_INVALID_HANDLE;
	if(d->f->C_DeriveKey(d->session, &mech, d->key, newkey_template.data(), CK_ULONG(newkey_template.size()), &newkey) != CKR_OK) {
		d->logout();
		return CRYPTO_ERROR;
	}

	std::vector<uint8_t> val = d->attribute(d->session, newkey, CKA_VALUE);
	d->logout();
	if (val.empty()) return CRYPTO_ERROR;
	dst = val;
	return OK;
}

int
libcdoc::PKCS11Backend::extractHKDF(std::vector<uint8_t>& kek, const std::vector<uint8_t>& salt, const std::vector<uint8_t> pw_salt, int32_t kdf_iter, const std::string& label)
{
	if (kdf_iter > 0) return libcdoc::NOT_IMPLEMENTED;

	if(!d) return CRYPTO_ERROR;

	int result = connectToKey(label);
	if (result != OK) return result;

	CK_HKDF_PARAMS hkdf_params = {
		1, // bExtract
		0, // bExpand
		CKM_SHA256, // prfHashMechanism
		CKF_HKDF_SALT_DATA, // ulSaltType
		(CK_BYTE_PTR) salt.data(), // pSalt
		(CK_ULONG) salt.size(), // ulSaltLen
		0, // hSaltKey
		nullptr, // pInfo
		0 // ulInfoLen
	};
	CK_MECHANISM mech = {
		CKM_HKDF_DERIVE,
		&hkdf_params,
		sizeof(CK_HKDF_PARAMS)
	};
	CK_BBOOL _false = CK_FALSE;
	CK_OBJECT_CLASS newkey_class = CKO_SECRET_KEY;
	CK_KEY_TYPE newkey_type = CKK_GENERIC_SECRET;
	CK_ULONG newkey_value_len = 32;
	std::vector<CK_ATTRIBUTE> newkey_template{
		{CKA_TOKEN, &_false, sizeof(_false)},
		{CKA_CLASS, &newkey_class, sizeof(newkey_class)},
		{CKA_KEY_TYPE, &newkey_type, sizeof(newkey_type)},
		{CKA_VALUE_LEN, &newkey_value_len, sizeof(newkey_value_len)}
	};
	CK_OBJECT_HANDLE newkey = CK_INVALID_HANDLE;
	if(d->f->C_DeriveKey(d->session, &mech, d->key, newkey_template.data(), CK_ULONG(newkey_template.size()), &newkey) != CKR_OK) {
		d->logout();
		return CRYPTO_ERROR;
	}

	std::vector<uint8_t> val = d->attribute(d->session, newkey, CKA_VALUE);
	d->logout();
	if (val.empty()) return CRYPTO_ERROR;
	kek = val;
	return OK;
}

