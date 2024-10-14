#ifndef __LOCK_H__
#define __LOCK_H__

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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <string>
#include <vector>

namespace libcdoc {

struct Lock
{
public:
	enum Type : uint8_t {
		SYMMETRIC_KEY,
		PUBLIC_KEY,
		CERTIFICATE,
		CDOC1,
		SERVER
	};

	enum PKType : uint8_t {
		ECC,
		RSA
	};

	Type type;
	std::string label;

	// Decryption data
	std::vector<uint8_t> encrypted_fmk;

	// Recipients public key
	// QByteArray key;

	bool isSymmetric() const { return type == Type::SYMMETRIC_KEY; }
	bool isPKI() const { return (type == Type::CERTIFICATE) || (type == Type::CDOC1) || (type == Type::PUBLIC_KEY) || (type == Type::SERVER); }
	bool isCertificate() const { return (type == Type::CERTIFICATE) || (type == Type::CDOC1); }
	bool isCDoc1() const { return type == Type::CDOC1; }

	bool hasTheSameKey(const Lock &key) const;
	bool hasTheSameKey(const std::vector<uint8_t>& public_key) const;

	virtual ~Lock() = default;
protected:
	Lock(Type _type) : type(_type) {};
private:
	bool operator==(const Lock &other) const { return false; }
};

// Symmetric key (plain or PBKDF)
// Usage:
// CDoc2:decrypt LT

struct LockSymmetric : public Lock {
	std::vector<uint8_t> salt;
	// PBKDF
	std::vector<uint8_t> pw_salt;
	// 0 symmetric key, >0 password
	int32_t kdf_iter;

	LockSymmetric(const std::vector<uint8_t>& _salt) : Lock(Type::SYMMETRIC_KEY), salt(_salt), kdf_iter(0) {}
	LockSymmetric(const std::vector<uint8_t>& _salt, const std::vector<uint8_t>& _pw_salt, int32_t _kdf_iter) : Lock(Type::SYMMETRIC_KEY), salt(_salt), pw_salt(_pw_salt), kdf_iter(_kdf_iter) {}
};

// Base PKI key
// Usage:
// CDoc2:encrypt

struct LockPKI : public Lock {
	// Recipient's public key
	PKType pk_type;
	std::vector<uint8_t> rcpt_key;

protected:
	LockPKI(Type _type) : Lock(_type), pk_type(PKType::ECC) {};
	LockPKI(Type _type, PKType _pk_type, const std::vector<uint8_t>& _rcpt_key) : Lock(_type), pk_type(_pk_type), rcpt_key(_rcpt_key) {};
	LockPKI(Type _type, PKType _pk_type, const uint8_t *key_data, size_t key_len) : Lock(_type), pk_type(_pk_type), rcpt_key(key_data, key_data + key_len) {};
};

// Public key with additonal information
// Usage:
// CDoc1:encrypt

struct LockCert : public LockPKI {
	std::vector<uint8_t> cert;

	LockCert(const std::string& label, const std::vector<uint8_t> &cert) : LockCert(Lock::Type::CERTIFICATE, label, cert) {};

	void setCert(const std::vector<uint8_t> &_cert);

protected:
	LockCert(Type _type) : LockPKI(_type) {};
	LockCert(Type _type, const std::string& label, const std::vector<uint8_t> &_cert);
};

// CDoc2 PKI key with key material
// Usage:
// CDoc2: decrypt

struct LockPublicKey : public libcdoc::LockPKI {
	// Either ECC public key or RSA encrypted kek
	std::vector<uint8_t> key_material;

	LockPublicKey(PKType _pk_type, const std::vector<uint8_t>& _rcpt_key) : LockPKI(Type::PUBLIC_KEY, _pk_type, _rcpt_key) {};
	LockPublicKey(PKType _pk_type, const uint8_t *_key_data, size_t _key_len) : LockPKI(Type::PUBLIC_KEY, _pk_type, _key_data, _key_len) {};
};

// CDoc2 PKI key with server info
// Usage:
// CDoc2: decrypt

struct LockServer : public libcdoc::LockPKI {
	// Server info
	std::string keyserver_id;
	std::string transaction_id;

	static LockServer *fromKey(const std::vector<uint8_t> _key, PKType _pk_type);
protected:
	LockServer(const std::vector<uint8_t>& _rcpt_key, PKType _pk_type) : LockPKI(Type::SERVER, _pk_type, _rcpt_key) {};
	LockServer(const uint8_t *_key_data, size_t _key_size, PKType _pk_type) : LockPKI(Type::SERVER, _pk_type, _key_data, _key_size) {};
};

// CDoc1 decryption key (with additional information from file)
// Usage:
// CDoc1:decrypt

struct LockCDoc1 : public libcdoc::LockCert {

	std::vector<uint8_t> publicKey;
	std::string concatDigest, method;
	std::vector<uint8_t> AlgorithmID, PartyUInfo, PartyVInfo;

	LockCDoc1() : LockCert(Type::CDOC1) {};
};

} // namespace libcdoc

#endif // LOCK_H
