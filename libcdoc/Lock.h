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

#include <libcdoc/Exports.h>

#include <cstdint>
#include <string>
#include <vector>
#include <map>

namespace libcdoc {

struct CDOC_EXPORT Lock
{
	enum Type : unsigned char {
		INVALID,
		// Plain symmetric key
		SYMMETRIC_KEY,
		// PBKDF based symmetric key
		PASSWORD,
		PUBLIC_KEY,
		// PKI lock with certificate data
		CERTIFICATE,
		// CDoc1 lock - PKI with additional data
		CDOC1,
		// PKI lock with key material stored in server
		SERVER
	};

	enum PKType : unsigned char {
		ECC,
		RSA
	};

	enum Params : unsigned int {
		// SYMMETRIC_KEY, PASSWORD
		SALT,
		// PASSWORD
		PW_SALT,
		// PASSWORD
		KDF_ITER,
		// PUBLIC_KEY, CERTIFICATE, CDOC1, SERVER
		RCPT_KEY,
		// CERTIFICATE
		CERT,
		// CDoc1: ECC ephemereal key
		// CDoc2: Either ECC ephemereal key or RSA encrypted KEK
		KEY_MATERIAL,
		// SERVER
		KEYSERVER_ID,
		// SERVER
		TRANSACTION_ID,
		// CDOC1
		CONCAT_DIGEST,
		METHOD,
		ALGORITHM_ID,
		PARTY_UINFO,
		PARTY_VINFO
	};

	std::vector<uint8_t> getBytes(Params key) const { return params.at(key); };
	std::string getString(Params key) const;
	int32_t getInt(Params key) const;

	Type type = Type::INVALID;
	PKType pk_type = PKType::ECC;

	std::string label;
	std::vector<uint8_t> encrypted_fmk;

	bool isValid() const { return (type != Type::INVALID) && !label.empty() && !encrypted_fmk.empty(); }
	bool isSymmetric() const { return (type == Type::SYMMETRIC_KEY) || (type == Type::PASSWORD); }
	bool isPKI() const { return (type == Type::CERTIFICATE) || (type == Type::CDOC1) || (type == Type::PUBLIC_KEY) || (type == Type::SERVER); }
	bool isCertificate() const { return (type == Type::CERTIFICATE) || (type == Type::CDOC1); }
	bool isCDoc1() const { return type == Type::CDOC1; }
	bool isRSA() const { return pk_type == PKType::RSA; }

	bool hasTheSameKey(const Lock &key) const;
	bool hasTheSameKey(const std::vector<uint8_t>& public_key) const;

	Lock() = default;
	Lock(Type _type) : type(_type) {};

	void setBytes(Params key, const std::vector<uint8_t>& val) { params[key] = val; }
	void setString(Params key, const std::string& val) { params[key] = std::vector<uint8_t>(val.cbegin(), val.cend()); }
	void setInt(Params key, int32_t val);

	bool operator== (const Lock& other) const = default;

	// Set certificate, rcpt_key and pk_type values
	void setCertificate(const std::vector<uint8_t>& cert);
private:
	std::map<int,std::vector<uint8_t>> params;
};

} // namespace libcdoc

#endif // LOCK_H
