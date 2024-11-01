#ifndef __RECIPIENT_H__
#define __RECIPIENT_H__

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

#include <string>

namespace libcdoc {

struct CDOC_EXPORT Recipient {
	enum Type : unsigned char {
		NONE,
		// Symmetric key (plain or PBKDF)
		SYMMETRIC_KEY,
		PUBLIC_KEY,
		// Public key with additonal information
		CERTIFICATE,
	};

	enum PKType : unsigned char {
		ECC,
		RSA
	};

	Recipient() = default;

	Type type = Type::NONE;
	PKType pk_type = PKType::ECC;
	// 0 symmetric key, >0 password
	int32_t kdf_iter = 0;
	std::string label;
	// Recipient's public key
	std::vector<uint8_t> rcpt_key;
	std::vector<uint8_t> cert;

	bool isEmpty() const { return type == Type::NONE; }
	bool isSymmetric() const { return type == Type::SYMMETRIC_KEY; }
	bool isPKI() const { return (type == Type::CERTIFICATE) || (type == Type::PUBLIC_KEY); }
	bool isCertificate() const { return (type == Type::CERTIFICATE); }

	void clear() { type = Type::NONE; pk_type = PKType::ECC; label.clear(); kdf_iter = 0; rcpt_key.clear(); cert.clear(); }

	bool isTheSameRecipient(const Recipient &other) const;
	bool isTheSameRecipient(const std::vector<uint8_t>& public_key) const;

	static Recipient makeSymmetric(const std::string& label, int32_t kdf_iter);
	static Recipient makeCertificate(const std::string& label, const std::vector<uint8_t>& cert);

	bool operator== (const Recipient& other) const = default;
protected:
	Recipient(Type _type) : type(_type) {};
private:
};

} // namespace libcdoc

#endif // RECIPIENT_H
