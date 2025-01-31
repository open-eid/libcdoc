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

#include "Exports.h"

#include <map>
#include <string>
#include <vector>
#include <cstdint>

namespace libcdoc {

struct CDOC_EXPORT Recipient {
	enum Type : unsigned char {
		NONE,
		// Symmetric key (plain or PBKDF)
		SYMMETRIC_KEY,
        // Plain public key
		PUBLIC_KEY,
        // Public key + certificate chain
		CERTIFICATE,
        // Public key, key material stored on server
        SERVER
	};

	enum PKType : unsigned char {
		ECC,
		RSA
	};

    enum EIDType {
        Unknown,
        IDCard,
        DigiID,
        DigiID_EResident
    };

	Recipient() = default;

	Type type = Type::NONE;
	PKType pk_type = PKType::ECC;
	// 0 symmetric key, >0 password
	int32_t kdf_iter = 0;
	std::string label;
    // Recipient's public key (for all PKI types)
    std::vector<uint8_t> rcpt_key;

    std::vector<uint8_t> cert;
    std::string server_id;

	bool isEmpty() const { return type == Type::NONE; }
	bool isSymmetric() const { return type == Type::SYMMETRIC_KEY; }
    bool isPKI() const { return (type == Type::CERTIFICATE) || (type == Type::PUBLIC_KEY) || (type == Type::SERVER); }
	bool isCertificate() const { return (type == Type::CERTIFICATE); }
    bool isKeyServer() const { return (type == Type::SERVER); }

    void clear() { type = Type::NONE; pk_type = PKType::ECC; label.clear(); kdf_iter = 0; rcpt_key.clear(); cert.clear(); }

	bool isTheSameRecipient(const Recipient &other) const;
	bool isTheSameRecipient(const std::vector<uint8_t>& public_key) const;

	static Recipient makeSymmetric(const std::string& label, int32_t kdf_iter);
	static Recipient makePublicKey(const std::string& label, const std::vector<uint8_t>& public_key, PKType pk_type);
	static Recipient makeCertificate(const std::string& label, const std::vector<uint8_t>& cert);
    static Recipient makeServer(const std::string& label, const std::vector<uint8_t>& public_key, PKType pk_type, const std::string& server_id);

    static std::string buildLabel(std::vector<std::pair<std::string_view, std::string_view>> components);
    static std::string BuildLabelEID(int version, EIDType type, const std::string& cn, const std::string& serial_number, const std::string& last_name, const std::string& first_name);
    static std::string BuildLabelCertificate(int version, const std::string file, const std::string& cn, const std::vector<uint8_t>& cert_sha1);
    static std::string BuildLabelPublicKey(int version, const std::string file);
    static std::string BuildLabelSymmetricKey(int version, const std::string& label, const std::string file);
    static std::string BuildLabelPassword(int version, const std::string& label);

    static EIDType getEIDType(const std::vector<std::string>& policies);

    static std::map<std::string, std::string> parseLabel(const std::string& label);

    bool operator== (const Recipient& other) const = default;
protected:
	Recipient(Type _type) : type(_type) {};
private:
};

} // namespace libcdoc

#endif // RECIPIENT_H
