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

#ifndef __KEYSHARES_H__
#define __KEYSHARES_H__

#include <cdoc/CDoc.h>

#include <cstdint>
#include <string>

namespace libcdoc {

struct ShareData {
    std::string base_url;
    std::string share_id;
    std::string nonce;
    
    ShareData(const std::string& base_url, const std::string& share_id, const std::string& nonce);

    std::string getURL();
};

struct Disclosure {
    // Disclosure salt (base64url)
    std::string salt64;
    // Disclosure JSON
    std::string json;

    Disclosure(const std::string name, const std::string& val);
    Disclosure(const std::string name, std::vector<Disclosure>& val);

    std::string getHash();
};

struct Signer {
    virtual std::string sign(const std::string& data, std::error_code& ec) const = 0;
    virtual void verify(const std::string& data, const std::string& signature, std::error_code& ec) const = 0;
    std::string name() const { return "RS256"; }
};

struct SIDSigner : public Signer {
    SIDSigner(const std::string& _id, std::vector<uint8_t>& _cert) : id(_id), cert(_cert) {}
    std::string sign(const std::string& data, std::error_code& ec) const final;
    void verify(const std::string& data, const std::string& signature, std::error_code& ec) const final;
    std::string id;
    std::vector<uint8_t> &cert;
};

void fetchKeyShare(const ShareData& acc);

result_t signSID(std::vector<uint8_t>& dst, std::vector<uint8_t>& cert, const std::string& rcpt_id, const std::vector<uint8_t>& digest);

std::string testSID(const std::string& etsiidentifier, Disclosure& aud, Signer& signer);

result_t generateTickets(std::vector<std::string>& dst, std::vector<uint8_t>& cert, const std::string& rcpt_id, std::vector<libcdoc::ShareData>& shares);

} // namespace libcdoc

#endif // LOCK_H
