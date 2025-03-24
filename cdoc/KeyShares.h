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

#include <cdoc/CryptoBackend.h>
#include <cdoc/CDoc.h>

#include <cstdint>
#include <string>
#include <system_error>

namespace libcdoc {

/**
 * @brief Share information from CDoc capsule
 * 
 * Contains the full share information, including session nonce queried from the server
 * 
 */
struct ShareData {
    std::string base_url;
    std::string share_id;
    std::string nonce;
    
    /**
     * @brief Construct a new Share Data object for authentication
     * 
     * @param base_url share server base url (e.g. https://cdoc2.my.domain/v1/)
     * @param share_id share id from capsule
     * @param nonce session nonce from server
     */
    ShareData(const std::string& base_url, const std::string& share_id, const std::string& nonce);

    std::string getURL();
};

struct Signer {
    virtual result_t generateTickets(std::vector<std::string>& dst, std::vector<libcdoc::ShareData>& shares) = 0;
};

struct SIDSigner : public Signer {
    SIDSigner(const std::string& _id) : rcpt_id(_id) {}
    std::string rcpt_id;
    /* After successful authentication holds the user certificate value */
    std::vector<uint8_t> cert;

    result_t generateTickets(std::vector<std::string>& dst, std::vector<libcdoc::ShareData>& shares) final;
};

struct MIDSigner : public Signer {
    MIDSigner(const std::string& _id) : rcpt_id(_id) {}
    std::string rcpt_id;
    /* After successful authentication holds the user certificate value */
    std::vector<uint8_t> cert;

    result_t generateTickets(std::vector<std::string>& dst, std::vector<libcdoc::ShareData>& shares) final;
};

result_t signSID(std::vector<uint8_t>& dst, std::vector<uint8_t>& cert,
    const std::string& url, const std::string& rp_uuid, const std::string& rp_name,
    const std::string& rcpt_id, const std::vector<uint8_t>& digest, CryptoBackend::HashAlgorithm algo);

struct Disclosure {
    // Disclosure salt (base64url)
    std::string salt64;
    // Disclosure JSON
    std::string json;

    Disclosure(const std::string name, const std::string& val);
    Disclosure(const std::string name, std::vector<Disclosure>& val);

    std::string getHash();
};

} // namespace libcdoc

#endif // LOCK_H
