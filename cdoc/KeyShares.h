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

    ShareData(const ShareData& other) = default;

    std::string getSalt();
    std::string getURL();
    // Get base64(utf8(json([salt,url])))
    std::string getDisclosure();
    // Get base64(sha256(disclosure))
    std::string getDisclosureHash();
private:
    std::vector<uint8_t> salt;
};

void fetchKeyShare(const ShareData& acc);

result_t signSID(std::vector<uint8_t>& dst, const std::string& rcpt_id, const std::vector<uint8_t>& digest);

std::string testSID(const std::string& etsiidentifier, std::vector<libcdoc::ShareData> shares);

std::string generateTicket(const std::string& etsiidentifier, std::vector<libcdoc::ShareData> shares, unsigned int idx);

} // namespace libcdoc

#endif // LOCK_H
