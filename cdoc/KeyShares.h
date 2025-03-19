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

#include <string>

namespace libcdoc {

struct ShareAccessData {
    std::string base_url;
    std::string share_id;
    std::string nonce;
};

void fetchKeyShare(const ShareAccessData& acc);

result_t authKeyshares(const std::string& rcpt_id, const std::vector<uint8_t>& digest);

} // namespace libcdoc

#endif // LOCK_H
