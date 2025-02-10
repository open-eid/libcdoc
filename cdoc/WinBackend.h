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

#ifndef __LIBCDOC_WINBACKEND_H__
#define __LIBCDOC_WINBACKEND_H__

#include <cdoc/CryptoBackend.h>

#include <memory>

namespace libcdoc {

struct CDOC_EXPORT WinBackend : public CryptoBackend {
    result_t useKey(const std::string& name, const std::string& pin);

    virtual result_t connectToKey(int idx, bool priv) = 0;
    virtual result_t usePSS(int idx) {return true;}

    virtual result_t decryptRSA(std::vector<uint8_t>& dst, const std::vector<uint8_t>& data, bool oaep, unsigned int idx);
    virtual result_t deriveConcatKDF(std::vector<uint8_t>& dst, const std::vector<uint8_t> &public_key, const std::string &digest,
								 const std::vector<uint8_t> &algorithm_id, const std::vector<uint8_t> &party_uinfo,
                                 const std::vector<uint8_t> &party_vinfo, unsigned int idx);
    virtual result_t deriveHMACExtract(std::vector<uint8_t>& dst, const std::vector<uint8_t> &public_key, const std::vector<uint8_t> &salt, unsigned int idx);

    virtual result_t sign(std::vector<uint8_t>& dst, HashAlgorithm algorithm, const std::vector<uint8_t> &digest, unsigned int idx);

    WinBackend(const std::string& provider);
    virtual ~WinBackend();
private:
	struct Private;
	std::unique_ptr<Private> d;
};

} // namespace libcdoc

#endif
