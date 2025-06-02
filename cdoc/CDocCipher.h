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

#ifndef CDOCCIPHER_H
#define CDOCCIPHER_H

#include "CDocReader.h"
#include "CDocWriter.h"
#include "RcptInfo.h"
#include "ToolConf.h"

#include <map>
#include <memory>

namespace libcdoc
{

typedef typename std::map<int, RcptInfo>         RecipientInfoIdMap;
typedef typename std::vector<RcptInfo>           RecipientInfoVector;

class CDocCipher
{
public:
    CDocCipher() = default;
    CDocCipher(const CDocCipher&) = delete;
    CDocCipher(CDocCipher&&) = delete;

    int Encrypt(ToolConf& conf, RecipientInfoVector& recipients);

    int Decrypt(ToolConf& conf, int idx_base_1, const RcptInfo& recipient);
    int Decrypt(ToolConf& conf, const std::string& label, const RcptInfo& recipient);

    int ReEncrypt(ToolConf& conf, int lock_idx_base_1, const std::string& lock_label, const RcptInfo& lock_info, RecipientInfoVector& recipients);

    void Locks(const char* file) const;

private:
    int writer_push(CDocWriter& writer, const std::vector<libcdoc::Recipient>& keys, const std::vector<std::string>& files);
    int Decrypt(const std::unique_ptr<CDocReader>& rdr, unsigned int lock_idx, const std::string& base_path);
};

}

#endif // CDOCCIPHER_H
