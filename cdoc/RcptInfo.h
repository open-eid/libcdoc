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

#ifndef RCPTINFO_H
#define RCPTINFO_H

#include "utils/memory.h"

#include <vector>

namespace libcdoc {

struct RcptInfo {
    struct PKCS11Info {
        long slot = 0;
        std::vector<uint8_t> key_id;
        std::string key_label;
    };

    enum Type {
        LOCK,
        CERT,
        PASSWORD,
        SKEY,
        PKEY,
        P11_SYMMETRIC,
        P11_PKI,
        NCRYPT,
        SHARE
    };

    Type type;
    std::string label;
    std::vector<uint8_t> cert;
    SecureBytes secret;
    PKCS11Info p11;

    std::string key_file_name;
    std::string id;
    int lock_idx = -1;
    int resolved_lock_idx = -1;
};

}

#endif // RCPTINFO_H
