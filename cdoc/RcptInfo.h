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

#include <vector>

namespace libcdoc {

struct RcptInfo {
    // PKCS11/NCrypt data
    // NB! PIN is stored in secret
    struct PKCS11Info {
        long slot = 0;
        std::vector<uint8_t> key_id;
        std::string key_label;
    };

    enum Type {
        // For decryption (use the lock type)
        LOCK,

        // For encryption
        // Certificate from file
        CERT,
        // Password from command line
        PASSWORD,
        // Symetric key from command line
        SKEY,
        // Public key from command line
        PKEY,
        // Symetric key from PKCS11 device
        P11_SYMMETRIC,
        // Public key from PKC11 device
        P11_PKI,
        // Windows
        NCRYPT,
        // N of n
        SHARE
    };

    Type type;
    // Locks label
    std::string label;
    // Certificate for encryption
    std::vector<uint8_t> cert;
    // Pin or password
    std::vector<uint8_t> secret;
    // PKCS11-specific info
    PKCS11Info p11;

    // Keyfile name for automatic labels
    std::string key_file_name;
    // ID code for shares server
    std::string id;
    // Lock index
    int lock_idx = -1;
};

}

#endif // RCPTINFO_H
