#ifndef RCPTINFO_H
#define RCPTINFO_H

#include <vector>

namespace libcdoc {

struct RcptInfo {
    enum Type {
        // Detect type from container
        ANY,
        CERT,
        PASSWORD,
        // Symetric key from command line
        SKEY,
        // Public key from command line
        PKEY,
        // Symetric key from PKCS11 device
        P11_SYMMETRIC,
        // Public key from PKC11 device
        P11_PKI
    };

    Type type;
    std::vector<uint8_t> cert;
    // Pin or password
    std::vector<uint8_t> secret;
    long slot = 0;
    std::vector<uint8_t> key_id;
    std::string key_label;
};

}

#endif // RCPTINFO_H
