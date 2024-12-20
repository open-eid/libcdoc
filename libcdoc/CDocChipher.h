#ifndef CDOCCHIPHER_H
#define CDOCCHIPHER_H

namespace libcdoc
{

class CDocChipher
{
public:
    CDocChipher() {}

    int Encrypt(int argc, char *argv[]);
    int Decrypt(int argc, char *argv[]);
    int Locks(int argc, char *argv[]);
};

}

#endif // CDOCCHIPHER_H
