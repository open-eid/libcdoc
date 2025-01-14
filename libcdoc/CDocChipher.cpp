#include <cstring>
#include <iostream>
#include <sstream>
#include <map>

#include "CDocChipher.h"
#include "CDocReader.h"
#include "CDoc.h"
#include "CDoc2.h"
#include "Certificate.h"
#include "PKCS11Backend.h"
#include "Utils.h"

using namespace std;
using namespace libcdoc;


struct ToolPKCS11 : public libcdoc::PKCS11Backend {
    const RecipientInfoLabelMap& rcpts;

    ToolPKCS11(const std::string& library, const RecipientInfoLabelMap& map) : libcdoc::PKCS11Backend(library), rcpts(map) {}

    int connectToKey(const std::string& label, bool priv) override final {
        if (!rcpts.contains(label)) return libcdoc::CRYPTO_ERROR;
        const RcptInfo& rcpt = rcpts.at(label);
        int result = libcdoc::CRYPTO_ERROR;
        if (!priv) {
            result = useSecretKey(rcpt.slot, rcpt.secret, rcpt.key_id, rcpt.key_label);
        } else {
            result = usePrivateKey(rcpt.slot, rcpt.secret, rcpt.key_id, rcpt.key_label);
        }
        if (result != libcdoc::OK) return result;
        return libcdoc::OK;
    }
};

struct ToolCrypto : public libcdoc::CryptoBackend {
    const RecipientInfoLabelMap& rcpts;
    std::unique_ptr<libcdoc::PKCS11Backend> p11;

    ToolCrypto(const RecipientInfoLabelMap& recipients) : rcpts(recipients) {
    }

    bool connectLibrary(const std::string& library) {
        p11 = std::make_unique<ToolPKCS11>(library, rcpts);
        return true;
    }

    int decryptRSA(std::vector<uint8_t>& dst, const std::vector<uint8_t> &data, bool oaep, const std::string& label) override final {
        if (p11) return p11->decryptRSA(dst, data, oaep, label);
        return libcdoc::NOT_IMPLEMENTED;
    }
    int deriveConcatKDF(std::vector<uint8_t>& dst, const std::vector<uint8_t> &publicKey, const std::string &digest,
                        const std::vector<uint8_t> &algorithmID, const std::vector<uint8_t> &partyUInfo, const std::vector<uint8_t> &partyVInfo, const std::string& label) override final {
        if (p11) return p11->deriveConcatKDF(dst, publicKey, digest, algorithmID, partyUInfo, partyVInfo, label);
        return libcdoc::NOT_IMPLEMENTED;
    }
    int deriveHMACExtract(std::vector<uint8_t>& dst, const std::vector<uint8_t> &publicKey, const std::vector<uint8_t> &salt, const std::string& label) override final {
        if (p11) return p11->deriveHMACExtract(dst, publicKey, salt, label);
        return libcdoc::NOT_IMPLEMENTED;
    }
    int extractHKDF(std::vector<uint8_t>& kek, const std::vector<uint8_t>& salt, const std::vector<uint8_t>& pw_salt, int32_t kdf_iter, const std::string& label) override {
        if (p11) return p11->extractHKDF(kek, salt, pw_salt, kdf_iter, label);
        return libcdoc::CryptoBackend::extractHKDF(kek, salt, pw_salt, kdf_iter, label);
    }
    int getSecret(std::vector<uint8_t>& secret, const std::string& label) override final {
        const RcptInfo& rcpt = rcpts.at(label);
        secret =rcpt.secret;
        return secret.empty() ? INVALID_PARAMS : libcdoc::OK;
    }

    int sign(std::vector<uint8_t>& dst, HashAlgorithm algorithm, const std::vector<uint8_t> &digest, const std::string& label) override final {
        if (p11) return p11->sign(dst, algorithm, digest, label);
        return libcdoc::NOT_IMPLEMENTED;
    }
};

struct ToolNetwork : public libcdoc::NetworkBackend {
    ToolCrypto *crypto;

    std::string label;

    std::vector<std::vector<uint8_t>> certs;

    explicit ToolNetwork(ToolCrypto *_crypto) : crypto(_crypto) {
    }

    int getClientTLSCertificate(std::vector<uint8_t>& dst) override final {
        if (!crypto->rcpts.contains(label)) return libcdoc::CRYPTO_ERROR;
        const RcptInfo& rcpt = crypto->rcpts.at(label);
        bool rsa = false;
        return crypto->p11->getCertificate(dst, rsa, rcpt.slot, rcpt.secret, rcpt.key_id, rcpt.key_label);
    }

    int getPeerTLSCertificates(std::vector<std::vector<uint8_t>> &dst) override final {
        dst = certs;
        return libcdoc::OK;
    }

    int signTLS(std::vector<uint8_t>& dst, libcdoc::CryptoBackend::HashAlgorithm algorithm, const std::vector<uint8_t> &digest) override final {
        return crypto->p11->sign(dst, algorithm, digest, label);
    }

};


int CDocChipher::writer_push(CDocWriter& writer, const vector<Recipient>& keys, const vector<string>& files)
{
    int result = writer.beginEncryption();
    if (result != libcdoc::OK) return result;
    for (const libcdoc::Recipient& rcpt : keys) {
        result = writer.addRecipient(rcpt);
        if (result != libcdoc::OK) return result;
    }
    for (const std::string& file : files) {
        std::filesystem::path path(file);
        if (!std::filesystem::exists(path)) {
            cerr << "File does not exist: " << file << endl;
            return 1;
        }
        size_t size = std::filesystem::file_size(path);
        int result = writer.addFile(file, size);
        if (result != libcdoc::OK) return result;
        libcdoc::IStreamSource src(file);
        while (!src.isEof()) {
            uint8_t b[256];
            int64_t len = src.read(b, 256);
            if (len < 0) {
                std::cerr << "IO error: " << file;
                return 1;
            }
            int64_t nbytes = writer.writeData(b, len);
            if (nbytes < 0) return (int) nbytes;
        }
    }
    return writer.finishEncryption();
}

#define PUSH true


int CDocChipher::Encrypt(ToolConf& conf, RecipientInfoVector& recipients, const vector<vector<uint8_t>>& certs)
{
    RecipientInfoLabelMap rcptsInfo;
    ToolCrypto crypto(rcptsInfo);
    ToolNetwork network(&crypto);
    network.certs = certs;

    if (!conf.library.empty())
        crypto.connectLibrary(conf.library);

    vector<libcdoc::Recipient> rcpts;
    for (RecipientInfoVector::const_reference rcpt : recipients)
    {
        // Generate the labels if needed
        string label;
        if (conf.gen_label)
        {
            switch (rcpt.type)
            {
            case RcptInfo::Type::PASSWORD:
                label = std::move(Recipient::BuildLabelPassword(CDoc2::KEYLABELVERSION, rcpt.label.empty() ? GenerateRandomSequence() : rcpt.label));
                break;

            case RcptInfo::Type::SKEY:
                label = std::move(Recipient::BuildLabelSymmetricKey(CDoc2::KEYLABELVERSION, rcpt.label.empty() ? GenerateRandomSequence() : rcpt.label, rcpt.key_file_name));
                break;

            case RcptInfo::Type::PKEY:
                label = std::move(Recipient::BuildLabelPublicKey(CDoc2::KEYLABELVERSION, rcpt.key_file_name));
                break;

            case RcptInfo::Type::P11_PKI:
            {
                bool isRsa;
                vector<uint8_t> cert_bytes;
                ToolPKCS11* p11 = dynamic_cast<ToolPKCS11*>(crypto.p11.get());
                int result = p11->getCertificate(cert_bytes, isRsa, rcpt.slot, rcpt.secret, rcpt.key_id, rcpt.key_label);
                if (result != libcdoc::OK)
                {
                    cerr << "Certificate reading from SC card failed. Key label: " << rcpt.key_label << endl;
                    return 1;
                }
                Certificate cert(cert_bytes);
                label = std::move(Recipient::BuildLabelEID(CDoc2::KEYLABELVERSION, Recipient::getEIDType(cert.policies()), cert.getCommonName(), cert.getSerialNumber(), cert.getSurname(), cert.getGivenName()));
                break;
            }

            case RcptInfo::Type::CERT:
            {
                Certificate cert(rcpt.cert);

                // TODO: How to get certificate fingerprint without re-calculating it?
                label = std::move(Recipient::BuildLabelCertificate(CDoc2::KEYLABELVERSION, rcpt.key_file_name, cert.getCommonName(), {}));
                break;
            }
            case RcptInfo::Type::P11_SYMMETRIC:
                // TODO: what label should be generated in this case?
                break;

            default:
                cerr << "Unhandled recipient type " << rcpt.type << " for generating the lock's label" << endl;
                break;
            }
#ifndef NDEBUG
            cerr << "Generated label: " << label << endl;
#endif
        }
        else
        {
            label = rcpt.label;
        }

        if (label.empty()) {
            cerr << "No lock label" << endl;
            return 1;
        }

        // Map does not have value's move assignment operator. Hence,
        // the object is always copied, even if an R-value is assigned.
        rcptsInfo[label] = rcpt;

        libcdoc::Recipient key;
        if (rcpt.type == RcptInfo::Type::CERT) {
            key = libcdoc::Recipient::makeCertificate(label, rcpt.cert);
        } else if (rcpt.type == RcptInfo::Type::SKEY) {
            key = libcdoc::Recipient::makeSymmetric(label, 0);
            std::cerr << "Creating symmetric key:" << std::endl;
        } else if (rcpt.type == RcptInfo::Type::PKEY) {
            if (!conf.servers.empty()) {
                key = libcdoc::Recipient::makeServer(label, rcpt.secret, libcdoc::Recipient::PKType::ECC, conf.servers[0].ID);
            } else {
                key = libcdoc::Recipient::makePublicKey(label, rcpt.secret, libcdoc::Recipient::PKType::ECC);
            }
            std::cerr << "Creating public key:" << std::endl;
        } else if (rcpt.type == RcptInfo::Type::P11_SYMMETRIC) {
            key = libcdoc::Recipient::makeSymmetric(label, 0);
        } else if (rcpt.type == RcptInfo::Type::P11_PKI) {
            std::vector<uint8_t> val;
            bool rsa;
            ToolPKCS11* p11 = dynamic_cast<ToolPKCS11*>(crypto.p11.get());
            int result = p11->getPublicKey(val, rsa, rcpt.slot, rcpt.secret, rcpt.key_id, rcpt.key_label);
            if (result != libcdoc::OK) {
                std::cerr << "No such public key: " << rcpt.key_label << std::endl;
                continue;
            }
            std::cerr << "Public key (" << (rsa ? "rsa" : "ecc") << "):" << libcdoc::toHex(val) << std::endl;
            if (!conf.servers.empty()) {
                key = libcdoc::Recipient::makeServer(label, val, rsa ? libcdoc::Recipient::PKType::RSA : libcdoc::Recipient::PKType::ECC, conf.servers[0].ID);
            } else {
                key = libcdoc::Recipient::makePublicKey(label, val, rsa ? libcdoc::Recipient::PKType::RSA : libcdoc::Recipient::PKType::ECC);
            }
        } else if (rcpt.type == RcptInfo::Type::PASSWORD) {
            std::cerr << "Creating password key:" << std::endl;
            key = libcdoc::Recipient::makeSymmetric(label, 65535);
        }

        rcpts.push_back(std::move(key));
    }

    if (rcpts.empty()) {
        cerr << "No key for encryption was found" << endl;
        return 1;
    }

    unique_ptr<CDocWriter> writer(CDocWriter::createWriter(conf.cdocVersion, conf.out, &conf, &crypto, &network));

    int result;
    if (PUSH) {
        result = writer_push(*writer, rcpts, conf.input_files);
    } else {
        libcdoc::FileListSource src({}, conf.input_files);
        result = writer->encrypt(src, rcpts);
    }
    if (result < 0) {
        cerr << "Encryption failed: error " << result << endl;
        cerr << writer->getLastErrorStr() << endl;
    } else {
        cout << "File encrypted successfully: " << conf.out << endl;
    }

    return result;
}

int CDocChipher::Decrypt(ToolConf& conf, const RecipientInfoIdMap& recipients, const vector<vector<uint8_t>>& certs)
{
    RecipientInfoLabelMap rcpts;
    ToolCrypto crypto(rcpts);
    ToolNetwork network(&crypto);
    network.certs = certs;

    unique_ptr<CDocReader> rdr(CDocReader::createReader(conf.input_files[0], &conf, &crypto, &network));
    if (rdr) {
        cout << "Reader created" << endl;
    } else {
        cerr << "Cannot create reader (invalid file?)" << endl;
        return 1;
    }

    // Acquire the locks and get the labels according to the index
    const vector<const Lock> locks(rdr->getLocks());
    int labelIndex = recipients.cbegin()->first - 1;
    if (labelIndex < 0) {
        cerr << "Indexing of labels starts from 1" << endl;
        return 1;
    }
    if (labelIndex >= locks.size()) {
        cerr << "Label index is out of range" << endl;
        return 1;
    }

    const Lock& lock = locks[labelIndex];
    cerr << "Found matching label: " << lock.label << endl;
    network.label = lock.label;
    rcpts[lock.label] = recipients.cbegin()->second;

    if (!conf.library.empty())
        crypto.connectLibrary(conf.library);

    return Decrypt(rdr, lock, conf.out);
}

int CDocChipher::Decrypt(ToolConf& conf, const RecipientInfoLabelMap& recipients, const vector<vector<uint8_t>>& certs)
{
    ToolCrypto crypto(recipients);
    ToolNetwork network(&crypto);
    network.certs = certs;

    const string& label = recipients.cbegin()->first;
    network.label = label;

    if (!conf.library.empty())
        crypto.connectLibrary(conf.library);

    unique_ptr<CDocReader> rdr(CDocReader::createReader(conf.input_files[0], &conf, &crypto, &network));
    if (!rdr) {
        cerr << "Cannot create reader (invalid file?)" << endl;
        return 1;
    }
    cout << "Reader created" << endl;
    vector<const Lock> locks(rdr->getLocks());
    for (const Lock& lock : locks) {
        if (lock.label == label) {
            cerr << "Found matching label: " << label << endl;
            return Decrypt(rdr, lock, conf.out);
        }
    }

    cerr << "Lock not found: " << label << endl;
    return 1;
}

int CDocChipher::Decrypt(const unique_ptr<CDocReader>& rdr, const Lock& lock, const string& base_path)
{
    vector<uint8_t> fmk;
    int result = rdr->getFMK(fmk, lock);
    if (result != libcdoc::OK) {
        cerr << "Error on extracting FMK: " << result << endl;
        cerr << rdr->getLastErrorStr() << endl;
        return 1;
    }
    FileListConsumer fileWriter(base_path);
    result = rdr->decrypt(fmk, &fileWriter);
    if (result != libcdoc::OK) {
        cerr << "Error on decrypting files: " << result << endl;
        cerr << rdr->getLastErrorStr() << endl;
        return 1;
    }
    cout << "File decrypted successfully" << endl;
    return 0;
}

void CDocChipher::Locks(const char* file) const
{
    unique_ptr<CDocReader> rdr(CDocReader::createReader(file, nullptr, nullptr, nullptr));
    const vector<const Lock> locks(rdr->getLocks());

    int lock_id = 1;
    for (const Lock& lock : locks) {
        vector<pair<string, string>> parsed_label(Recipient::parseLabel(lock.label));
        if (parsed_label.empty()) {
            // Human-readable label
            cout << lock_id << ": " << lock.label << endl;
        } else {
            // Machine generated label
            // Find the longest field
            int maxFieldLength = 0;
            for (vector<pair<string, string>>::const_reference pair : parsed_label) {
                if (pair.first.size() > maxFieldLength) {
                    maxFieldLength = static_cast<int>(pair.first.size());
                }
            }

            // Output the fields with their values
            cout << lock_id << ":" << endl;
            for (vector<pair<string, string>>::const_reference pair : parsed_label) {
                cout << "  " << setw(maxFieldLength + 1) << left << pair.first << ": " << pair.second << endl;
            }

            cout << endl;
        }

        lock_id++;
    }
}

string CDocChipher::GenerateRandomSequence() const
{
    constexpr uint32_t upperbound = 'z' - '0' + 1;
    constexpr int MaxSequenceLength = 11;

    uint32_t rnd;
    ostringstream sequence;
    for (int cnt = 0; cnt < MaxSequenceLength;)
    {
        rnd = arc4random_uniform(upperbound) + '0';
        if (isalnum(rnd))
        {
            sequence << static_cast<char>(rnd);
            cnt++;
        }
    }

    return sequence.str();
}
