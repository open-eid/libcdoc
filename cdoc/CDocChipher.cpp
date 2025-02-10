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

#include <sstream>
#include <map>
#include <openssl/rand.h>

#include "CDocChipher.h"
#include "CDocReader.h"
#include "CDoc.h"
#include "CDoc2.h"
#include "Certificate.h"
#include "Crypto.h"
#include "ILogger.h"
#include "PKCS11Backend.h"
#include "Utils.h"


using namespace std;
using namespace libcdoc;


struct ToolPKCS11 : public libcdoc::PKCS11Backend {
    const RecipientInfoVector& rcpts;

    ToolPKCS11(const std::string& library, const RecipientInfoVector& vec) : libcdoc::PKCS11Backend(library), rcpts(vec) {}

    int connectToKey(int idx, bool priv) override final {
        if ((idx < 0) || (idx >= rcpts.size())) return libcdoc::CRYPTO_ERROR;
        const RcptInfo& rcpt = rcpts.at(idx);
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

#ifdef _WIN32
struct ToolWin : public libcdoc::WinBackend {
    const RecipientInfoVector& rcpts;

    ToolWin(const std::string& provider, const RecipientInfoVector& vec) : libcdoc::WinBackend(provider), rcpts(vec) {}

    int connectToKey(int idx, bool priv) {
        return useKey(rcpts[idx].key_label, std::string(rcpts[idx].secret.cbegin(), rcpts[idx].secret.cend()));
    }

};
#endif

struct ToolCrypto : public libcdoc::CryptoBackend {
    const RecipientInfoVector& rcpts;
    std::unique_ptr<libcdoc::PKCS11Backend> p11;
#ifdef _WIN32
    std::unique_ptr<libcdoc::WinBackend> ncrypt;
#endif

    ToolCrypto(const RecipientInfoVector& recipients) : rcpts(recipients) {
    }

    bool connectLibrary(const std::string& library) {
        p11 = std::make_unique<ToolPKCS11>(library, rcpts);
        return true;
    }

    bool connectNCrypt() {
#ifdef _WIN32
        ncrypt = std::make_unique<ToolWin>("", rcpts);
        return true;
#else
        return false;
#endif
    }

    int decryptRSA(std::vector<uint8_t>& dst, const std::vector<uint8_t> &data, bool oaep, unsigned int idx) override final {
        if (p11) return p11->decryptRSA(dst, data, oaep, idx);
        return libcdoc::NOT_IMPLEMENTED;
    }
    int deriveConcatKDF(std::vector<uint8_t>& dst, const std::vector<uint8_t> &publicKey, const std::string &digest,
                        const std::vector<uint8_t> &algorithmID, const std::vector<uint8_t> &partyUInfo, const std::vector<uint8_t> &partyVInfo, unsigned int idx) override final {
        if (p11) return p11->deriveConcatKDF(dst, publicKey, digest, algorithmID, partyUInfo, partyVInfo, idx);
        return libcdoc::NOT_IMPLEMENTED;
    }
    int deriveHMACExtract(std::vector<uint8_t>& dst, const std::vector<uint8_t> &publicKey, const std::vector<uint8_t> &salt, unsigned int idx) override final {
        if (p11) return p11->deriveHMACExtract(dst, publicKey, salt, idx);
        return libcdoc::NOT_IMPLEMENTED;
    }
    int extractHKDF(std::vector<uint8_t>& kek, const std::vector<uint8_t>& salt, const std::vector<uint8_t>& pw_salt, int32_t kdf_iter, unsigned int idx) override {
        if (p11) return p11->extractHKDF(kek, salt, pw_salt, kdf_iter, idx);
        return libcdoc::CryptoBackend::extractHKDF(kek, salt, pw_salt, kdf_iter, idx);
    }
    int getSecret(std::vector<uint8_t>& secret, unsigned int idx) override final {
        const RcptInfo& rcpt = rcpts.at(idx);
        secret =rcpt.secret;
        return secret.empty() ? INVALID_PARAMS : libcdoc::OK;
    }

    int sign(std::vector<uint8_t>& dst, HashAlgorithm algorithm, const std::vector<uint8_t> &digest, int idx) {
        if (p11) return p11->sign(dst, algorithm, digest, idx);
        return libcdoc::NOT_IMPLEMENTED;
    }
};

struct ToolNetwork : public libcdoc::NetworkBackend {
    ToolCrypto *crypto;

    int rcpt_idx = -1;

    std::vector<std::vector<uint8_t>> certs;

    explicit ToolNetwork(ToolCrypto *_crypto) : crypto(_crypto) {
    }

    int getClientTLSCertificate(std::vector<uint8_t>& dst) override final {
        if ((rcpt_idx < 0) || (rcpt_idx >= crypto->rcpts.size())) return libcdoc::CRYPTO_ERROR;
        const RcptInfo& rcpt = crypto->rcpts.at(rcpt_idx);
        bool rsa = false;
        return crypto->p11->getCertificate(dst, rsa, rcpt.slot, rcpt.secret, rcpt.key_id, rcpt.key_label);
    }

    int getPeerTLSCertificates(std::vector<std::vector<uint8_t>> &dst) override final {
        dst = certs;
        return libcdoc::OK;
    }

    int signTLS(std::vector<uint8_t>& dst, libcdoc::CryptoBackend::HashAlgorithm algorithm, const std::vector<uint8_t> &digest) override final {
        if ((rcpt_idx < 0) || (rcpt_idx >= crypto->rcpts.size())) return libcdoc::CRYPTO_ERROR;
        return crypto->p11->sign(dst, algorithm, digest, rcpt_idx);
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
            LOG_ERROR("File does not exist: {}", file);
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
                LOG_ERROR("IO error: {}", file);
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
    RecipientInfoVector rcptsInfo;
    ToolCrypto crypto(rcptsInfo);
    ToolNetwork network(&crypto);
    network.certs = certs;

    if (!conf.library.empty()) {
        crypto.connectLibrary(conf.library);
    }
    for (const auto& rcpt : recipients) {
        if (rcpt.type == RcptInfo::NCRYPT) {
            crypto.connectNCrypt();
        }
    }

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
                    LOG_ERROR("Certificate reading from SC card failed. Key label: {}", rcpt.key_label);
                    return 1;
                }
                Certificate cert(cert_bytes);
                label = std::move(Recipient::BuildLabelEID(CDoc2::KEYLABELVERSION, Recipient::getEIDType(cert.policies()), cert.getCommonName(), cert.getSerialNumber(), cert.getSurname(), cert.getGivenName()));
                break;
            }

            case RcptInfo::Type::CERT:
            {
                Certificate cert(rcpt.cert);
                vector<uint8_t> digest = cert.getDigest();
                label = std::move(Recipient::BuildLabelCertificate(CDoc2::KEYLABELVERSION, rcpt.key_file_name, cert.getCommonName(), digest));
                break;
            }
            case RcptInfo::Type::P11_SYMMETRIC:
                // TODO: what label should be generated in this case?
                break;

            default:
                LOG_ERROR("Unhandled recipient type {} for generating the lock's label", static_cast<int>(rcpt.type));
                break;
            }
#ifndef NDEBUG
            LOG_DBG("Generated label: {}", label);
#endif
        }
        else
        {
            label = rcpt.label;
        }

        if (label.empty()) {
            LOG_ERROR("No lock label");
            return 1;
        }

        rcptsInfo.push_back(rcpt);

        Recipient key;
        if (rcpt.type == RcptInfo::Type::CERT) {
            key = libcdoc::Recipient::makeCertificate(label, rcpt.cert);
        } else if (rcpt.type == RcptInfo::Type::SKEY) {
            key = libcdoc::Recipient::makeSymmetric(label, 0);
            LOG_DBG("Creating symmetric key:");
        } else if (rcpt.type == RcptInfo::Type::PKEY) {
            if (!conf.servers.empty()) {
                key = libcdoc::Recipient::makeServer(label, rcpt.secret, libcdoc::Recipient::PKType::ECC, conf.servers[0].ID);
            } else {
                key = libcdoc::Recipient::makePublicKey(label, rcpt.secret, libcdoc::Recipient::PKType::ECC);
            }
            LOG_DBG("Creating public key:");
        } else if (rcpt.type == RcptInfo::Type::P11_SYMMETRIC) {
            key = libcdoc::Recipient::makeSymmetric(label, 0);
        } else if (rcpt.type == RcptInfo::Type::P11_PKI) {
            std::vector<uint8_t> val;
            bool rsa;
            ToolPKCS11* p11 = dynamic_cast<ToolPKCS11*>(crypto.p11.get());
            int result = p11->getPublicKey(val, rsa, rcpt.slot, rcpt.secret, rcpt.key_id, rcpt.key_label);
            if (result != libcdoc::OK) {
                LOG_ERROR("No such public key: {}", rcpt.key_label);
                continue;
            }
            LOG_DBG("Public key ({}): {}", rsa ? "rsa" : "ecc", toHex(val));
            if (!conf.servers.empty()) {
                key = libcdoc::Recipient::makeServer(label, val, rsa ? libcdoc::Recipient::PKType::RSA : libcdoc::Recipient::PKType::ECC, conf.servers[0].ID);
            } else {
                key = libcdoc::Recipient::makePublicKey(label, val, rsa ? libcdoc::Recipient::PKType::RSA : libcdoc::Recipient::PKType::ECC);
            }
        } else if (rcpt.type == RcptInfo::Type::PASSWORD) {
            LOG_DBG("Creating password key:");
            key = libcdoc::Recipient::makeSymmetric(label, 65535);
        }

        rcpts.push_back(std::move(key));
    }

    if (rcpts.empty()) {
        LOG_ERROR("No key for encryption was found");
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
        LOG_ERROR("Encryption failed: error {}", result);
        cerr << writer->getLastErrorStr() << endl;
    } else {
        LOG_INFO("File encrypted successfully: {}", conf.out);
    }

    return result;
}

int CDocChipher::Decrypt(ToolConf& conf, int idx_base_1, const RcptInfo& recipient, const vector<vector<uint8_t>>& certs)
{
    RecipientInfoVector rcpts;
    ToolCrypto crypto(rcpts);
    ToolNetwork network(&crypto);
    network.certs = certs;

    unique_ptr<CDocReader> rdr(CDocReader::createReader(conf.input_files[0], &conf, &crypto, &network));
    if (rdr) {
        LOG_DBG("Reader created");
    } else {
        LOG_ERROR("Cannot create reader (invalid file?)");
        return 1;
    }

    // Acquire the locks and get the labels according to the index
    const vector<Lock> locks(rdr->getLocks());
    int lock_idx = idx_base_1 - 1;
    if (lock_idx < 0) {
        LOG_ERROR("Indexing of labels starts from 1");
        return 1;
    }
    if (lock_idx >= locks.size()) {
        LOG_ERROR("Label index is out of range");
        return 1;
    }
    rcpts.resize(locks.size());
    rcpts[lock_idx] = recipient;

    const Lock& lock = locks[lock_idx];
    LOG_INFO("Found matching label: {}", lock.label);
    network.rcpt_idx = lock_idx;
    rcpts.resize(locks.size());
    //rcpts[idx_base_1] = recipient;

    if (!conf.library.empty())
        crypto.connectLibrary(conf.library);

    return Decrypt(rdr, lock_idx, conf.out);
}

int CDocChipher::Decrypt(ToolConf& conf, const std::string& label, const RcptInfo& recipient, const vector<vector<uint8_t>>& certs)
{
    RecipientInfoVector rcpts;
    ToolCrypto crypto(rcpts);
    ToolNetwork network(&crypto);
    network.certs = certs;

    if (!conf.library.empty())
        crypto.connectLibrary(conf.library);

    unique_ptr<CDocReader> rdr(CDocReader::createReader(conf.input_files[0], &conf, &crypto, &network));
    if (!rdr) {
        LOG_ERROR("Cannot create reader (invalid file?)");
        return 1;
    }
    LOG_DBG("Reader created");

    // Acquire the locks and get the labels according to the index
    int lock_idx = -1;
    const vector<Lock> locks(rdr->getLocks());
    for (unsigned int i = 0; i < locks.size(); i++) {
        if (locks[i].label == label) {
            lock_idx = i;
            break;
        }
    }
    if (lock_idx < 0) {
        LOG_ERROR("Lock not found: {}", label);
        return 1;
    }
    LOG_INFO("Found matching label: {}", label);
    rcpts.resize(locks.size());
    rcpts[lock_idx] = recipient;

    network.rcpt_idx = lock_idx;
    return Decrypt(rdr, lock_idx, conf.out);
}

int CDocChipher::Decrypt(const unique_ptr<CDocReader>& rdr, unsigned int lock_idx, const string& base_path)
{
    vector<uint8_t> fmk;
    LOG_DBG("Fetching FMK, idx=", lock_idx);
    int result = rdr->getFMK(fmk, lock_idx);
    LOG_DBG("Got FMK");
    if (result != libcdoc::OK) {
        LOG_ERROR("Error on extracting FMK: {} {}", result, rdr->getLastErrorStr());
        return 1;
    }
    FileListConsumer fileWriter(base_path);
    result = rdr->decrypt(fmk, &fileWriter);
    if (result != libcdoc::OK) {
        LOG_ERROR("Error on decrypting files: {} {}", result, rdr->getLastErrorStr());
        return 1;
    }
    LOG_INFO("File decrypted successfully");
    return 0;
}

void CDocChipher::Locks(const char* file) const
{
    unique_ptr<CDocReader> rdr(CDocReader::createReader(file, nullptr, nullptr, nullptr));
    const vector<Lock> locks(rdr->getLocks());

    int lock_id = 1;
    for (const Lock& lock : locks) {
        map<string, string> parsed_label(Recipient::parseLabel(lock.label));
        if (parsed_label.empty()) {
            // Human-readable label
            cout << lock_id << ": " << lock.label << endl;
        } else {
            // Machine generated label
            // Find the longest field
            int maxFieldLength = 0;
            for (map<string, string>::const_reference pair : parsed_label) {
                if (pair.first.size() > maxFieldLength) {
                    maxFieldLength = static_cast<int>(pair.first.size());
                }
            }

            // Output the fields with their values
            cout << lock_id << ":" << endl;
            for (map<string, string>::const_reference pair : parsed_label) {
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
    uint8_t rndByte;
    ostringstream sequence;
    for (int cnt = 0; cnt < MaxSequenceLength;)
    {
        if (SSL_FAILED(RAND_bytes(&rndByte, 1), "RAND_bytes"))
        {
            rnd = rand() % upperbound + '0';
        }
        else
        {
            rnd = rndByte % upperbound + '0';
        }

        // arc4random_uniform tends to be not available on all platforms.
        // rnd = arc4random_uniform(upperbound) + '0';

        if (isalnum(rnd))
        {
            sequence << static_cast<char>(rnd);
            cnt++;
        }
    }

    return sequence.str();
}
