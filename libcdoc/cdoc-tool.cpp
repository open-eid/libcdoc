#define __CDOC_TOOL_CPP__

#include <chrono>
#include <cstring>
#include <iostream>
#include <sstream>
#include <map>

#include "CDocReader.h"
#include "CDocWriter.h"
#include "CDoc.h"
#include "PKCS11Backend.h"
#include "Utils.h"
#include "Crypto.h"

using namespace std;

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
    /* Pin or password */
	std::vector<uint8_t> secret;
	long slot = 0;
    //std::string pin;
	std::vector<uint8_t> key_id;
	std::string key_label;
};

//
//
//
//


static void
print_usage(ostream& ofs)
{
    ofs << "cdoc-tool encrypt [--library PKCS11LIBRARY] --rcpt RECIPIENT [--rcpt...] -v1 --out OUTPUTFILE FILE [FILE...]" << endl;
    ofs << "  Encrypt files for one or more recipients" << endl;
    ofs << "  RECIPIENT has to be one of the following:" << endl;
    ofs << "    label:cert:CERTIFICATE_HEX - public key from certificate" << endl;
    ofs << "    label:skey:SECRET_KEY_HEX - AES key" << endl;
    ofs << "    label:pkey:SECRET_KEY_HEX - public key" << endl;
    ofs << "    label:pfkey:PUB_KEY_FILE - path to DER file with EC (secp384r1 curve) public key" << endl;
    ofs << "    label:pw:PASSWORD - Derive key using PWBKDF" << endl;
    ofs << "    label:p11sk:SLOT:[PIN]:[PKCS11 ID]:[PKCS11 LABEL] - use AES key from PKCS11 module" << endl;
    ofs << "    label:p11pk:SLOT:[PIN]:[PKCS11 ID]:[PKCS11 LABEL] - use public key from PKCS11 module" << endl;
    ofs << "  -v1 creates CDOC1 version container. Supported only on encryption with certificate." << endl;
    ofs << "  --server ID SEND_URL Specify a keyserver. The recipient key will be stored in server instead of in the document." << endl;
    ofs << endl;
    ofs << "cdoc-tool decrypt [--library LIBRARY] ARGUMENTS FILE [OUTPU_DIR]" << endl;
    ofs << "  Decrypt container using lock specified by label" << endl;
    ofs << "  Supported arguments" << endl;
    ofs << "    --label LABEL   CDoc container lock label" << endl;
    ofs << "    --slot SLOT     PKCS11 slot number" << endl;
    ofs << "    --secret|password|pin SECRET    Secret phrase (either lock password or PKCS11 pin)" << endl;
    ofs << "    --key-id        PKCS11 key id" << endl;
    ofs << "    --key-label     PKCS11 key label" << endl;
    ofs << "    --library       path to the PKCS11 library to be used" << endl;
    ofs << "    --server ID FETCH_URL Specify a keyserver. The recipient key will be loaded from server." << endl;
    ofs << endl;
    ofs << "cdoc-tool locks FILE" << endl;
    ofs << "  Show locks in a container file" << endl;

    //<< "cdoc-tool encrypt -r X509DerRecipientCert [-r X509DerRecipientCert [...]] InFile [InFile [...]] OutFile" << std::endl
    //	<< "cdoc-tool encrypt --rcpt RECIPIENT [--rcpt RECIPIENT] [--file INFILE] [...] --out OUTFILE" << std::endl
    //	<< "  where RECIPIENT is in form label:TYPE:value" << std::endl
    //	<< "    where TYPE is 'cert', 'key' or 'pw'" << std::endl
#ifdef _WIN32
    //	<< "cdoc-tool decrypt win [ui|noui] pin InFile OutFolder" << endl
#endif
    //	<< "cdoc-tool decrypt pkcs11 path/to/so pin InFile OutFolder" << std::endl
    //	<< "cdoc-tool decrypt pkcs12 path/to/pkcs12 pin InFile OutFolder" << std::endl;
}

static std::vector<uint8_t>
fromStr(const std::string& str) {
	return std::vector<uint8_t>(str.cbegin(), str.cend());
}

//
// libcdoc::Configuration implementation
//

struct ToolConf : public libcdoc::Configuration {
    struct ServerData {
        std::string ID;
        std::string SEND_URL;
        std::string FETCH_URL;
    };

    bool use_keyserver = false;
    std::vector<ServerData> servers;

    std::string getValue(const std::string_view& param) override final {
        if (param == libcdoc::Configuration::USE_KEYSERVER) {
            return use_keyserver ? "true" : "false";
        } else if (param == libcdoc::Configuration::KEYSERVER_ID) {
            if (!servers.empty()) {
                return servers[0].ID;
            }
        }
        return {};
	}

    std::string getValue(const std::string_view& domain, const std::string_view& param) override final {
        for (auto& sdata : servers) {
            if (sdata.ID == domain) {
                if (param == libcdoc::Configuration::KEYSERVER_SEND_URL) {
                    return sdata.SEND_URL;
                } else if (param == libcdoc::Configuration::KEYSERVER_FETCH_URL) {
                    return sdata.FETCH_URL;
                }
            }
        }
        return {};
    }
};

struct ToolPKCS11 : public libcdoc::PKCS11Backend {
	const std::map<std::string, RcptInfo>& rcpts;

	ToolPKCS11(const std::string& library, const std::map<std::string, RcptInfo>& map) : libcdoc::PKCS11Backend(library), rcpts(map) {}

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
	std::map<std::string, RcptInfo> rcpts;
    std::unique_ptr<libcdoc::PKCS11Backend> p11;

	ToolCrypto() = default;

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
	int extractHKDF(std::vector<uint8_t>& kek, const std::vector<uint8_t>& salt, const std::vector<uint8_t> pw_salt, int32_t kdf_iter, const std::string& label) override {
		if (p11) return p11->extractHKDF(kek, salt, pw_salt, kdf_iter, label);
		return libcdoc::CryptoBackend::extractHKDF(kek, salt, pw_salt, kdf_iter, label);
	}
	int getSecret(std::vector<uint8_t>& secret, const std::string& label) override final {
		const RcptInfo& rcpt = rcpts.at(label);
		secret =rcpt.secret;
		return (secret.empty()) ? INVALID_PARAMS : libcdoc::OK;
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

    int getPeerTLSCerticates(std::vector<std::vector<uint8_t>> &dst) override final {
        dst = certs;
        return libcdoc::OK;
    }

    int signTLS(std::vector<uint8_t>& dst, libcdoc::CryptoBackend::HashAlgorithm algorithm, const std::vector<uint8_t> &digest) override final {
        return crypto->p11->sign(dst, algorithm, digest, label);
    }

};

static int
writer_push(libcdoc::CDocWriter& writer, const std::vector<libcdoc::Recipient>& keys, const std::vector<std::string>& files)
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

//
// cdoc-tool encrypt --rcpt RECIPIENT [--rcpt...] --out OUTPUTFILE FILE [FILE...]
// Where RECIPIENT has a format:
//   label:cert:CERTIFICATE_HEX
//	 label:key:SECRET_KEY_HEX
//   label:pw:PASSWORD
//	 label:p11sk:SLOT:[PIN]:[ID]:[LABEL]
//	 label:p11pk:SLOT:[PIN]:[ID]:[LABEL]
//

int encrypt(int argc, char *argv[])
{
    std::cout << "Encrypting" << std::endl;

    ToolConf conf;
    ToolCrypto crypto;
    ToolNetwork network(&crypto);

    bool libraryRequired = false;
	std::string library;
	std::vector<std::string> files;
	std::string out;
    int cdocVersion = 2;
	for (int i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "--rcpt") && ((i + 1) <= argc)) {
            std::vector<std::string> parts = libcdoc::split(argv[i + 1]);
            if (parts.size() < 3)
            {
                print_usage(std::cerr);
                return 1;
            }
            const string& label = parts[0];
            const string& method = parts[1];
            if (method == "cert") {
                if (parts.size() != 3)
                {
                    print_usage(std::cerr);
                    return 1;
                }
				crypto.rcpts[label] = {
					RcptInfo::CERT,
					libcdoc::readFile(libcdoc::toUTF8(parts[2])),
					{}
				};
            }
            else if (method == "key" || method == "skey" || method == "pkey")
            {
                // For backward compatibility leave also "key" as the synonym for "skey" method.
                if (parts.size() != 3)
                {
                    print_usage(cerr);
                    return 1;
                }

                RcptInfo::Type type = method == "pkey" ? RcptInfo::PKEY : RcptInfo::SKEY;

				crypto.rcpts[label] = {
                    type,
					{},
                    libcdoc::fromHex(parts[2])
				};
            }
            else if (method == "pfkey")
            {
                if (parts.size() != 3)
                {
                    print_usage(cerr);
                    return 1;
                }

                vector<uint8_t> key = libcdoc::readAllBytes(parts[2]);

                crypto.rcpts[label] = {
                    RcptInfo::PKEY,
                    {},
                    key
                };
            }
            else if (method == "pw")
            {
                if (parts.size() != 3)
                {
                    print_usage(std::cerr);
                    return 1;
                }
				crypto.rcpts[label] = {
					RcptInfo::PASSWORD,
					{},
					std::vector<uint8_t>(parts[2].cbegin(), parts[2].cend())
				};
            }
            else if (method == "p11sk" || method == "p11pk")
            {
                RcptInfo::Type type = method == "p11sk" ? RcptInfo::P11_SYMMETRIC : RcptInfo::P11_PKI;

                if (parts.size() < 5) {
                    print_usage(std::cerr);
                    return 1;
                }
                libraryRequired = true;
				long slot;
				if (parts[2].starts_with("0x")) {
					slot = std::stol(parts[2].substr(2), nullptr, 16);
				} else {
					slot = std::stol(parts[2]);
				}
				std::string& pin = parts[3];
                std::vector<uint8_t> key_id = libcdoc::fromHex(parts[4]);
				std::string key_label = (parts.size() >= 6) ? parts[5] : "";
				crypto.rcpts[label] = {
                    type,
                    {}, std::vector<uint8_t>(pin.cbegin(), pin.cend()),
                    slot, key_id, key_label
				};
#ifndef NDEBUG
                // For debugging
                cout << "Method: " << method << endl;
                cout << "Slot: " << slot << endl;
                if (!pin.empty())
                    cout << "Pin: " << pin << endl;
                if (!key_id.empty())
                    cout << "Key ID: " << parts[4] << endl;
                if (!key_label.empty())
                    cout << "Key label: " << key_label << endl;
#endif
            } else {
                cerr << "Unkown method: " << method << endl;
                print_usage(cerr);
                return 1;
			}
			i += 1;
		} else if (!strcmp(argv[i], "--out") && ((i + 1) <= argc)) {
			out = argv[i + 1];
			i += 1;
		} else if (!strcmp(argv[i], "--library") && ((i + 1) <= argc)) {
			library = argv[i + 1];
			i += 1;
        } else if (!strcmp(argv[i], "-v1")) {
            cdocVersion = 1;
            i++;
        } else if (!strcmp(argv[i], "--server") && ((i + 2) <= argc)) {
            ToolConf::ServerData sdata;
            sdata.ID = argv[i + 1];
            sdata.SEND_URL = argv[i + 2];
            conf.servers.push_back(sdata);
            conf.use_keyserver = true;
            i += 2;
        } else if (!strcmp(argv[i], "--accept") && ((i + 1) <= argc)) {
            std::vector<uint8_t> der = libcdoc::readAllBytes(argv[i + 1]);
            network.certs.push_back(der);
            i += 1;
        } else if (argv[i][0] == '-') {
            print_usage(std::cerr);
            return 1;
		} else {
			files.push_back(argv[i]);
		}
	}
	if (crypto.rcpts.empty()) {
		std::cerr << "No recipients" << std::endl;
        print_usage(std::cerr);
        return 1;
	}
	if (files.empty()) {
		std::cerr << "No files specified" << std::endl;
        print_usage(std::cerr);
        return 1;
	}
	if (out.empty()) {
		std::cerr << "No output specified" << std::endl;
        print_usage(std::cerr);
        return 1;
	}

    // CDOC1 is supported only in case of encryption with certificate.
    if (cdocVersion == 1)
    {
        for (const pair<string, RcptInfo>& rcpt : crypto.rcpts)
        {
            if (rcpt.second.type != RcptInfo::CERT)
            {
                cerr << "CDOC version 1 container can be used on encryption with certificate only." << endl;
                print_usage(cerr);
                return 1;
            }
        }
    }

    if (!library.empty())
    {
        crypto.connectLibrary(library);
    }
    else if (libraryRequired)
    {
        cerr << "Cryptographic library is required" << endl;
        print_usage(cerr);
        return 1;
    }

	std::vector<libcdoc::Recipient> keys;
    for (const std::pair<std::string, RcptInfo>& pair : crypto.rcpts) {
        const std::string& label = pair.first;
		const RcptInfo& rcpt = pair.second;
		libcdoc::Recipient key;
        if (rcpt.type == RcptInfo::Type::CERT)
        {
			key = libcdoc::Recipient::makeCertificate(label, rcpt.cert);
        }
        else if (rcpt.type == RcptInfo::Type::SKEY) {
			key = libcdoc::Recipient::makeSymmetric(label, 0);
			std::cerr << "Creating symmetric key:" << std::endl;
        }
        else if (rcpt.type == RcptInfo::Type::PKEY)
        {
            key = libcdoc::Recipient::makePublicKey(label, rcpt.secret, libcdoc::Recipient::PKType::ECC);
            std::cerr << "Creating public key:" << std::endl;
        }
        else if (rcpt.type == RcptInfo::Type::P11_SYMMETRIC)
        {
			key = libcdoc::Recipient::makeSymmetric(label, 0);
        }
        else if (rcpt.type == RcptInfo::Type::P11_PKI)
        {
			std::vector<uint8_t> val;
			bool rsa;
            ToolPKCS11* p11 = dynamic_cast<ToolPKCS11*>(crypto.p11.get());
            int result = p11->getPublicKey(val, rsa, rcpt.slot, rcpt.secret, rcpt.key_id, rcpt.key_label);
			if (result != libcdoc::OK) {
				std::cerr << "No such public key: " << rcpt.key_label << std::endl;
				continue;
			}
            std::cerr << "Public key (" << (rsa ? "rsa" : "ecc") << "):" << libcdoc::toHex(val) << std::endl;
			key = libcdoc::Recipient::makePublicKey(label, val, rsa ? libcdoc::Recipient::PKType::RSA : libcdoc::Recipient::PKType::ECC);
        }
        else if (rcpt.type == RcptInfo::Type::PASSWORD)
        {
			std::cerr << "Creating password key:" << std::endl;
			key = libcdoc::Recipient::makeSymmetric(label, 65535);
		}

		keys.push_back(key);
	}

    if (keys.empty())
    {
        cerr << "No key for encryption was found" << endl;
        return 1;
    }

    unique_ptr<libcdoc::CDocWriter> writer(libcdoc::CDocWriter::createWriter(cdocVersion, out, &conf, &crypto, &network));

    int result;
	if (PUSH) {
        result = writer_push(*writer, keys, files);
	} else {
		libcdoc::FileListSource src({}, files);
        result = writer->encrypt(src, keys);
	}
    if (result < 0) {
        cerr << "Encryption failed: error " << result << endl;
        cerr << writer->getLastErrorStr() << endl;
    } else {
        cout << "File encrypted successfully: " << out << endl;
    }
    return result;
}

//
// cdoc-tool decrypt ARGUMENTS FILE [OUTPU_DIR]
//   --label LABEL   CDoc container lock label
//   --slot SLOT     PKCS11 slot number
//   --secret|password|pin SECRET    Secret phrase (either lock password or PKCS11 pin)
//   --key-id        PKCS11 key id
//   --key-label     PKCS11 key label
//   --library       full path to cryptographic library to be used (needed for decryption with PKCS11)

int decrypt(int argc, char *argv[])
{
    ToolConf conf;
    ToolCrypto crypto;
    ToolNetwork network(&crypto);

    std::string library;

	std::string label;
	std::vector<uint8_t> secret;
    long slot;
    std::vector<uint8_t> key_id;
    std::string key_label;
    std::string file;
    std::string basePath;

    // Keyserver info
    std::string tls_cert_label;
    std::vector<uint8_t> tls_cert_id;
    std::vector<uint8_t> tls_cert_pin;

    bool libraryRequired = false;

    for (int i = 0; i < argc; i++)
    {
        if (!strcmp(argv[i], "--label") && ((i + 1) < argc)) {
			label = argv[i + 1];
			i += 1;
        } else if (!strcmp(argv[i], "--password") || !strcmp(argv[i], "--secret") || !strcmp(argv[i], "--pin")) {
            if ((i + 1) >= argc) {
                print_usage(cerr);
                return 1;
            }
            string_view s(argv[i + 1]);
            secret.assign(s.cbegin(), s.cend());
			i += 1;
        } else if (!strcmp(argv[i], "--slot")) {
            if ((i + 1) >= argc) {
                print_usage(cerr);
                return 1;
            }
            libraryRequired = true;
            string str(argv[i + 1]);
            if (str.starts_with("0x")) {
                slot = std::stol(str.substr(2), nullptr, 16);
            } else {
                slot = std::stol(str);
            }
            i += 1;
        } else if (!strcmp(argv[i], "--key-id")) {
            if ((i + 1) >= argc) {
                print_usage(cerr);
                return 1;
            }
            string_view s(argv[i + 1]);
            key_id.assign(s.cbegin(), s.cend());
            i += 1;
        } else if (!strcmp(argv[i], "--key-label")) {
            if ((i + 1) >= argc) {
                print_usage(cerr);
                return 1;
            }
            key_label = argv[i + 1];
            i += 1;
        } else if (!strcmp(argv[i], "--library") && ((i + 1) < argc)) {
            library = argv[i + 1];
            i += 1;
        } else if (!strcmp(argv[i], "--server") && ((i + 2) <= argc)) {
            ToolConf::ServerData sdata;
            sdata.ID = argv[i + 1];
            sdata.FETCH_URL = argv[i + 2];
            conf.servers.push_back(sdata);
            conf.use_keyserver = true;
            i += 2;
        } else if (!strcmp(argv[i], "--accept") && ((i + 1) <= argc)) {
            std::vector<uint8_t> der = libcdoc::readAllBytes(argv[i + 1]);
            network.certs.push_back(der);
            i += 1;
        } else if (argv[i][0] != '-') {
            if (file.empty())
                file = argv[i];
            else
                basePath = argv[i];
        } else {
            print_usage(cerr);
            return 1;
        }
	}

    if (file.empty())
    {
        std::cerr << "No file to decrypt" << std::endl;
        return 1;
    }

    // If output directory was not specified, use current directory
    if (basePath.empty())
    {
        basePath = ".";
        basePath += filesystem::path::preferred_separator;
    }

    if (!library.empty())
    {
        crypto.connectLibrary(library);
    }
    else if (libraryRequired)
    {
        cerr << "Cryptographic library is required" << endl;
        print_usage(cerr);
        return 1;
    }

    network.label = label;

    crypto.rcpts[label] = {
        RcptInfo::ANY,
		{},
        secret,
        slot, key_id, key_label
	};
    unique_ptr<libcdoc::CDocReader> rdr(libcdoc::CDocReader::createReader(file, &conf, &crypto, &network));
    std::cout << "Reader created" << std::endl;
    std::vector<const libcdoc::Lock> locks = rdr->getLocks();
    for (const libcdoc::Lock& lock : locks) {
        if (lock.label == label) {
            cerr << "Found matching label: " << label << endl;
			std::vector<uint8_t> fmk;
            int result = rdr->getFMK(fmk, lock);
            if (result != libcdoc::OK) {
                cerr << "Error extracting FMK: " << result << endl;
                cerr << rdr->getLastErrorStr() << endl;
                return 1;
            }
            libcdoc::FileListConsumer fileWriter(basePath);
            result = rdr->decrypt(fmk, &fileWriter);
            if (result != libcdoc::OK) {
                cerr << "Error decrypting files: " << result << endl;
                cerr << rdr->getLastErrorStr() << endl;
                return 1;
            }
            cout << "File decrypted successfully" << endl;
            return 0;
		}
	}
    cout << "Lock not found: " << label << endl;
    return 1;
}

//
// cdoc-tool locks FILE
//

int locks(int argc, char *argv[])
{
    if (argc < 1)
    {
        print_usage(cerr);
        return 1;
    }
    unique_ptr<libcdoc::CDocReader> rdr(libcdoc::CDocReader::createReader(argv[0], nullptr, nullptr, nullptr));
    const std::vector<const libcdoc::Lock> locks = rdr->getLocks();
    for (const libcdoc::Lock& lock : locks) {
        cout << lock.label << endl;
	}
	return 0;
}

int main(int argc, char *argv[])
{
    std::chrono::time_point<std::chrono::system_clock> epoch;
    auto now = std::chrono::system_clock::now();

    std::cout << std::format("The time of the Unix epoch was {0:%F}T{0:%R%z}.", now)
              << '\n';

    const auto c_now = std::chrono::system_clock::to_time_t(now);

    cout << put_time(gmtime(&c_now), "%FT%TZ") << endl;

    if (argc < 2)
    {
        print_usage(cerr);
        return 1;
    }

    cout << "Command: " << argv[1] << endl;
	if (!strcmp(argv[1], "encrypt")) {
		return encrypt(argc - 2, argv + 2);
	} else if (!strcmp(argv[1], "decrypt")) {
		return decrypt(argc - 2, argv + 2);
	} else if (!strcmp(argv[1], "locks")) {
		return locks(argc - 2, argv + 2);
	} else if(argc >= 5 && strcmp(argv[1], "encrypt") == 0) {
#if 0
		CDOC1Writer w(toUTF8(argv[argc-1]));
		for(int i = 2; i < argc - 1; ++i)
		{
			if (strcmp(argv[i], "-r") == 0)
			{
				w.addRecipient(readFile(toUTF8(argv[i + 1])));
				++i;
			}
			else
			{
				std::string inFile = toUTF8(argv[i]);
				size_t pos = inFile.find_last_of("/\\");
				w.addFile(pos == std::string::npos ? inFile : inFile.substr(pos + 1), "application/octet-stream", inFile);
			}
		}
		if(w.encrypt())
			std::cout << "Success" << std::endl;
		else
			std::cout << w.lastError() << std::endl;
#endif
	} else if(argc == 7 && strcmp(argv[1], "decrypt") == 0) {
#if 0
		std::unique_ptr<Token> token;
		if (strcmp(argv[2], "pkcs11") == 0)
			token.reset(new PKCS11Token(toUTF8(argv[3]), argv[4]));
		else if (strcmp(argv[2], "pkcs12") == 0)
			token.reset(new PKCS12Token(toUTF8(argv[3]), argv[4]));
#ifdef _WIN32
		else if (strcmp(argv[2], "win") == 0)
			token.reset(new WinToken(strcmp(argv[3], "ui") == 0, argv[4]));
#endif
		CDoc1Reader r(toUTF8(argv[5]));
		if(r.mimeType() == "http://www.sk.ee/DigiDoc/v1.3.0/digidoc.xsd")
		{
			for(const DDOCReader::File &file: DDOCReader::files(r.decryptData(token.get())))
				writeFile(toUTF8(argv[6]) + "/" + file.name, file.data);
		}
		else
			writeFile(toUTF8(argv[6]) + "/" + r.fileName(), r.decryptData(token.get()));
#endif
	}
	else
	{
        print_usage(cout);
        return 0;
	}
	return 0;
}
