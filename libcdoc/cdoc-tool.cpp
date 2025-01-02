#define __CDOC_TOOL_CPP__

#include <chrono>
#include <iostream>
#include <iomanip>

#include "CDocChipher.h"
#include "Utils.h"

using namespace std;
using namespace libcdoc;


static void print_usage(ostream& ofs)
{
    ofs << "cdoc-tool encrypt [--library PKCS11LIBRARY] --rcpt RECIPIENT [--rcpt...] [-v1] --out OUTPUTFILE FILE [FILE...]" << endl;
    ofs << "  Encrypt files for one or more recipients" << endl;
    ofs << "  RECIPIENT has to be one of the following:" << endl;
    ofs << "    label:cert:CERTIFICATE_HEX - public key from certificate" << endl;
    ofs << "    label:skey:SECRET_KEY_HEX - AES key" << endl;
    ofs << "    label:pkey:SECRET_KEY_HEX - public key" << endl;
    ofs << "    label:pfkey:PUB_KEY_FILE - path to DER file with EC (secp384r1 curve) public key" << endl;
    ofs << "    label:pw:PASSWORD - Derive key using PWBKDF" << endl;
    ofs << "    label:p11sk:SLOT:[PIN]:[PKCS11 ID]:[PKCS11 LABEL] - use AES key from PKCS11 module" << endl;
    ofs << "    label:p11pk:SLOT:[PIN]:[PKCS11 ID]:[PKCS11 LABEL] - use public key from PKCS11 module" << endl;
    ofs << "  -v1 - creates CDOC1 version container. Supported only on encryption with certificate." << endl;
    ofs << "  --server ID SEND_URL - specifies a keyserver. The recipient key will be stored in server instead of in the document." << endl;
    ofs << endl;
    ofs << "cdoc-tool decrypt [--library LIBRARY] ARGUMENTS FILE [OUTPU_DIR]" << endl;
    ofs << "  Decrypt container using lock specified by label" << endl;
    ofs << "  Supported arguments" << endl;
    ofs << "    --label LABEL - CDOC container's lock label" << endl;
    ofs << "    --slot SLOT - PKCS11 slot number" << endl;
    ofs << "    --password PASSWORD - lock's password" << endl;
    ofs << "    --secret SECRET - secret phrase (AES key)" << endl;
    ofs << "    --pin PIN - PKCS11 pin" << endl;
    ofs << "    --key-id - PKCS11 key ID" << endl;
    ofs << "    --key-label - PKCS11 key label" << endl;
    ofs << "    --library - path to the PKCS11 library to be used" << endl;
    ofs << "    --server ID FETCH_URL - specifies a keyserver. The recipient key will be loaded from the server." << endl;
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

//
// cdoc-tool encrypt --rcpt RECIPIENT [--rcpt...] --out OUTPUTFILE FILE [FILE...]
// Where RECIPIENT has a format:
//   label:cert:CERTIFICATE_HEX
//	 label:key:SECRET_KEY_HEX
//   label:pw:PASSWORD
//	 label:p11sk:SLOT:[PIN]:[ID]:[LABEL]
//	 label:p11pk:SLOT:[PIN]:[ID]:[LABEL]
//

static int ParseAndEncrypt(int argc, char *argv[])
{
    cout << "Encrypting" << endl;

    ToolConf conf;
    Recipients rcpts;
    vector<vector<uint8_t>> certs;

    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--rcpt") && ((i + 1) <= argc)) {
            vector<string> parts = split(argv[i + 1]);
            if (parts.size() < 3)
                return 1;

            const string& label = parts[0];
            const string& method = parts[1];
            if (method == "cert") {
                if (parts.size() != 3)
                    return 1;

                rcpts[label] = {
                    RcptInfo::CERT,
                    readFile(toUTF8(parts[2])),
                    {}
                };
            }
            else if (method == "key" || method == "skey" || method == "pkey") {
                // For backward compatibility leave also "key" as the synonym for "skey" method.
                if (parts.size() != 3)
                    return 1;

                RcptInfo::Type type = method == "pkey" ? RcptInfo::PKEY : RcptInfo::SKEY;

                rcpts[label] = {
                    type,
                    {},
                    fromHex(parts[2])
                };
            }
            else if (method == "pfkey") {
                if (parts.size() != 3)
                    return 1;

                vector<uint8_t> key = readAllBytes(parts[2]);

                rcpts[label] = {
                    RcptInfo::PKEY,
                    {},
                    key
                };
            }
            else if (method == "pw") {
                if (parts.size() != 3)
                    return 1;

                rcpts[label] = {
                    RcptInfo::PASSWORD,
                    {},
                    vector<uint8_t>(parts[2].cbegin(), parts[2].cend())
                };
            }
            else if (method == "p11sk" || method == "p11pk") {
                RcptInfo::Type type = method == "p11sk" ? RcptInfo::P11_SYMMETRIC : RcptInfo::P11_PKI;

                if (parts.size() < 5)
                    return 1;

                conf.libraryRequired = true;
                long slot;
                if (parts[2].starts_with("0x")) {
                    slot = std::stol(parts[2].substr(2), nullptr, 16);
                } else {
                    slot = std::stol(parts[2]);
                }
                string& pin = parts[3];
                vector<uint8_t> key_id = fromHex(parts[4]);
                string key_label = (parts.size() >= 6) ? parts[5] : "";
                rcpts[label] = {
                    type,
                    {}, vector<uint8_t>(pin.cbegin(), pin.cend()),
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
                return 1;
            }
            i += 1;
        } else if (!strcmp(argv[i], "--out") && ((i + 1) <= argc)) {
            conf.out = argv[i + 1];
            i += 1;
        } else if (!strcmp(argv[i], "--library") && ((i + 1) <= argc)) {
            conf.library = argv[i + 1];
            i += 1;
        } else if (!strcmp(argv[i], "-v1")) {
            conf.cdocVersion = 1;
            i++;
        } else if (!strcmp(argv[i], "--server") && ((i + 2) <= argc)) {
            ToolConf::ServerData sdata;
            sdata.ID = argv[i + 1];
            sdata.SEND_URL = argv[i + 2];
            conf.servers.push_back(sdata);
            conf.use_keyserver = true;
            i += 2;
        } else if (!strcmp(argv[i], "--accept") && ((i + 1) <= argc)) {
            vector<uint8_t> der = readAllBytes(argv[i + 1]);
            certs.push_back(der);
            i += 1;
        } else if (argv[i][0] == '-') {
            return 1;
        } else {
            conf.input_files.push_back(argv[i]);
        }
    }
    if (rcpts.empty()) {
        cerr << "No recipients" << endl;
        return 1;
    }
    if (conf.input_files.empty()) {
        cerr << "No files specified" << endl;
        return 1;
    }
    if (conf.out.empty()) {
        cerr << "No output specified" << endl;
        return 1;
    }

    if (conf.libraryRequired && conf.library.empty()) {
        cerr << "Cryptographic library is required" << endl;
        return 1;
    }

    // CDOC1 is supported only in case of encryption with certificate.
    if (conf.cdocVersion == 1) {
        for (const pair<string, RcptInfo>& rcpt : rcpts) {
            if (rcpt.second.type != RcptInfo::CERT) {
                cerr << "CDOC version 1 container can be used on encryption with certificate only." << endl;
                // print_usage(cerr);
                return 1;
            }
        }
    }

    CDocChipher chipher;
    return chipher.Encrypt(conf, rcpts, certs);
}

//
// cdoc-tool decrypt ARGUMENTS FILE [OUTPU_DIR]
//   --label LABEL   CDoc container lock label
//   --slot SLOT     PKCS11 slot number
//   --secret|password|pin SECRET    Secret phrase (either lock password or PKCS11 pin)
//   --key-id        PKCS11 key id
//   --key-label     PKCS11 key label
//   --library       full path to cryptographic library to be used (needed for decryption with PKCS11)

static int ParseAndDecrypt(int argc, char *argv[])
{
    ToolConf conf;

    string label;
    vector<uint8_t> secret;
    long slot;
    vector<uint8_t> key_id;
    string key_label;
    vector<vector<uint8_t>> certs;

    // Keyserver info
    std::string tls_cert_label;
    std::vector<uint8_t> tls_cert_id;
    std::vector<uint8_t> tls_cert_pin;

    for (int i = 0; i < argc; i++)
    {
        if (!strcmp(argv[i], "--label") && ((i + 1) < argc)) {
            // Make sure the label is provided only once.
            if (!label.empty()) {
                cerr << "The label was already provided" << endl;
                return 1;
            }
            label = argv[i + 1];
            i += 1;
        } else if (!strcmp(argv[i], "--password") || !strcmp(argv[i], "--pin")) {
            if ((i + 1) >= argc) {
                return 1;
            }
            string_view s(argv[i + 1]);
            secret.assign(s.cbegin(), s.cend());
            i += 1;
        } else if (!strcmp(argv[i], "--secret")) {
            if (i + 1 >= argc) {
                return 1;
            }
            secret = fromHex(argv[i + 1]);
            i += 1;
        } else if (!strcmp(argv[i], "--slot")) {
            if ((i + 1) >= argc) {
                return 1;
            }
            conf.libraryRequired = true;
            string str(argv[i + 1]);
            if (str.starts_with("0x")) {
                slot = std::stol(str.substr(2), nullptr, 16);
            } else {
                slot = std::stol(str);
            }
            i += 1;
        } else if (!strcmp(argv[i], "--key-id")) {
            if ((i + 1) >= argc) {
                return 1;
            }
            string_view s(argv[i + 1]);
            key_id.assign(s.cbegin(), s.cend());
            i += 1;
        } else if (!strcmp(argv[i], "--key-label")) {
            if ((i + 1) >= argc) {
                return 1;
            }
            key_label = argv[i + 1];
            i += 1;
        } else if (!strcmp(argv[i], "--library") && ((i + 1) < argc)) {
            conf.library = argv[i + 1];
            i += 1;
        } else if (!strcmp(argv[i], "--server") && ((i + 2) <= argc)) {
            ToolConf::ServerData sdata;
            sdata.ID = argv[i + 1];
            sdata.FETCH_URL = argv[i + 2];
            conf.servers.push_back(sdata);
            conf.use_keyserver = true;
            i += 2;
        } else if (!strcmp(argv[i], "--accept") && ((i + 1) <= argc)) {
            vector<uint8_t> der = readAllBytes(argv[i + 1]);
            certs.push_back(der);
            i += 1;
        } else if (argv[i][0] != '-') {
            if (conf.input_files.empty())
                conf.input_files.push_back(argv[i]);
            else
                conf.out = argv[i];
        } else {
            return 1;
        }
    }

    if (label.empty()) {
        cerr << "No label provided" << endl;
        return 1;
    }

    if (conf.libraryRequired && conf.library.empty()) {
        cerr << "Cryptographic library is required" << endl;
        return 1;
    }

    Recipients rcpts {{label, {RcptInfo::ANY, {}, secret, slot, key_id, key_label} }};

    if (conf.input_files.empty()) {
        cerr << "No file to decrypt" << endl;
        return 1;
    }

    // If output directory was not specified, use current directory
    if (conf.out.empty())
        conf.out = ".";

    CDocChipher chipher;
    return chipher.Decrypt(conf, rcpts, certs);
}

//
// cdoc-tool locks FILE
//

static int ParseAndGetLocks(int argc, char *argv[])
{
    if (argc < 1)
        return 1;

    CDocChipher chipher;
    chipher.Locks(argv[0]);
    return 0;
}

int main(int argc, char *argv[])
{
    chrono::time_point<chrono::system_clock> epoch;
    auto now = chrono::system_clock::now();

    cout << format("The time of the Unix epoch was {0:%F}T{0:%R%z}.", now) << endl;

    const auto c_now = chrono::system_clock::to_time_t(now);

    cout << put_time(gmtime(&c_now), "%FT%TZ") << endl;

    if (argc < 2) {
        print_usage(cerr);
        return 1;
    }

    string_view command(argv[1]);
    cout << "Command: " << command << endl;

    libcdoc::CDocChipher chipher;
    int retVal = 0;
    if (command == "encrypt") {
        retVal = ParseAndEncrypt(argc - 2, argv + 2);
    } else if (command == "decrypt") {
        retVal = ParseAndDecrypt(argc - 2, argv + 2);
    } else if (command == "locks") {
        retVal = ParseAndGetLocks(argc - 2, argv + 2);
    } else if(argc >= 5 && command == "encrypt") {
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
    } else if(argc == 7 && command == "decrypt") {
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

    if (retVal)
        print_usage(cerr);

    return retVal;
}
