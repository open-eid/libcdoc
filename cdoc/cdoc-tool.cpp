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

#include <iostream>

#include "CDocChipher.h"
#include "ConsoleLogger.h"
#include "ILogger.h"
#include "Utils.h"

using namespace std;
using namespace libcdoc;

static void print_usage(ostream& ofs)
{
    ofs << "cdoc-tool version: " << VERSION_STR << endl;
    ofs << "cdoc-tool encrypt [--library PKCS11LIBRARY] --rcpt RECIPIENT [--rcpt...] [-v1] [--genlabel] --out OUTPUTFILE FILE [FILE...]" << endl;
    ofs << "  Encrypt files for one or more recipients" << endl;
    ofs << "  RECIPIENT has to be one of the following:" << endl;
    ofs << "    [label]:cert:CERTIFICATE_HEX - public key from certificate" << endl;
    ofs << "    [label]:skey:SECRET_KEY_HEX - AES key" << endl;
    ofs << "    [label]:pkey:SECRET_KEY_HEX - public key" << endl;
    ofs << "    [label]:pfkey:PUB_KEY_FILE - path to DER file with EC (secp384r1 curve) public key" << endl;
    ofs << "    [label]:pw:PASSWORD - Derive key using PWBKDF" << endl;
    ofs << "    [label]:p11sk:SLOT:[PIN]:[PKCS11 ID]:[PKCS11 LABEL] - use AES key from PKCS11 module" << endl;
    ofs << "    [label]:p11pk:SLOT:[PIN]:[PKCS11 ID]:[PKCS11 LABEL] - use public key from PKCS11 module" << endl;
    ofs << "  -v1 - creates CDOC1 version container. Supported only for encryption with certificate." << endl;
    ofs << "  --server ID SEND_URL - specifies a keyserver. The recipient key will be stored in server instead of in the document." << endl;
    ofs << "  --genlabel - If specified, the lock label is generated." << endl;
    ofs << endl;
    ofs << "cdoc-tool decrypt [--library LIBRARY] ARGUMENTS FILE [OUTPU_DIR]" << endl;
    ofs << "  Decrypt container using lock specified by label" << endl;
    ofs << "  Supported arguments" << endl;
    ofs << "    --label LABEL - CDOC container's lock label" << endl;
    ofs << "    --label_idx INDEX - CDOC container's lock 1-based label index" << endl;
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
    LOG_INFO("Encrypting");

    ToolConf conf;
    RecipientInfoVector rcpts;
    vector<vector<uint8_t>> certs;

    for (int i = 0; i < argc; i++) {
        string_view arg(argv[i]);
        if (arg == "--rcpt" && ((i + 1) <= argc)) {
            vector<string> parts(split(argv[i + 1]));
            if (parts.size() < 3)
                return 2;

            RcptInfo rcpt;
            rcpt.label = parts[0];
            const string& method = parts[1];
            if (method == "cert") {
                if (parts.size() != 3)
                    return 2;

                rcpt.type = RcptInfo::CERT;

                filesystem::path cert_file(toUTF8(parts[2]));
                rcpt.cert = std::move(readFile(cert_file.string()));
                rcpt.key_file_name = cert_file.filename().string();
            }
            else if (method == "pkey") {
                if (parts.size() != 3)
                    return 2;

                rcpt.type = RcptInfo::PKEY;
                rcpt.secret = std::move(fromHex(parts[2]));
            }
            else if (method == "key" || method == "skey") {
                // For backward compatibility leave also "key" as the synonym for "skey" method.
                if (parts.size() != 3)
                    return 2;

                rcpt.type = RcptInfo::SKEY;
                rcpt.secret = std::move(fromHex(parts[2]));
                if (rcpt.secret.size() != 32) {
                    LOG_ERROR("Symmetric key has to be exactly 32 bytes long");
                    return 1;
                }
            }
            else if (method == "pfkey") {
                if (parts.size() != 3)
                    return 2;

                rcpt.type = RcptInfo::PKEY;
                rcpt.secret = std::move(readAllBytes(parts[2]));
                if (rcpt.secret.empty()) {
                    // Occurs when the file does not exit. readAllBytes already output the error message.
                    return 1;
                }

                filesystem::path key_file(parts[2]);
                rcpt.key_file_name = key_file.filename().string();
            }
            else if (method == "pw") {
                if (parts.size() != 3)
                    return 2;

                rcpt.type = RcptInfo::PASSWORD;
                rcpt.secret.assign(parts[2].cbegin(), parts[2].cend());
            }
            else if (method == "p11sk" || method == "p11pk") {
                rcpt.type = method == "p11sk" ? RcptInfo::P11_SYMMETRIC : RcptInfo::P11_PKI;

                conf.libraryRequired = true;

                size_t last_char_idx;
                if (parts[2].starts_with("0x")) {
                    rcpt.slot = std::stol(parts[2].substr(2), &last_char_idx, 16);
                    last_char_idx += 2;
                } else {
                    rcpt.slot = std::stol(parts[2], &last_char_idx);
                }
                if (last_char_idx < parts[2].size()) {
                    LOG_ERROR("Slot is not a number");
                    return 2;
                }

                if (parts.size() > 3) {
                    if (!parts[3].empty())
                        rcpt.secret.assign(parts[3].cbegin(), parts[3].cend());

                    if (parts.size() > 4) {
                        if (!parts[4].empty()) {
                            rcpt.key_id = std::move(fromHex(parts[4]));
                        }

                        if (parts.size() > 5)
                            rcpt.key_label = parts[5];
                    }
                }

#ifndef NDEBUG
                // For debugging
                LOG_DBG("Method: {}", method);
                LOG_DBG("Slot: {}", rcpt.slot);
                if (!rcpt.secret.empty()) {
                    string str(rcpt.secret.cbegin(), rcpt.secret.cend());
                    LOG_DBG("Pin: {}", str);
                }
                if (!rcpt.key_id.empty())
                    LOG_DBG("Key ID: {}", toHex(rcpt.key_id));
                if (!rcpt.key_label.empty())
                    LOG_DBG("Key label: {}", rcpt.key_label);
#endif
            } else if (method == "ncrypt") {
                rcpt.type = RcptInfo::NCRYPT;

                if (parts.size() > 2) {
                    if (!parts[2].empty()) {
                        rcpt.key_label = parts[2];
                    }
                    if (parts.size() > 3) {
                        if (!parts[3].empty()) {
                            rcpt.secret.assign(parts[3].cbegin(), parts[3].cend());
                        }
                    }
                }

#ifndef NDEBUG
                // For debugging
                cout << "Method: " << method << endl;
                cout << "Slot: " << rcpt.slot << endl;
                if (!rcpt.secret.empty())
                    cout << "Pin: " << string(rcpt.secret.cbegin(), rcpt.secret.cend()) << endl;
                if (!rcpt.key_id.empty())
                    cout << "Key ID: " << toHex(rcpt.key_id) << endl;
                if (!rcpt.key_label.empty())
                    cout << "Key label: " << rcpt.key_label << endl;
#endif
            } else {
                LOG_ERROR("Unknown method: {}", method);
                return 2;
            }

            rcpts.push_back(std::move(rcpt));

            i += 1;
        } else if (arg == "--out" && ((i + 1) <= argc)) {
            conf.out = argv[i + 1];
            i += 1;
        } else if (arg == "--library" && ((i + 1) <= argc)) {
            conf.library = argv[i + 1];
            i += 1;
        } else if (arg == "-v1") {
            conf.cdocVersion = 1;
        } else if (arg == "--server" && ((i + 2) <= argc)) {
            ToolConf::ServerData sdata;
            sdata.ID = argv[i + 1];
            sdata.SEND_URL = argv[i + 2];
            conf.servers.push_back(sdata);
            conf.use_keyserver = true;
            i += 2;
        } else if (arg == "--accept" && ((i + 1) <= argc)) {
            certs.push_back(std::move(readAllBytes(argv[i + 1])));
            i += 1;
        } else if (arg == "--genlabel") {
            conf.gen_label = true;
        } else if (arg[0] == '-') {
            LOG_ERROR("Unknown argument: {}", arg);
            return 2;
        } else {
            conf.input_files.push_back(argv[i]);
        }
    }

    // Validate input parameters
    if (rcpts.empty()) {
        LOG_ERROR("No recipients");
        return 2;
    }
    if (!conf.gen_label) {
        // If labels must not be generated then is there any Recipient without provided label?
        auto rcpt_wo_label{ find_if(rcpts.cbegin(), rcpts.cend(), [](RecipientInfoVector::const_reference rcpt) -> bool {return rcpt.label.empty();}) };
        if (rcpt_wo_label != rcpts.cend()) {
            if (rcpts.size() > 1) {
                LOG_ERROR("Not all Recipients have label");
            } else {
                LOG_ERROR("Label not provided");
            }
            return 2;
        }
    }

    if (conf.input_files.empty()) {
        LOG_ERROR("No files specified");
        return 2;
    }
    if (conf.out.empty()) {
        LOG_ERROR("No output specified");
        return 2;
    }

    if (conf.libraryRequired && conf.library.empty()) {
        LOG_ERROR("Cryptographic library is required");
        return 2;
    }

    // CDOC1 is supported only for encryption with certificate.
    if (conf.cdocVersion == 1) {
        auto rcpt_type_non_cert{ find_if(rcpts.cbegin(), rcpts.cend(), [](RecipientInfoVector::const_reference rcpt) -> bool {return rcpt.type != RcptInfo::CERT;}) };
        if (rcpt_type_non_cert != rcpts.cend()) {
            LOG_ERROR("CDOC version 1 container can be used for encryption with certificate only.");
            return 1;
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

    int label_idx = -1;
    string label;
    vector<uint8_t> secret;
    long slot = -1;
    vector<uint8_t> key_id;
    string key_label;
    vector<vector<uint8_t>> certs;

    // Keyserver info
    std::string tls_cert_label;
    std::vector<uint8_t> tls_cert_id;
    std::vector<uint8_t> tls_cert_pin;

    for (int i = 0; i < argc; i++)
    {
        string_view arg(argv[i]);
        if ((arg == "--label" || arg == "--label_idx") && i + 1 < argc) {
            // Make sure the label or label index is provided only once.
            if (!label.empty() || label_idx != -1) {
                LOG_ERROR("The label or label's index was already provided");
                return 2;
            }
            if (arg == "--label_idx") {
                size_t last_char_idx;
                string str(argv[i + 1]);
                label_idx = std::stol(str, &last_char_idx);
                if (last_char_idx < str.size()) {
                    LOG_ERROR("Label index is not a number");
                    return 2;
                }
            } else {
                label = argv[i + 1];
            }
            i += 1;
        } else if (arg == "--password" || arg == "--pin") {
            if ((i + 1) >= argc) {
                return 2;
            }
            string_view s(argv[i + 1]);
            secret.assign(s.cbegin(), s.cend());
            i += 1;
        } else if (arg == "--secret") {
            if (i + 1 >= argc) {
                return 2;
            }
            secret = fromHex(argv[i + 1]);
            i += 1;
        } else if (arg == "--slot") {
            if ((i + 1) >= argc) {
                return 2;
            }
            conf.libraryRequired = true;
            string str(argv[i + 1]);
            size_t last_char_idx;
            if (str.starts_with("0x")) {
                slot = std::stol(str.substr(2), &last_char_idx, 16);
                last_char_idx += 2;
            } else {
                slot = std::stol(str, &last_char_idx);
            }
            if (last_char_idx < str.size()) {
                LOG_ERROR("Slot is not a number");
                return 2;
            }
            i += 1;
        } else if (arg == "--key-id") {
            if ((i + 1) >= argc) {
                return 2;
            }
            string_view s(argv[i + 1]);
            key_id.assign(s.cbegin(), s.cend());
            i += 1;
        } else if (arg == "--key-label") {
            if ((i + 1) >= argc) {
                return 2;
            }
            key_label = argv[i + 1];
            i += 1;
        } else if (arg == "--library" && i + 1 < argc) {
            conf.library = argv[i + 1];
            i += 1;
        } else if (arg == "--server" && i + 2 <= argc) {
            ToolConf::ServerData sdata;
            sdata.ID = argv[i + 1];
            sdata.FETCH_URL = argv[i + 2];
            conf.servers.push_back(sdata);
            conf.use_keyserver = true;
            i += 2;
        } else if (arg == "--accept" && i + 1 <= argc) {
            vector<uint8_t> der = readAllBytes(argv[i + 1]);
            certs.push_back(der);
            i += 1;
        } else if (arg[0] != '-') {
            if (conf.input_files.empty())
                conf.input_files.push_back(argv[i]);
            else
                conf.out = argv[i];
        } else {
            return 2;
        }
    }

    // Validating the input parameters
    if (label.empty() && label_idx == -1) {
        LOG_ERROR("No label nor index was provided");
        return 2;
    }

    if (conf.libraryRequired && conf.library.empty()) {
        LOG_ERROR("Cryptographic library is required");
        return 2;
    }

    if (conf.input_files.empty()) {
        LOG_ERROR("No file to decrypt");
        return 2;
    }

    // If output directory was not specified, use current directory
    if (conf.out.empty())
        conf.out = ".";

    CDocChipher chipher;
    RcptInfo rcpt {RcptInfo::ANY, {}, secret, slot, key_id, key_label};
    if (label_idx != -1) {
        return chipher.Decrypt(conf, label_idx, rcpt, certs);
    } else {
        return chipher.Decrypt(conf, label, rcpt, certs);
    }
}

//
// cdoc-tool locks FILE
//

static int ParseAndGetLocks(int argc, char *argv[])
{
    if (argc < 1)
        return 2;

    CDocChipher chipher;
    chipher.Locks(argv[0]);
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        print_usage(cerr);
        return 1;
    }

    // Add console logger by default
    ConsoleLogger console_logger;
    console_logger.SetMinLogLevel(LogLevelDebug);
    int cookie = add_logger(&console_logger);

    string_view command(argv[1]);
    LOG_INFO("Command: {}", command);

    CDocChipher chipher;
    int retVal = 2;     // Output the help by default.
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
    } else {
        cerr << "Invalid command: " << command << endl;
    }

    if (retVal == 2) {
        // We print usage information only in case the parse-function returned 2. Value 1 indicates other error.
        print_usage(cout);
    }

    remove_logger(cookie);
    return retVal;
}
