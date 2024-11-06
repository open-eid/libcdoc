#define __CDOC_TOOL_CPP__

#include <cstring>
#include <iostream>
#include <sstream>
#include <map>

#include "CDocReader.h"
#include "CDocWriter.h"
#include "CDoc.h"
#include "PKCS11Backend.h"
#include "Utils.h"


struct RcptInfo {
	enum Type {
		CERT, PASSWORD, KEY, P11
	};
	Type type;
	std::vector<uint8_t> cert;
	std::vector<uint8_t> secret;
	int slot = 0;
	std::string pin;
	int key_index = -1;
	std::string key_id;
	std::string key_label;
};

static void
print_usage(std::ostream& ofs, int exit_value)
{
	ofs
		//<< "cdoc-tool encrypt -r X509DerRecipientCert [-r X509DerRecipientCert [...]] InFile [InFile [...]] OutFile" << std::endl
		<< "cdoc-tool encrypt --rcpt RECIPIENT [--rcpt RECIPIENT] [--file INFILE] [...] --out OUTFILE" << std::endl
		<< "  where RECIPIENT is in form label:TYPE:value" << std::endl
		<< "    where TYPE is 'cert', 'key' or 'pw'" << std::endl
#ifdef _WIN32
		<< "cdoc-tool decrypt win [ui|noui] pin InFile OutFolder" << std::endl
#endif
		<< "cdoc-tool decrypt pkcs11 path/to/so pin InFile OutFolder" << std::endl
		<< "cdoc-tool decrypt pkcs12 path/to/pkcs12 pin InFile OutFolder" << std::endl;
	exit(exit_value);
}

static std::vector<uint8_t>
fromHex(const std::string& hex) {
	std::vector<uint8_t> val(hex.size() / 2);
	char c[3] = {0};
	for (size_t i = 0; i < (hex.size() & 0xfffffffe); i += 2) {
		std::copy(hex.cbegin() + i, hex.cbegin() + i + 2, c);
		val[i / 2] = (uint8_t) strtol(c, NULL, 16);
	}
	return std::move(val);
}

static std::vector<std::string>
split (const std::string &s, char delim = ':') {
	std::vector<std::string> result;
	std::stringstream ss(s);
	std::string item;
	while (getline (ss, item, delim)) {
		result.push_back (item);
	}
	return result;
}

static std::vector<uint8_t>
fromStr(const std::string& str) {
	return std::vector<uint8_t>(str.cbegin(), str.cend());
}

struct ToolConf : public libcdoc::Configuration {
	std::string getValue(const std::string& param) override final {
		return "false";
	}
};

struct ToolPKCS11 : public libcdoc::PKCS11Backend {
	const std::map<std::string, RcptInfo>& rcpts;

	ToolPKCS11(const std::string& library, const std::map<std::string, RcptInfo>& map) : libcdoc::PKCS11Backend(library), rcpts(map) {}

	int connectToKey(const std::string& label) override final {
		const RcptInfo& rcpt = rcpts.at(label);
		int result = useSecretKey(rcpt.slot, rcpt.pin, rcpt.key_index, rcpt.key_id, rcpt.key_label);
		if (result != libcdoc::OK) return result;
		return libcdoc::OK;
	}
};

struct ToolCrypto : public libcdoc::CryptoBackend {
	std::map<std::string, RcptInfo> rcpts;
	std::unique_ptr<ToolPKCS11> p11;

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
};

#define PUSH true

//
// cdoc-tool encrypt --rcpt RECIPIENT [--rcpt...] --out OUTPUTFILE FILE [FILE...]
// Where RECIPIENT has a format:
//   label:cert:CERTIFICATE_HEX
//	 label:key:SECRET_KEY_HEX
//   label:pw:PASSWORD
//	 label:p11:SLOT:[PIN]:[INDEX]:[ID]:[LABEL]
//

int
encrypt(int argc, char *argv[])
{
    std::cout << "Encrypting" << std::endl;

	ToolCrypto crypto;

	std::string library;
	std::vector<std::string> files;
	std::string out;
	for (int i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "--rcpt") && ((i + 1) <= argc)) {
			std::vector<std::string> parts = split(argv[i + 1]);
			if (parts.size() < 3) print_usage(std::cerr, 1);
			const std::string& label = parts[0];
			if (parts[1] == "cert") {
				if (parts.size() != 3) print_usage(std::cerr, 1);
				crypto.rcpts[label] = {
					RcptInfo::CERT,
					libcdoc::readFile(libcdoc::toUTF8(parts[2])),
					{}
				};
			} else if (parts[1] == "key") {
				if (parts.size() != 3) print_usage(std::cerr, 1);
				crypto.rcpts[label] = {
					RcptInfo::KEY,
					{},
					fromHex(parts[2])
				};
			} else if (parts[1] == "pw") {
				if (parts.size() != 3) print_usage(std::cerr, 1);
				crypto.rcpts[label] = {
					RcptInfo::PASSWORD,
					{},
					std::vector<uint8_t>(parts[2].cbegin(), parts[2].cend())
				};
			} else if (parts[1] == "p11") {
				if (parts.size() < 5) print_usage(std::cerr, 1);
				int slot = std::stoi(parts[2]);
				std::string& pin = parts[3];
				int key_idx = (!parts[4].empty()) ? stoi(parts[4]) : -1;
				std::string key_id = (parts.size() >= 6) ? parts[5] : "";
				std::string key_label = (parts.size() >= 7) ? parts[6] : "";
				crypto.rcpts[label] = {
					RcptInfo::PASSWORD,
					{},
					std::vector<uint8_t>(parts[2].cbegin(), parts[2].cend()),
					slot, pin, key_idx, key_id, key_label
				};
			} else {
				std::cerr << "Unkown method: " << parts[1] << std::endl;
				print_usage(std::cerr, 1);
			}
			i += 1;
		} else if (!strcmp(argv[i], "--out") && ((i + 1) <= argc)) {
			out = argv[i + 1];
			i += 1;
		} else if (!strcmp(argv[i], "--library") && ((i + 1) <= argc)) {
			library = argv[i + 1];
			i += 1;
		} else if (argv[i][0] == '-') {
			print_usage(std::cerr, 1);
		} else {
			files.push_back(argv[i]);
		}
	}
	if (crypto.rcpts.empty()) {
		std::cerr << "No recipients" << std::endl;
		print_usage(std::cerr, 1);
	}
	if (files.empty()) {
		std::cerr << "No files specified" << std::endl;
		print_usage(std::cerr, 1);
	}
	if (out.empty()) {
		std::cerr << "No output specified" << std::endl;
		print_usage(std::cerr, 1);
	}
	std::vector<libcdoc::Recipient> keys;
	for (const std::pair<std::string, RcptInfo> pair : crypto.rcpts) {
		const std::string label = pair.first;
		const RcptInfo& rcpt = pair.second;
		libcdoc::Recipient key;
		if (rcpt.type == RcptInfo::Type::CERT) {
			key = libcdoc::Recipient::makeCertificate(label, rcpt.cert);
		} else if (rcpt.type == RcptInfo::Type::KEY) {
			key = libcdoc::Recipient::makeSymmetric(label, 0);
		} else if (rcpt.type == RcptInfo::Type::PASSWORD) {
			key = libcdoc::Recipient::makeSymmetric(label, 65535);
		}
		keys.push_back(key);
	}
    if (!library.empty())
        crypto.connectLibrary(library);

	ToolConf conf;
    auto writer {std::unique_ptr<libcdoc::CDocWriter>(libcdoc::CDocWriter::createWriter(2, &conf, &crypto, nullptr))};

	libcdoc::OStreamConsumer ofs(out);
	if (PUSH) {
		writer->beginEncryption(ofs);
		for (const libcdoc::Recipient& rcpt : keys) {
			writer->addRecipient(rcpt);
		}
		for (const std::string& file : files) {
			std::filesystem::path path(file);
			if (!std::filesystem::exists(path)) {
				std::cerr << "File does not exist: " << file;
				return 1;
			}
			size_t size = std::filesystem::file_size(path);
			writer->addFile(file, size);
			libcdoc::IStreamSource src(file);
			while (!src.isEof()) {
				uint8_t b[256];
				int64_t len = src.read(b, 256);
				if (len < 0) {
					std::cerr << "IO error: " << file;
					return 1;
				}
				writer->writeData(b, len);
			}
		}
		writer->finishEncryption(true);
	} else {
		libcdoc::FileListSource src({}, files);
		writer->encrypt(ofs, src, keys);
	}

	return 0;
}

//
// cdoc-tool decrypt --label LABEL [--secret SECRET] FILE [OUTPUT DIR]
//

int decrypt(int argc, char *argv[])
{
	ToolCrypto crypto;

	std::string label;
	std::vector<uint8_t> secret;
	std::string file;
    std::string basePath;
    for (int i = 0; i < argc; i++)
    {
		if (!strcmp(argv[i], "--label") && ((i + 1) <= argc)) {
			label = argv[i + 1];
			i += 1;
        }
        else if (!strcmp(argv[i], "--password") && ((i + 1) <= argc)) {
			std::string s(argv[i + 1]);
			secret = std::vector<uint8_t>(s.cbegin(), s.cend());
			i += 1;
        }
        else
        {
            if (file.empty())
                file = argv[i];
            else
                basePath = argv[i];
		}
	}

    if (file.empty())
    {
        std::cerr << "No file to decrypt" << std::endl;
        return 1;
    }

    // If output directory was not specified, use current directory
    if (basePath.empty())
        basePath = "./";

	crypto.rcpts[label] = {
		RcptInfo::PASSWORD,
		{},
		secret
	};
	ToolConf conf;
    auto rdr {std::unique_ptr<libcdoc::CDocReader>(libcdoc::CDocReader::createReader(file, &conf, &crypto, nullptr))};
    std::cout << "Reader created" << std::endl;
	std::vector<libcdoc::Lock> locks = rdr->getLocks();
    for (const libcdoc::Lock& lock : locks) {
		if (lock.label == label) {
			std::vector<uint8_t> fmk;
			rdr->getFMK(fmk, lock);
            libcdoc::FileListConsumer fileWriter(basePath);
            rdr->decrypt(fmk, &fileWriter);
            // rdr->beginDecryption(fmk);
            // std::string name;
            // int64_t size;
            // while (rdr->nextFile(name, size) == libcdoc::OK) {
   //              std::cout << name << ":" << size << std::endl;
            // }
            break;
		}
	}
	return 0;
}

//
// cdoc-tool locks FILE
//

int
locks(int argc, char *argv[])
{
	if (argc < 1) print_usage(std::cerr, 1);
	libcdoc::CDocReader *rdr = libcdoc::CDocReader::createReader(argv[0], nullptr, nullptr, nullptr);
	std::vector<libcdoc::Lock> locks = rdr->getLocks();
    for (const libcdoc::Lock& lock : locks) {
        std::cout << lock.label << std::endl;
	}
	return 0;
}

int
main(int argc, char *argv[])
{
    if (argc < 2)
        print_usage(std::cerr, 1);

    std::cout << "Command: " << argv[1] << std::endl;
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
		print_usage(std::cout, 0);
	}
	return 0;
}
