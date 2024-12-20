#define __CDOC_TOOL_CPP__

#include <chrono>
#include <iostream>
#include <iomanip>

#include "CDocChipher.h"

using namespace std;

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


int main(int argc, char *argv[])
{
    std::chrono::time_point<std::chrono::system_clock> epoch;
    auto now = std::chrono::system_clock::now();

    std::cout << std::format("The time of the Unix epoch was {0:%F}T{0:%R%z}.", now)
              << endl;

    const auto c_now = std::chrono::system_clock::to_time_t(now);

    cout << put_time(gmtime(&c_now), "%FT%TZ") << endl;

    if (argc < 2)
    {
        print_usage(cerr);
        return 1;
    }

    string_view command(argv[1]);
    cout << "Command: " << command << endl;

    libcdoc::CDocChipher chipher;
    int retVal = 0;
    if (command == "encrypt") {
        retVal = chipher.Encrypt(argc - 2, argv + 2);
    } else if (command == "decrypt") {
        retVal = chipher.Decrypt(argc - 2, argv + 2);
    } else if (command == "locks") {
        retVal = chipher.Locks(argc - 2, argv + 2);
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
