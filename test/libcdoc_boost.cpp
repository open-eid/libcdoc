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

#define BOOST_TEST_MODULE "C++ Unit Tests for libcdoc"

#include <boost/test/unit_test.hpp>
#include <codecvt>
#include <filesystem>
#include <fstream>
#include <map>
#include <CDocCipher.h>
#include <CryptoBackend.h>
#include <Recipient.h>
#include <Utils.h>
#include <cdoc/Crypto.h>

#include "pipe.h"

#ifndef DATA_DIR
#define DATA_DIR "data"
#endif

namespace btools = boost::test_tools;
namespace utf = boost::unit_test;
namespace fs = std::filesystem;

using namespace std;

/**
 * @brief Unencrypted file name.
 */
constexpr string_view SourceFile("test_data.txt");
constexpr string_view SourceFile2("test_data2.txt");
constexpr string_view SourceFile3("test_data3.txt");

/**
 * @brief Encrypted file name.
 */
constexpr string_view TargetFile("test_data.txt.cdoc");
constexpr string_view ECPrivKeyFile("ec-secp384r1-priv.der");
constexpr string_view ECPubKeyFile("ec-secp384r1-pub.der");
constexpr string_view ECCertFile("ec-secp384r1-cert.der");
constexpr string_view RSAPrivKeyFile("rsa_2048_priv.der");
constexpr string_view RSAPubKeyFile("rsa_2048_pub.der");
constexpr string_view RSACertFile("rsa_2048_cert.der");

const string Label("Proov");

constexpr string_view Password("Proov123");

constexpr string_view AESKey = "E165475C6D8B9DD0B696EE2A37D7176DFDF4D7B510406648E70BAE8E80493E5E"sv;

constexpr string_view CDOC2HEADER = "CDOC\x02"sv;

const map<string, string> ExpectedParsedLabel {
    {"v", "1"},
    {"type", "ID-card"},
    {"serial_number", "PNOEE-38001085718"},
    {"cn", "JÕEORG,JAAK-KRISTJAN,38001085718"}
};

/**
 * @brief The base class for Test Fixtures.
 */
class FixtureBase
{
public:
    FixtureBase()
    {
        int argc = utf::framework::master_test_suite().argc;
        for (int i = 0; i < argc; i++) {
            std::string_view arg = utf::framework::master_test_suite().argv[i];
            if (arg == "--data-path") {
                if (i >= argc) {
                    std::cerr << "Missing data path value" << std::endl;
                    ::exit(1);
                }
                i += 1;
                testDataPath = utf::framework::master_test_suite().argv[i];
            } else if (arg == "--max-filesize") {
                if (i >= argc) {
                    std::cerr << "Missing max filesize value" << std::endl;
                    ::exit(1);
                }
                i += 1;
                max_filesize = std::stoull(utf::framework::master_test_suite().argv[i]);
            }
        }
    }

    /**
     * @brief Concatenates test-data path with given file name and assigns it to given target.
     * @param fileName File's name to be appended to test data path.
     * @param target Target where the result is assigned.
     */
    void FormFilePath(string_view fileName, fs::path& target) const
    {
        target = testDataPath;
        target /= fileName;
    }

    std::string formTargetFile(const std::string_view name) const
    {
        fs::path path(fs::path(tmpDataPath) / name);
        if (fs::exists(path)) {
            error_code e;
            fs::remove(path, e);
            if(e) BOOST_TEST_MESSAGE("Failed to remove file");
        }
        return path.string();
    }

    std::string checkDataFile(const std::string_view name) const
    {
        fs::path path(fs::path(testDataPath) / name);
        BOOST_TEST_REQUIRE(fs::exists(path), "file " << name << " does not exist");
        return path.string();
    }

    std::string checkTargetFile(const std::string_view name) const
    {
        fs::path path(fs::path(tmpDataPath) / name);
        BOOST_TEST_REQUIRE(fs::exists(path), "file " << name << " does not exist");
        return path.string();
    }

    std::vector<uint8_t> fetchDataFile(const std::string_view name) const
    {
        fs::path path(fs::path(testDataPath) / name);
        BOOST_TEST_REQUIRE(fs::exists(path), "file " << name << " does not exist");
        return libcdoc::readAllBytes(path.string());
    }

    fs::path testDataPath = DATA_DIR;
    fs::path tmpDataPath = fs::path(DATA_DIR) / "tmp";
    fs::path sourceFilePath;
    fs::path sourceFilePath2;
    fs::path sourceFilePath3;

    std::vector<std::string> sources = {"test_data.txt", "test_data2.txt", "test_data3.txt"};

    size_t max_filesize = 100000000;
};

/**
 * @brief The Test Fixture class for encrypt operations.
 */
class EncryptFixture : public FixtureBase
{
public:
    EncryptFixture()
    {
        BOOST_TEST_MESSAGE("Encrypt fixture setup");

        // Setup source, unencrypted file path
        FormFilePath(SourceFile, sourceFilePath);
        FormFilePath(SourceFile2, sourceFilePath2);
        FormFilePath(SourceFile3, sourceFilePath3);
    }

    ~EncryptFixture() { BOOST_TEST_MESSAGE("Encrypt fixture deardown"); }

    /**
     * @brief ValidateEncryptedFile Validates encrypted file.
     * @param encryptedFilePath Path to the file to be validated.
     * @return predicate_result object with the validation result.
     */
    btools::predicate_result ValidateEncryptedFile(const fs::path& encryptedFilePath)
    {
        // Check if the encrypted file exists
        btools::predicate_result resTargetFileExists(fs::exists(encryptedFilePath));
        if (!resTargetFileExists)
        {
            resTargetFileExists.message() << "File " << encryptedFilePath << " does not exist";
            return resTargetFileExists;
        }

        // Check if the file size is greater than 0.
        btools::predicate_result resGtZero(fs::file_size(encryptedFilePath) > 0);
        if (!resGtZero)
        {
            resGtZero.message() << "Encrypted file size is 0";
            return resGtZero;
        }

        // Check if the encrypted file starts with "CDOC"
        ifstream encryptedFile(encryptedFilePath, ios_base::binary);
        vector<char> header(CDOC2HEADER.size() + 1);
        encryptedFile.read(header.data(), CDOC2HEADER.size());
        btools::predicate_result resCdocHeaderOk(string_view(header.data()) == CDOC2HEADER);
        if (!resCdocHeaderOk)
        {
            resCdocHeaderOk.message() << "Encrypted file has no CDOC header";
        }

        return resCdocHeaderOk;
    }
};

/**
 * @brief The Test Fixture class for decrypt operations.
 */
class DecryptFixture : public FixtureBase
{
public:
    DecryptFixture()
    {
        BOOST_TEST_MESSAGE("Decrypt fixture setup");

        // Setup source, encrypted file path
        FormFilePath(TargetFile, sourceFilePath);
    }

    ~DecryptFixture()
    {
        BOOST_TEST_MESSAGE("Decrypt fixture deardown");
    }
};

static void
encrypt(unsigned int version, const std::vector<std::string>& files, const std::string& container, std::vector<libcdoc::RcptInfo>& rcpts) {
    libcdoc::ToolConf conf;
    for (auto file : files) {
        conf.input_files.push_back(file);
    }
    conf.out = container;
    conf.cdocVersion = version;

    libcdoc::CDocCipher cipher;
    BOOST_CHECK_EQUAL(cipher.Encrypt(conf, rcpts), 0);

    BOOST_TEST(fs::exists(fs::path(container)), "File " << container << " does not exist");
}

static void
encryptV1(const std::vector<std::string>& files, const std::string& container, const std::vector<uint8_t>& cert) {
    std::vector<libcdoc::RcptInfo> rcpts {
        {libcdoc::RcptInfo::CERT, {}, cert}
    };
    encrypt(1, files, container, rcpts);
}

static void
encryptV2(const std::vector<std::string>& files, const std::string& container, const std::vector<uint8_t>& cert) {
    std::vector<libcdoc::RcptInfo> rcpts {
        {libcdoc::RcptInfo::CERT, {}, cert}
    };
    encrypt(2, files, container, rcpts);
}

static void
decrypt(const std::vector<std::string>& files, const std::string& container, const std::string& dir, libcdoc::RcptInfo& rcpt)
{
    libcdoc::ToolConf conf;
    conf.input_files.push_back(container);
    conf.out = dir;

    libcdoc::CDocCipher cipher;
    BOOST_CHECK_EQUAL(cipher.Decrypt(conf, rcpt), 0);

    fs::path path(dir);
    for (auto file : files) {
        BOOST_TEST(fs::exists(path / fs::path(file).filename()), "File " << file << " does not exist");
    }

    path = fs::path(container);
    if (fs::exists(path)) {
        error_code e;
        fs::remove(path, e);
        if(e)
            BOOST_TEST_MESSAGE("Failed to remove file");    }
}

static void
decrypt(const std::vector<std::string>& files, const std::string& container, const std::string& dir, const std::vector<uint8_t>& key)
{
    libcdoc::RcptInfo rcpt {.type=libcdoc::RcptInfo::LOCK, .secret=key, .lock_idx=0};
    decrypt(files, container, dir, rcpt);
}
static int
unicode_to_utf8 (unsigned int uval, uint8_t *d, uint64_t size)
{
	if ((uval < 0x80) && (size >= 1)) {
		d[0] = (uint8_t) uval;
		return 1;
	} else if ((uval < 0x800) && (size >= 2)) {
		d[0] = 0xc0 | (uval >> 6);
		d[1] = 0x80 | (uval & 0x3f);
		return 2;
	} else if ((uval < 0x10000) && (size >= 3)) {
		d[0] = 0xe0 | (uval >> 12);
		d[1] = 0x80 | ((uval >> 6) & 0x3f);
		d[2] = 0x80 | (uval & 0x3f);
		return 3;
	} else if ((uval < 0x110000) && (size >= 4)) {
		d[0] = 0xf0 | (uval >> 18);
		d[1] = 0x80 | ((uval >> 12) & 0x3f);
		d[2] = 0x80 | ((uval >> 6) & 0x3f);
		d[3] = 0x80 | (uval & 0x3f);
		return 4;
	}
	return 0;
}

static std::string
utf16_to_utf8(const std::u16string& utf16)
{
    std::string utf8;
    for (char16_t c16 : utf16) {
        char c[4];
        utf8.append(c, unicode_to_utf8(c16, (uint8_t *) c, 4));
    }
    return utf8;
}

static std::string
gen_random_filename()
{
    size_t len = std::rand() % 1000 + 1;
    std::u16string u16(len, ' ');
    for (int i = 0; i < len; i++) u16[i] = std::rand() % 10000 + 32;
    return utf16_to_utf8(u16);
}

BOOST_AUTO_TEST_SUITE(LargeFiles)

BOOST_FIXTURE_TEST_CASE_WITH_DECOR(EncryptWithPasswordAndLabel, FixtureBase, * utf::description("Testing weird and large files"))
{
    std::srand(1);

    std::vector<uint8_t> data;
    bool eof = false;
    PipeConsumer pipec(data, eof);
    PipeSource pipes(data, eof);
    PipeCrypto pcrypto("password");

    // Create writer
    libcdoc::CDocWriter *writer = libcdoc::CDocWriter::createWriter(2, &pipec, false, nullptr, &pcrypto, nullptr);
    BOOST_TEST(writer != nullptr);
    libcdoc::Recipient rcpt = libcdoc::Recipient::makeSymmetric("test", 65536);
    BOOST_TEST(writer->addRecipient(rcpt) == libcdoc::OK);
    BOOST_TEST(writer->beginEncryption() == libcdoc::OK);

    // List of files: 0, 0, max_size...0
    std::vector<libcdoc::FileInfo> files;
    files.emplace_back(gen_random_filename(), 0);
    files.emplace_back(gen_random_filename(), 0);
    for (size_t size = max_filesize; size != 0; size = size / 100) {
        files.emplace_back(gen_random_filename(), size);
    }
    files.emplace_back(gen_random_filename(), 0);

    PipeWriter wrt(writer, files);

    // Create reader
    libcdoc::CDocReader *reader = libcdoc::CDocReader::createReader(&pipes, false, nullptr, &pcrypto, nullptr);
    BOOST_TEST(reader != nullptr);

    // Fill buffer
    while((data.size() < 2 * wrt.BUFSIZE) && !wrt.isEof()) {
        BOOST_TEST(wrt.writeMore() == libcdoc::OK);
    }
    std::vector<uint8_t> fmk;
    BOOST_TEST(reader->getFMK(fmk, 0) == libcdoc::OK);
    BOOST_TEST(reader->beginDecryption(fmk) == libcdoc::OK);
    libcdoc::FileInfo fi;
    for (int cfile = 0; cfile < files.size(); cfile++) {
        // Fill buffer
        while((data.size() < 2 * wrt.BUFSIZE) && !wrt.isEof()) {
            BOOST_TEST(wrt.writeMore() == libcdoc::OK);
        }
        // Get file
        BOOST_TEST(reader->nextFile(fi) == libcdoc::OK);
        BOOST_TEST(fi.name == files[cfile].name);
        BOOST_TEST(fi.size == files[cfile].size);
        for (size_t pos = 0; pos < files[cfile].size; pos += wrt.BUFSIZE) {
            // Fill buffer
            while((data.size() < 2 * wrt.BUFSIZE) && !wrt.isEof()) {
                BOOST_TEST(wrt.writeMore() == libcdoc::OK);
            }
            size_t toread = files[cfile].size - pos;
            if (toread > wrt.BUFSIZE) toread = wrt.BUFSIZE;
            uint8_t buf[wrt.BUFSIZE], cbuf[wrt.BUFSIZE];
            BOOST_TEST(reader->readData(buf, toread) == toread);
            for (size_t i = 0; i < toread; i++) cbuf[i] = wrt.getChar(cfile, pos + i);
            BOOST_TEST(std::memcmp(buf, cbuf, toread) == 0);
        }
    }
    BOOST_TEST(reader->nextFile(fi) == libcdoc::END_OF_STREAM);
    BOOST_TEST(reader->finishDecryption() == libcdoc::OK);
}

BOOST_AUTO_TEST_SUITE_END()

// CDoc2 password and label

BOOST_AUTO_TEST_SUITE(PasswordUsageWithLabel)
BOOST_FIXTURE_TEST_CASE_WITH_DECOR(EncryptWithPasswordAndLabel, EncryptFixture, * utf::description("Encrypting a file with password and given label"))
{
    std::vector<libcdoc::RcptInfo> rcpts {
        {libcdoc::RcptInfo::PASSWORD, Label, {}, std::vector<uint8_t>(Password.cbegin(), Password.cend())}
    };
    encrypt(2, {checkDataFile(sources[0])}, formTargetFile("PasswordUsageWithoutLabel.cdoc"), rcpts);
}
BOOST_FIXTURE_TEST_CASE_WITH_DECOR(DecryptWithPasswordAndLabel, DecryptFixture,
        * utf::depends_on("PasswordUsageWithLabel/EncryptWithPasswordAndLabel")
        * utf::description("Decrypting a file with password and given label"))
{
    libcdoc::RcptInfo rcpt {.type=libcdoc::RcptInfo::LOCK, .label=Label, .secret=std::vector<uint8_t>(Password.cbegin(), Password.cend())};
    decrypt({checkDataFile(sources[0])}, checkTargetFile("PasswordUsageWithoutLabel.cdoc"), tmpDataPath, rcpt);
}
BOOST_AUTO_TEST_SUITE_END()

// CDoc2 password and label

BOOST_AUTO_TEST_SUITE(PasswordUsageWithoutLabel)
BOOST_FIXTURE_TEST_CASE_WITH_DECOR(EncryptWithPasswordWithoutLabel, EncryptFixture, * utf::description("Encrypting a file with password and without label"))
{
    std::vector<libcdoc::RcptInfo> rcpts {
        {libcdoc::RcptInfo::PASSWORD, {}, {}, std::vector<uint8_t>(Password.cbegin(), Password.cend())}
    };
    encrypt(2, {checkDataFile(sources[0])}, formTargetFile("PasswordUsageWithoutLabel.cdoc"), rcpts);
}
BOOST_FIXTURE_TEST_CASE_WITH_DECOR(DecryptWithPasswordLabelIndex, DecryptFixture,
                                   * utf::depends_on("PasswordUsageWithoutLabel/EncryptWithPasswordWithoutLabel")
                                   * utf::description("Decrypting a file with password and label index"))
{
    decrypt({checkDataFile(sources[0])}, checkTargetFile("PasswordUsageWithoutLabel.cdoc"), tmpDataPath.string(), std::vector<uint8_t>(Password.cbegin(), Password.cend()));
}
BOOST_AUTO_TEST_SUITE_END()

// CDoc2 AES key

BOOST_AUTO_TEST_SUITE(AESKeyUsage)
BOOST_FIXTURE_TEST_CASE_WITH_DECOR(EncryptWithAESKey, EncryptFixture, * utf::description("Encrypting a file with symmetric AES key"))
{
    std::vector<libcdoc::RcptInfo> rcpts {
        {libcdoc::RcptInfo::SKEY, {}, {}, libcdoc::fromHex(AESKey)}
    };
    encrypt(2, {checkDataFile(sources[0])}, formTargetFile("AESKeyUsage.cdoc"), rcpts);
}
BOOST_FIXTURE_TEST_CASE_WITH_DECOR(DecryptWithAESKey, DecryptFixture,
                     * utf::depends_on("AESKeyUsage/EncryptWithAESKey")
                     * utf::description("Decrypting a file with with symmetric AES key"))
{
    decrypt({checkDataFile(sources[0])}, checkTargetFile("AESKeyUsage.cdoc"), tmpDataPath.string(), libcdoc::fromHex(AESKey));
}
BOOST_AUTO_TEST_SUITE_END()

// CDoc2 EC public/private key

BOOST_AUTO_TEST_SUITE(ECKeyUsage)
BOOST_FIXTURE_TEST_CASE_WITH_DECOR(EncryptWithECKey, EncryptFixture, * utf::description("Encrypting a file with EC key"))
{
    std::vector<libcdoc::RcptInfo> rcpts {
        {libcdoc::RcptInfo::PKEY, {}, {}, fetchDataFile(ECPubKeyFile)}
    };
    encrypt(2, {checkDataFile(sources[0])}, formTargetFile("ECKeyUsage.cdoc"), rcpts);
}
BOOST_FIXTURE_TEST_CASE_WITH_DECOR(DecryptWithECKey, DecryptFixture,
                     * utf::depends_on("ECKeyUsage/EncryptWithECKey")
                     * utf::description("Decrypting a file with with EC private key"))
{
    decrypt({checkDataFile(sources[0])}, checkTargetFile("ECKeyUsage.cdoc"), tmpDataPath.string(), fetchDataFile(ECPrivKeyFile));
}
BOOST_AUTO_TEST_SUITE_END()

// CDoc2 RSA public/private key

BOOST_AUTO_TEST_SUITE(RSAKeyUsage)
BOOST_FIXTURE_TEST_CASE_WITH_DECOR(EncryptWithRSAKey, EncryptFixture, * utf::description("Encrypting a file with RSA key"))
{
    std::vector<libcdoc::RcptInfo> rcpts {
        {libcdoc::RcptInfo::PKEY, {}, {}, fetchDataFile(RSAPubKeyFile)}
    };
    encrypt(2, {checkDataFile(sources[0])}, formTargetFile("RSAKeyUsage.cdoc"), rcpts);
}
BOOST_FIXTURE_TEST_CASE_WITH_DECOR(DecryptWithRSAKey, DecryptFixture,
                     * utf::depends_on("RSAKeyUsage/EncryptWithRSAKey")
                     * utf::description("Decrypting a file with with RSA private key"))
{
    decrypt({checkDataFile(sources[0])}, checkTargetFile("RSAKeyUsage.cdoc"), tmpDataPath.string(), fetchDataFile(RSAPrivKeyFile));
}
BOOST_AUTO_TEST_SUITE_END()

// CDoc1 tests

BOOST_AUTO_TEST_SUITE(CDoc1ECKeySingle)
BOOST_FIXTURE_TEST_CASE_WITH_DECOR(EncryptWithECKeyV1, EncryptFixture, * utf::description("Encrypting a file with EC key in CDoc1 format"))
{
    encryptV1({checkDataFile(sources[0])}, formTargetFile("ECKeyUsageV1.cdoc"), fetchDataFile(ECCertFile));
}
BOOST_FIXTURE_TEST_CASE_WITH_DECOR(DecryptWithECKeyV1, DecryptFixture,
                     * utf::depends_on("CDoc1ECKeySingle/EncryptWithECKeyV1")
                     * utf::description("Decrypting a file in CDoc1 format with with EC private key"))
{
    decrypt({checkDataFile(sources[0])}, checkTargetFile("ECKeyUsageV1.cdoc"), tmpDataPath.string(), fetchDataFile(ECPrivKeyFile));
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(CDoc1ECKeyMulti)
BOOST_FIXTURE_TEST_CASE_WITH_DECOR(EncryptWithECKeyV1Multi, EncryptFixture, * utf::description("Encrypting multiple files with EC key in CDoc1 format"))
{
    encryptV1({checkDataFile(sources[0]), checkDataFile(sources[1]), checkDataFile(sources[2])}, formTargetFile("ECKeyUsageV1Multi.cdoc"), fetchDataFile(ECCertFile));
}
BOOST_FIXTURE_TEST_CASE_WITH_DECOR(DecryptWithECKeyV1Multi, DecryptFixture,
                     * utf::depends_on("CDoc1ECKeyMulti/EncryptWithECKeyV1Multi")
                     * utf::description("Decrypting multiple files in CDoc1 format with with EC private key"))
{
    decrypt({checkDataFile(sources[0]), checkDataFile(sources[1]), checkDataFile(sources[2])}, checkTargetFile("ECKeyUsageV1Multi.cdoc"), tmpDataPath.string(), fetchDataFile(ECPrivKeyFile));
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(CDoc1RSAKeySingle)
BOOST_FIXTURE_TEST_CASE_WITH_DECOR(EncryptWithRSAKeyV1, EncryptFixture, * utf::description("Encrypting a file with RSA key in CDoc1 format"))
{
    encryptV1({checkDataFile(sources[0])}, formTargetFile("RSAKeyUsageV1.cdoc"), fetchDataFile(RSACertFile));
}
BOOST_FIXTURE_TEST_CASE_WITH_DECOR(DecryptWithRSAKeyV1, DecryptFixture,
                     * utf::depends_on("CDoc1RSAKeySingle/EncryptWithRSAKeyV1")
                     * utf::description("Decrypting a file in CDoc1 format with with RSA private key"))
{
    decrypt({checkDataFile(sources[0])}, checkTargetFile("RSAKeyUsageV1.cdoc"), tmpDataPath.string(), fetchDataFile(RSAPrivKeyFile));
}
BOOST_AUTO_TEST_SUITE_END()

// Label parsing

BOOST_AUTO_TEST_SUITE(MachineLabelParsing)
BOOST_AUTO_TEST_CASE(PlainLabelParsing)
{
    const string label("data:v=1&type=ID-card&serial_number=PNOEE-38001085718&cn=J%C3%95EORG%2CJAAK-KRISTJAN%2C38001085718");

    map<string, string> result = libcdoc::Recipient::parseLabel(label);
    for (map<string, string>::const_reference expected_pair : ExpectedParsedLabel)
    {
        map<string, string>::const_iterator result_pair = result.find(expected_pair.first);
        BOOST_TEST((result_pair != result.cend()), "Field " << expected_pair.first << " presented");
        if (result_pair != result.end())
        {
            BOOST_CHECK_EQUAL(result_pair->second, expected_pair.second);
        }
    }
}

BOOST_AUTO_TEST_CASE(Base64LabelParsing)
{
    const string label("data:;base64,dj0xJnR5cGU9SUQtY2FyZCZzZXJpYWxfbnVtYmVyPVBOT0VFLTM4MDAxMDg1NzE4JmNuPUolQzMlOTVFT1JHJTJDSkFBSy1LUklTVEpBTiUyQzM4MDAxMDg1NzE4");

    map<string, string> result = libcdoc::Recipient::parseLabel(label);
    for (map<string, string>::const_reference expected_pair : ExpectedParsedLabel)
    {
        map<string, string>::const_iterator result_pair = result.find(expected_pair.first);
        BOOST_TEST((result_pair != result.cend()), "Field " << expected_pair.first << " presented");
        if (result_pair != result.end())
        {
            BOOST_CHECK_EQUAL(result_pair->second, expected_pair.second);
        }
    }
}

BOOST_AUTO_TEST_CASE(Base64LabelParsingWithMediaType)
{
    const string label("data:application/x-www-form-urlencoded;base64,dj0xJnR5cGU9SUQtY2FyZCZzZXJpYWxfbnVtYmVyPVBOT0VFLTM4MDAxMDg1NzE4JmNuPUolQzMlOTVFT1JHJTJDSkFBSy1LUklTVEpBTiUyQzM4MDAxMDg1NzE4");

    map<string, string> result = libcdoc::Recipient::parseLabel(label);
    for (map<string, string>::const_reference expected_pair : ExpectedParsedLabel)
    {
        map<string, string>::const_iterator result_pair = result.find(expected_pair.first);
        BOOST_TEST((result_pair != result.cend()), "Field " << expected_pair.first << " presented");
        if (result_pair != result.end())
        {
            BOOST_CHECK_EQUAL(result_pair->second, expected_pair.second);
        }
    }
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(StreamingDecryption)
using BufTypes = std::tuple<std::array<uint8_t, 4>, std::array<uint8_t, 16>, std::array<uint8_t, 20>, std::array<uint8_t, 36>>;
BOOST_AUTO_TEST_CASE_TEMPLATE(constructor, Buf, BufTypes)
{
    const std::vector<uint8_t> srouce_text {
        's', 'o', 'm', 'e', ' ', 'p', 'l', 'a', 'i', 'n', 't', 'e', 'x', 't', '.', '\n',
        's', 'o', 'm', 'e', ' ', 'p', 'l', 'a', 'i', 'n', 't', 'e', 'x', 't', '.', '\n',
        's', 'o', 'm', 'e', ' ', 'p', 'l', 'a', 'i', 'n', 't', 'e', 'x', 't', '.', '\n',
    };
    //std::vector<uint8_t> aad = {'A', 'A', 'D'};
    Buf buffer{};
    const auto key = libcdoc::Crypto::generateKey(std::string(libcdoc::Crypto::AES256GCM_MTH));
    const auto method = std::string(libcdoc::Crypto::AES256GCM_MTH);

    for(const auto &plaintext_size : {14, 16, 29, 32, 36})
    {
        auto plaintext = srouce_text;
        plaintext.resize(plaintext_size);
        // Encrypt
        std::vector<uint8_t> encrypted_data;
        libcdoc::VectorConsumer encrypted_dst(encrypted_data);
        libcdoc::EncryptionConsumer encrypt(encrypted_dst, method, key);
        BOOST_CHECK_EQUAL_COLLECTIONS(encrypted_data.begin(), encrypted_data.end(), key.iv.begin(), key.iv.end());
        //BOOST_CHECK_EQUAL(encrypt.writeAAD(aad), libcdoc::OK);
        libcdoc::VectorSource plain_src(plaintext);
        for(libcdoc::result_t read_len = 0; (read_len = plain_src.read(buffer.data(), buffer.size())) > 0; ) {
            BOOST_CHECK_EQUAL(encrypt.write(buffer.data(), read_len), read_len);
        }
        BOOST_CHECK_EQUAL(encrypt.close(), libcdoc::OK);

        // Decrypt
        libcdoc::VectorSource encrypted_src(encrypted_data);
        libcdoc::DecryptionSource decrypt(encrypted_src, method, key.key);
        //BOOST_CHECK_EQUAL(decrypt.readAAD(aad), libcdoc::OK);
        std::vector<uint8_t> decrypted_text;
        for(libcdoc::result_t read_len = 0; (read_len = decrypt.read(buffer.data(), buffer.size())) > 0; ) {
            decrypted_text.insert(decrypted_text.end(), buffer.data(), buffer.data() + read_len);
        }
        BOOST_CHECK_EQUAL(decrypt.isError(), false);
        BOOST_CHECK_EQUAL(decrypt.close(), libcdoc::OK);

        BOOST_CHECK_EQUAL_COLLECTIONS(plaintext.begin(), plaintext.end(), decrypted_text.begin(), decrypted_text.end());
    }
}

BOOST_AUTO_TEST_SUITE_END()
