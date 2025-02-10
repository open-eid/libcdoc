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
#include <filesystem>
#include <fstream>
#include <map>
#include <CDocChipher.h>
#include <Recipient.h>
#include <Utils.h>

#ifndef DATA_DIR
#define DATA_DIR "."
#endif

namespace btools = boost::test_tools;
namespace utf = boost::unit_test;
namespace fs = std::filesystem;

using namespace std;

/**
 * @brief Unencrypted file name.
 */
const string SourceFile("test_data.txt");

/**
 * @brief Encrypted file name.
 */
const string TargetFile("test_data.txt.cdoc");

const string Label("Proov");

const string Password("Proov123");

const string_view AESKey = "E165475C6D8B9DD0B696EE2A37D7176DFDF4D7B510406648E70BAE8E80493E5E"sv;

const string_view CDOC2HEADER = "CDOC\x02"sv;

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
        // Get path to test data, provided via argument to the unit tests application
        if (utf::framework::master_test_suite().argc <= 1)
        {
            testDataPath = DATA_DIR;
        }
        else
        {
            testDataPath = utf::framework::master_test_suite().argv[1];
        }
    }

    /**
     * @brief Concatenates test-data path with given file name and assigns it to given target.
     * @param fileName File's name to be appended to test data path.
     * @param target Target where the result is assigned.
     */
    void FormFilePath(const string& fileName, fs::path& target)
    {
        target = testDataPath;
        target /= fileName;
    }

    /**
     * @brief Checks if the file exists in the test data path.
     *
     * The method prepends the fileName with the test data path and checks its existence. If the file does not
     * exist then appropriate message is appended to returned predicate_result object and the value of the object
     * is set to false.
     * @param fileName the name of the file thats existence has to be checked.
     * @return predicate_result object with the check result.
     */
    boost::test_tools::predicate_result DoesFileExist(const string& fileName)
    {
        fs::path file(testDataPath);
        file /= fileName;
        if (fs::exists(file))
        {
            return true;
        }
        else
        {
            btools::predicate_result res(false);
            res.message() << "File " << file << " does not exist";
            return res;
        }
    }

    fs::path testDataPath;
    fs::path sourceFilePath;
    fs::path targetFilePath;
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

        // Setup target, encrypted file path
        FormFilePath(TargetFile, targetFilePath);

        // Remove target file if it exists
        if (fs::exists(targetFilePath))
        {
            fs::remove(targetFilePath);
        }
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
        ifstream encryptedFile(encryptedFilePath, ios_base::in | ios_base::binary);
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

        // Setup target, unencrypted file path
        FormFilePath(SourceFile, targetFilePath);
    }

    ~DecryptFixture()
    {
        BOOST_TEST_MESSAGE("Decrypt fixture deardown");
    }
};


BOOST_AUTO_TEST_SUITE(PasswordUsageWithLabel)

BOOST_FIXTURE_TEST_CASE_WITH_DECOR(EncryptWithPasswordAndLabel, EncryptFixture, * utf::description("Encrypting a file with password and given label"))
{
    // Check if the source, unecrypted file exists
    BOOST_TEST_REQUIRE(fs::exists(sourceFilePath), "File " << sourceFilePath << " exists");

    libcdoc::ToolConf conf;
    conf.input_files.push_back(sourceFilePath.string());
    conf.out = targetFilePath.string();

    libcdoc::RcptInfo rcpt;
    rcpt.type = libcdoc::RcptInfo::PASSWORD;
    rcpt.secret.assign(Password.cbegin(), Password.cend());
    rcpt.label = Label;

    libcdoc::RecipientInfoVector rcpts {rcpt};

    libcdoc::CDocChipher chipher;
    BOOST_CHECK_EQUAL(chipher.Encrypt(conf, rcpts, {}), 0);

    // Validate the encrypted file
    BOOST_TEST(ValidateEncryptedFile(targetFilePath));
}

BOOST_FIXTURE_TEST_CASE_WITH_DECOR(DecryptWithPasswordAndLabel, DecryptFixture,
        * utf::depends_on("PasswordUsageWithLabel/EncryptWithPasswordAndLabel")
        * utf::description("Decrypting a file with password and given label"))
{
    // Check if the source, encrypted file exists
    BOOST_TEST_REQUIRE(fs::exists(sourceFilePath), "File " << sourceFilePath << " must exists");

    libcdoc::ToolConf conf;
    conf.input_files.push_back(sourceFilePath.string());
    conf.out = testDataPath.string();

    libcdoc::RcptInfo rcpt {libcdoc::RcptInfo::ANY, {}, vector<uint8_t>(Password.cbegin(), Password.cend())};

    libcdoc::CDocChipher chipher;
    BOOST_CHECK_EQUAL(chipher.Decrypt(conf, Label, rcpt, {}), 0);

    // Check if the encrypted file exists
    BOOST_TEST(fs::exists(targetFilePath), "File " << targetFilePath << " exists");
}

BOOST_AUTO_TEST_SUITE_END()


BOOST_AUTO_TEST_SUITE(PasswordUsageWithoutLabel)

BOOST_FIXTURE_TEST_CASE_WITH_DECOR(EncryptWithPasswordWithoutLabel, EncryptFixture, * utf::description("Encrypting a file with password and without label"))
{
    // Check if the source, unecrypted file exists
    BOOST_TEST_REQUIRE(fs::exists(sourceFilePath), "File " << sourceFilePath << " must exists");

    libcdoc::ToolConf conf;
    conf.gen_label = true;
    conf.input_files.push_back(sourceFilePath.string());
    conf.out = targetFilePath.string();

    libcdoc::RcptInfo rcpt;
    rcpt.type = libcdoc::RcptInfo::PASSWORD;
    rcpt.secret.assign(Password.cbegin(), Password.cend());

    libcdoc::RecipientInfoVector rcpts {rcpt};

    libcdoc::CDocChipher chipher;
    BOOST_CHECK_EQUAL(chipher.Encrypt(conf, rcpts, {}), 0);

    // Validate the encrypted file
    BOOST_TEST(ValidateEncryptedFile(targetFilePath));
}

BOOST_FIXTURE_TEST_CASE_WITH_DECOR(DecryptWithPasswordLabelIndex, DecryptFixture,
                                   * utf::depends_on("PasswordUsageWithoutLabel/EncryptWithPasswordWithoutLabel")
                                   * utf::description("Decrypting a file with password and label index"))
{
    // Check if the source, encrypted file exists
    BOOST_TEST_REQUIRE(fs::exists(sourceFilePath), "File " << sourceFilePath << " must exists");

    libcdoc::ToolConf conf;
    conf.input_files.push_back(sourceFilePath.string());
    conf.out = testDataPath.string();

    libcdoc::RcptInfo rcpt {libcdoc::RcptInfo::ANY, {}, vector<uint8_t>(Password.cbegin(), Password.cend())};

    libcdoc::CDocChipher chipher;
    BOOST_CHECK_EQUAL(chipher.Decrypt(conf, 1, rcpt, {}), 0);

    // Check if the encrypted file exists
    BOOST_TEST(fs::exists(targetFilePath), "File " << targetFilePath << " exists");
}

BOOST_AUTO_TEST_SUITE_END()


BOOST_AUTO_TEST_SUITE(AESKeyUsage)

BOOST_FIXTURE_TEST_CASE_WITH_DECOR(EncryptWithAESKey, EncryptFixture, * utf::description("Encrypting a file with symmetric AES key"))
{
    // Check if the source, unecrypted file exists
    BOOST_TEST_REQUIRE(fs::exists(sourceFilePath), "File " << sourceFilePath << " must exists");

    libcdoc::ToolConf conf;
    conf.input_files.push_back(sourceFilePath.string());
    conf.out = targetFilePath.string();

    libcdoc::RcptInfo rcpt;
    rcpt.type = libcdoc::RcptInfo::SKEY;
    rcpt.secret = std::move(libcdoc::fromHex(AESKey));
    rcpt.label = Label;

    libcdoc::RecipientInfoVector rcpts {rcpt};

    libcdoc::CDocChipher chipher;
    BOOST_CHECK_EQUAL(chipher.Encrypt(conf, rcpts, {}), 0);

    // Validate the encrypted file
    BOOST_TEST(ValidateEncryptedFile(targetFilePath));
}

BOOST_FIXTURE_TEST_CASE_WITH_DECOR(DecryptWithAESKey, DecryptFixture,
                     * utf::depends_on("AESKeyUsage/EncryptWithAESKey")
                     * utf::description("Decrypting a file with with symmetric AES key"))
{
    // Check if the source, encrypted file exists
    BOOST_TEST_REQUIRE(fs::exists(sourceFilePath), "File " << sourceFilePath << " must exists");

    libcdoc::ToolConf conf;
    conf.input_files.push_back(sourceFilePath.string());
    conf.out = testDataPath.string();

    libcdoc::RcptInfo rcpt {libcdoc::RcptInfo::ANY, {}, libcdoc::fromHex(AESKey)};

    libcdoc::CDocChipher chipher;
    BOOST_CHECK_EQUAL(chipher.Decrypt(conf, Label, rcpt, {}), 0);

    // Check if the encrypted file exists
    BOOST_TEST(fs::exists(targetFilePath), "File " << targetFilePath << " exists");
}

BOOST_AUTO_TEST_SUITE_END()


BOOST_AUTO_TEST_SUITE(MacineLabelParsing)

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
