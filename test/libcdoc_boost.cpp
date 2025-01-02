#define BOOST_TEST_MODULE "C++ Unit Tests for libcdoc"

#include <boost/test/unit_test.hpp>
#include <filesystem>
#include <fstream>
#include <CDocChipher.h>
#include <Utils.h>

namespace btools = boost::test_tools;
namespace utf = boost::unit_test;
namespace fs = std::filesystem;

using namespace std;

/**
 * @brief Gets path to test data, provided via argument to the unit tests application.
 *
 * The path to the test data has to be provided as the first custom command line argument to the application.
 * @return std::filesystem::path object with the path to test data, or "." if no path was provided to the application.
 */
fs::path GetTestDataDir()
{
    fs::path testDataPath;
    if (utf::framework::master_test_suite().argc <= 1)
    {
        testDataPath = ".";
    }
    else
    {
        testDataPath = utf::framework::master_test_suite().argv[1];
    }

    return testDataPath;
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
    fs::path file(std::move(GetTestDataDir()));
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

/**
 * @brief Forms file path from given file name by prepending it with the test data path.
 * @param fileName to be appended to the test data path
 * @return std::filesystem::path object with the path to the file in the test data directory.
 */
fs::path FormFilePath(const string& fileName)
{
    fs::path filePath(std::move(GetTestDataDir()));
    filePath /= fileName;
    return filePath;
}

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
    array<char, 5> header;
    encryptedFile.read(header.data(), header.size() - 1);
    btools::predicate_result resCdocHeaderOk(string_view(header.data()) == "CDOC");
    if (!resCdocHeaderOk)
    {
        resCdocHeaderOk.message() << "Encrypted file has no CDOC header";
    }

    return resCdocHeaderOk;
}

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

BOOST_AUTO_TEST_SUITE(PasswordUsage)

BOOST_AUTO_TEST_CASE(EncryptWithPassword, * utf::description("Encrypting a file with password"))
{
    // Check if the source, unecrypted file exists
    fs::path sourceFilePath(FormFilePath(SourceFile));
    BOOST_TEST_REQUIRE(fs::exists(sourceFilePath), "File " << sourceFilePath << " exists");

    // Setup target, encrypted file path
    fs::path targetFilePath(FormFilePath(TargetFile));

    // Remove target file if it exists
    if (fs::exists(targetFilePath))
    {
        fs::remove(targetFilePath);
    }

    libcdoc::ToolConf conf;
    conf.input_files.push_back(sourceFilePath.string());
    conf.out = targetFilePath.string();

    libcdoc::Recipients rcpts {{Label, {libcdoc::RcptInfo::PASSWORD, {}, vector<uint8_t>(Password.cbegin(), Password.cend())} }};

    libcdoc::CDocChipher chipher;
    BOOST_CHECK_EQUAL(chipher.Encrypt(conf, rcpts, {}), 0);

    // Validate the encrypted file
    BOOST_TEST(ValidateEncryptedFile(targetFilePath));
}

BOOST_AUTO_TEST_CASE(DecryptWithPassword,
        * utf::depends_on("PasswordUsage/EncryptWithPassword")
        * utf::description("Decrypting a file with password"))
{
    // Check if the source, encrypted file exists
    fs::path sourceFilePath(FormFilePath(TargetFile));
    BOOST_TEST_REQUIRE(fs::exists(sourceFilePath), "File " << sourceFilePath << " exists");

    // Setup target, unencrypted file path
    fs::path targetFilePath(FormFilePath(SourceFile));

    libcdoc::ToolConf conf;
    conf.input_files.push_back(sourceFilePath.string());
    conf.out = GetTestDataDir().string();

    libcdoc::Recipients rcpts {{Label, {libcdoc::RcptInfo::ANY, {}, vector<uint8_t>(Password.cbegin(), Password.cend())} }};

    libcdoc::CDocChipher chipher;
    BOOST_CHECK_EQUAL(chipher.Decrypt(conf, rcpts, {}), 0);

    // Check if the encrypted file exists
    BOOST_TEST(fs::exists(targetFilePath), "File " << targetFilePath << " exists");
}

BOOST_AUTO_TEST_SUITE_END()


BOOST_AUTO_TEST_SUITE(AESKeyUsage)

BOOST_AUTO_TEST_CASE(EncryptWithAESKey, * utf::description("Encrypting a file with symmetric AES key"))
{
    // Check if the source, unecrypted file exists
    fs::path sourceFilePath(FormFilePath(SourceFile));
    BOOST_TEST_REQUIRE(fs::exists(sourceFilePath), "File " << sourceFilePath << " exists");

    // Setup target, encrypted file path
    fs::path targetFilePath(FormFilePath(TargetFile));

    // Remove target file if it exists
    if (fs::exists(targetFilePath))
    {
        fs::remove(targetFilePath);
    }

    libcdoc::ToolConf conf;
    conf.input_files.push_back(sourceFilePath.string());
    conf.out = targetFilePath.string();

    libcdoc::Recipients rcpts {{Label, {libcdoc::RcptInfo::SKEY, {}, libcdoc::fromHex(AESKey)} }};

    libcdoc::CDocChipher chipher;
    BOOST_CHECK_EQUAL(chipher.Encrypt(conf, rcpts, {}), 0);

    // Validate the encrypted file
    BOOST_TEST(ValidateEncryptedFile(targetFilePath));
}

BOOST_AUTO_TEST_CASE(DecryptWithAESKey,
                     * utf::depends_on("AESKeyUsage/EncryptWithAESKey")
                     * utf::description("Decrypting a file with with symmetric AES key"))
{
    // Check if the source, encrypted file exists
    fs::path sourceFilePath(FormFilePath(TargetFile));
    BOOST_TEST_REQUIRE(fs::exists(sourceFilePath), "File " << sourceFilePath << " exists");

    // Setup target, unencrypted file path
    fs::path targetFilePath(FormFilePath(SourceFile));

    libcdoc::ToolConf conf;
    conf.input_files.push_back(sourceFilePath.string());
    conf.out = GetTestDataDir().string();

    libcdoc::Recipients rcpts {{Label, {libcdoc::RcptInfo::ANY, {}, libcdoc::fromHex(AESKey)} }};

    libcdoc::CDocChipher chipher;
    BOOST_CHECK_EQUAL(chipher.Decrypt(conf, rcpts, {}), 0);

    // Check if the encrypted file exists
    BOOST_TEST(fs::exists(targetFilePath), "File " << targetFilePath << " exists");
}

BOOST_AUTO_TEST_SUITE_END()
