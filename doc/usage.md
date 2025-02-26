# Basic libcdoc usage

## Common

Most methods return result_t status value. It can be one of the following:

- positive value - for read and write methods indicates success and the number of bytes read/written
- OK (= 0) - indicates success
- END_OF_STREAM (= -1) - indicates the end of file list in multi-file source
- any error value (< -1) - failure

The END_OF_STREAM can only be returned from nextFile methods. For all other methods any negative value is always
an error.

## Encryption

The encryption is managed by CDocWriter object.

### CryptoBackend

Create or implement a CryptoBackend class. The default implementation is enough for public key encryption schemes, to use
symmetric keys, at least one of the following methods has to be implemented:

    int getSecret(std::vector<uint8_t>& dst, unsigned int idx)

It should return (in dst vector) either the password (for PBKDF based keys) or plain AES key. It is the simplest method, but
potentially exposes password or key in memory.

    int getKeyMaterial(std::vector<uint8_t>& dst, const std::vector<uint8_t>& pw_salt, int32_t kdf_iter, unsigned int idx)

It should return the key material for a symmetric key (either password or plain key) derivation. The default implementation calls getSecret
and performs PBKDF2_SHA256 if key is password-based.

    extractHKDF(std::vector<uint8_t>& dst, const std::vector<uint8_t>& salt, const std::vector<uint8_t>& pw_salt, int32_t kdf_iter, unsigned int idx)

It should calculate KEK (Key Encryption Key) pre-master from a symmetric key (either password or key-based). The default implementation calls
getKeyMaterial and performs local HKDF extract.

### NetworkBackend

If the user intends to use keyserver, a NetworkBackend has to be subclassed with the following method implementations:

    int getClientTLSCertificate(std::vector<uint8_t>& dst)

Return the client TLS for authentication to the keyserver

    int getPeerTLSCertificates(std::vector<std::vector<uint8_t>> &dst)

Return the list of acceptable peer sertificates of the keyserver

    int signTLS(std::vector<uint8_t>& dst, CryptoBackend::HashAlgorithm algorithm, const std::vector<uint8_t> &digest)

Sign method for TLS authentication

In addition to NetworkBackend methods, a Configuration subclass has to be created

### Configuration

It is needed to get keyserver parameters. Subclass has to implement the following method:

    std::string getValue(std::string_view domain, std::string_view param)

It returns configuration value for domain/param combination. For keyserver:

- domain is the keyserver id
- param is KEYSERVER_SEND_URL

### CDocWriter

CDocWriter should be created with one of the static constructors:

    CDocWriter *createWriter(int version, DataConsumer *dst, bool take_ownership, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network)
	CDocWriter *createWriter(int version, std::ostream& ofs, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network)
	CDocWriter *createWriter(int version, const std::string& path, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network)

Version is 1 or 2 (indicates the file format used).

CryptoBackend has to be supplied, NetworkBackend and Configuration may be nullptr if keyserver is not used. CDocWriter does not take ownership of these
objects, so they should be deleted by caller.

Add one or more recipients:

    int addRecipient(const Recipient& rcpt)

Start the encryption workflow:

    int beginEncryption()

Write one or more files:

    int addFile(const std::string& name, size_t size)
    int64_t writeData(const uint8_t *src, size_t size)

Finish encryption:

    int finishEncryption()

### TLDR

    struct MyBackend : public libcdoc::CryptoBackend {
        /* Only needed for symmetric keys */
        int getSecret(std::vector<uint8_t>& dst, unsigned int idx) override final {
            /* Write secret to dst */
        }
    }

    /* In the data processing method */
    MyBackend crypto;

    CDocWriter *writer = createWriter(version, cdoc_filename, nullptr, &crypto, nullptr);
    /* For each recipient */
        writer->addRecipient(myrcpt);
    writer->beginEncryption();
    /* For each file */
        writer->addFile(filename, -1);
        writer->writeData(data, data_size);

    writer->finishEncryption();

    delete writer;

## Decryption

Decryption is managed by CDocReader object

### CryptoBackend

Create or implement a CryptoBackend class. To decrypt all lock types, at least the following methods have to be implemented:

    int deriveECDH1(std::vector<uint8_t>& dst, const std::vector<uint8_t> &public_key, unsigned int idx)

Derives a shared secret from document public key and recipient's private key using ECDH1 algorithm.

    int decryptRSA(std::vector<uint8_t>& dst, const std::vector<uint8_t>& data, bool oaep, unsigned int idx)

Decrypts data using RSA private key.

Also one of the symmetric key methods listed in encryption section for symmetric key support.

### NetworkBackend

It has to be implemented and supplied if server-based capsules are needed.

### Configuration

To decrypt server capsules, configuration has to contain the value of the following entry (domain is keyserver id as in encryption):

- KEYSERVER_FETCH_URL

### CDocReader

Whether or not a file or DataSource is CDoc container can be determined by the following methods:

    int getCDocFileVersion(const std::string& path);
    int getCDocFileVersion(DataSource *src);

Both return either the container version (1 or 2) or a negative number if the file/source is not valid container.

CDocReader has to be created with one of the following static constructors:

    CDocReader *createReader(DataSource *src, bool take_ownership, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network)
    CDocReader *createReader(const std::string& path, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network)
    CDocReader *createReader(std::istream& ifs, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network)

CryptoBackend has to be supplied, NetworkBackend and Configuration may be nullptr if keyserver is not used. CDocReader does not take ownership of these
objects, so they should be deleted by caller.

The list of locks in file can be obtained by method:

    const std::vector<Lock> getLocks()

The order of locks is the same as in CDoc container and the 0-based index is used to refer to the lock in decryption methods.

As a convenience method, a public-key lock can be looked up by a certificate (der-encoded):

    result_t getLockForCert(const std::vector<uint8_t>& cert)

It return the index of a lock that can be opened by the private key of the certificate or negative number if not found.

Once the correct lock is chosen, the FMK (File Master Key) of the container has to be obtained:

    result_t getFMK(std::vector<uint8_t>& fmk, unsigned int lock_idx)

Depending on the lock type this calls relevant methods of CryptoBackend (and NetworkBackend) implementation to obtain and decrypt FMK.

Then the FMK can be used to start the encryption:

    result_t beginDecryption(const std::vector<uint8_t>& fmk)

Individual files can be read by nextFile:

    result_t nextFile(std::string& name, int64_t& size)

It return the name and size of the next file in encrypted stream, or END_OF_STREAM if there are no more files. Due to the structure
of CDoc container, files have to be processed sequentially - there is no way to rewind the stream.
The name returned is the *exact filename* in encrypted stream. If the application intends to save the file with the same name, it has
to verify that the path is safe.

The actual decrypted data can be read with method:

    result_t readData(uint8_t *dst, size_t size)

This reads the data from current file.

When all files are read, the finalizer has to be called:

    result_t finishDecryption()

The decrypted data should *not be used* before successful finalization because it performs the final check of data integrity. If it
fails, the data should be assumed incomplete or corrupted.

### TLDR

    struct MyBackend : public libcdoc::CryptoBackend {
        /* Elliptic curves */
        result_t deriveECDH1(std::vector<uint8_t>& dst, const std::vector<uint8_t> &public_key, unsigned int idx) override final {
            /* Derive shared secret and write to dst */
        }
        /* RSA */
        result_t decryptRSA(std::vector<uint8_t>& dst, const std::vector<uint8_t>& data, bool oaep, unsigned int idx) override final {
            /* Decrypt data and write to dst */
        }
        /* Only needed for symmetric keys */
        int getSecret(std::vector<uint8_t>& dst, unsigned int idx) override final {
            /* Write secret to dst */
        }
    }

    /* In the data processing method */
    MyBackend crypto;

    CDocReader *reader = createReader(cdoc_filename, nullptr, &crypto, nullptr);
    /* Get list of locks */
    auto locks = reader->getLocks();
    /* Choose a lock that you have a key for, then decrypt FMK */
    std::vector<uint8_t> fmk;
    reader->getFMK(fmk, lock_idx);
    /* Start decryption */
    reader->beginDecryption(const std::vector<uint8_t>& fmk);
    std::string name;
    int64_t size;
    while(reader->nextFile(name, size) == libcdoc::OK) {
        /* Allocate data buffer etc... */
        reader->readData(buffer, size);
    }
    /* Finish decryption */
    reader->finishDecryption();

    delete reader;

