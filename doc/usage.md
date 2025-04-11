# Basic libcdoc Library Usage

## Common

Most methods return `result_t` status value. It can be one of the following:

- OK (= 0) - indicates success
- positive value - for read and write methods indicates success and the number of bytes read/written
- END_OF_STREAM (= 1) - for `nextFile` methods indicates the end of file list in multi-file source
- any error value (< -1) - failure

## Encryption

The encryption is managed by CDocWriter object.

### CryptoBackend

Create or implement a CryptoBackend class. The default implementation is enough for public key encryption schemes. To use
symmetric keys, at least one of the following methods has to be implemented:

```cpp
int getSecret(std::vector<uint8_t>& dst, unsigned int idx)
```

The method copies into `dst` vector either the password (for PBKDF based keys) or plain AES key. It is the simplest method, but
potentially exposes password or key in memory.

```cpp
int getKeyMaterial(std::vector<uint8_t>& dst, const std::vector<uint8_t>& pw_salt, int32_t kdf_iter, unsigned int idx)
```

The method returns the key material for a symmetric key (either password or plain key) derivation. The default implementation calls `getSecret`
and performs PBKDF2_SHA256 if key is password-based.

```cpp
result_t extractHKDF(std::vector<uint8_t>& dst, const std::vector<uint8_t>& salt, const std::vector<uint8_t>& pw_salt, int32_t kdf_iter, unsigned int idx)
```

Calculates KEK (Key Encryption Key) pre-master from a symmetric key (either password or key-based). The default implementation calls
`getKeyMaterial` and performs local HKDF extract.

### NetworkBackend

If the user intends to use key-server, a NetworkBackend has to be sub-classed with the following method implementations:

```cpp
int getClientTLSCertificate(std::vector<uint8_t>& dst)
```

Returns the client's TLS for authentication to the key-server.

```cpp
int getPeerTLSCertificates(std::vector<std::vector<uint8_t>> &dst)
```

Returns the list of acceptable peer certificates of the key-server.

```cpp
int signTLS(std::vector<uint8_t>& dst, CryptoBackend::HashAlgorithm algorithm, const std::vector<uint8_t> &digest)
```

Sign method for TLS authentication.

In addition to NetworkBackend methods, a Configuration subclass has to be instantiated.

### Configuration

The Configuration class is needed to get key-server parameters. Subclass has to implement the following method:

```cpp
std::string getValue(std::string_view domain, std::string_view param)
```

Returns configuration value for domain/param combination. For key-server:

- domain is the key-server ID
- param is KEYSERVER_SEND_URL

### CDocWriter

The CDocWriter object has to be created with one of the static methods:

```cpp
CDocWriter* createWriter(int version, DataConsumer *dst, bool take_ownership, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network)
CDocWriter* createWriter(int version, std::ostream& ofs, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network)
CDocWriter* createWriter(int version, const std::string& path, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network)
```

The value of _version_ is either 1 or 2 and indicates the file format to be used: 1 for CDOC version 1 container, and 2 for CDOC version 2 container.

CryptoBackend has to be supplied, NetworkBackend and Configuration may be `nullptr` if key-server is not used. CDocWriter does not take ownership of these
objects, so they should be deleted by caller.

Add one or more recipients:

```cpp
int addRecipient(const Recipient& rcpt)
```

Start the encryption workflow:

```cpp
int beginEncryption()
```

Write one or more files:

```cpp
int addFile(const std::string& name, size_t size)
int64_t writeData(const uint8_t *src, size_t size)
```

Finish encryption:

```cpp
int finishEncryption()
```

### Implementation Example

```cpp
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
```

## Decryption

Decryption is managed by CDocReader object.

### CryptoBackend

Create or implement a CryptoBackend class. To decrypt all lock types, at least the following methods have to be implemented:

```cpp
int deriveECDH1(std::vector<uint8_t>& dst, const std::vector<uint8_t> &public_key, unsigned int idx)
```

Derives a shared secret from document's public key and recipient's private key by using ECDH1 algorithm.

```cpp
int decryptRSA(std::vector<uint8_t>& dst, const std::vector<uint8_t>& data, bool oaep, unsigned int idx)
```

Decrypts data using RSA private key.

Also one of the symmetric key methods listed in encryption section for symmetric key support.

### NetworkBackend

It has to be implemented and supplied if server-based capsules are needed.

### Configuration

To decrypt server capsules, configuration has to contain the value of the following entry (domain is key-server id as in encryption):

- KEYSERVER_FETCH_URL

### CDocReader

Whether or not a file or DataSource is CDoc container can be determined by the following methods:

```cpp
int getCDocFileVersion(const std::string& path);
int getCDocFileVersion(DataSource *src);
```

Both return either the container version (1 or 2) or a negative number if the file/source is not valid container.

CDocReader has to be created with one of the following static constructors:

```cpp
CDocReader* createReader(DataSource *src, bool take_ownership, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network)
CDocReader* createReader(const std::string& path, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network)
CDocReader* createReader(std::istream& ifs, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network)
```

CryptoBackend has to be supplied, NetworkBackend and Configuration may be `nullptr` if key-server is not used. CDocReader does not take ownership of these
objects, so they should be deleted by caller.

The list of locks in file can be obtained by method:

```cpp
const std::vector<Lock>& getLocks()
```

The order of locks is the same as in CDoc container and the 0-based index is used to refer to the lock in decryption methods.

As a convenience method, a public-key lock can be looked up by a certificate (DER-encoded):

```cpp
result_t getLockForCert(const std::vector<uint8_t>& cert)
```

Returns the index of a lock that can be opened by the private key of the certificate, or negative number if not found.

Once the correct lock is chosen, the FMK (File Master Key) of the container has to be obtained:

```cpp
result_t getFMK(std::vector<uint8_t>& fmk, unsigned int lock_idx)
```

Depending on the lock type the method calls appropriate methods of CryptoBackend (and NetworkBackend) implementation to obtain and decrypt FMK.

After that the FMK can be used to start the encryption:

```cpp
result_t beginDecryption(const std::vector<uint8_t>& fmk)
```

Individual files can be read by nextFile method:

```cpp
result_t nextFile(std::string& name, int64_t& size)
```

The method returns the name and size of the next file in encrypted stream, or END_OF_STREAM if there are no more files. Due to the structure
of CDoc container, files have to be processed sequentially - there is no way to rewind the stream.
The name returned is the *exact filename* in encrypted stream. If the application intends to save the file with the same name, it has
to verify that the path is safe.

The actual decrypted data can be read with method:

```cpp
result_t readData(uint8_t *dst, size_t size)
```

This reads the data from current file.

When all files are read, the finalizer has to be called:

```cpp
result_t finishDecryption()
```

The decrypted data should *not be used* before successful finalization because it performs the final check of data integrity. If it
fails, the data should be assumed incomplete or corrupted.

### Implementation Example

```cpp
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
```
