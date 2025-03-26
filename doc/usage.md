# Basic libcdoc Library Usage

## Common

Most methods return `result_t` status value. It can be one of the following:

- positive value - for read and write methods indicates success and the number of bytes read/written
- OK (= 0) - indicates success
- END_OF_STREAM (= -1) - indicates the end of file list in multi-file source
- any error value (< -1) - failure

The END_OF_STREAM can only be returned from `nextFile` methods. For all other methods any negative value indicates always an error.

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
const std::vector<Lock> getLocks()
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

# libcdoc Tool Usage

libcdoc includes command-line tool, **cdoc-tool** (**cdoc-tool.exe** in Windows) that can be used to encrypt and decrypt files, and see the locks in encrypted container.

## Encryption

Common syntax for encrypting one of more files for one or more recipients is following:

```bash
cdoc-tool encrypt --rcpt RECIPIENT [--rcpt...] [-v1] [--genlabel]
    [--library PKCS11_LIBRARY]
    [--server ID URL(s)]
    [--accept SERVER_CERT_FILENAME]
    --out OUTPUTFILE
    FILE1 [FILE2 FILE3... FILEn]
```

It is also possible to re-encrypt file by adding new recipients. In that case, use **re-encrypt** switch instead of *encrypt*. The rest of the options are same.

### Options

- `-v1` - generates CDOC ver. 1 format container instead of CDOC ver. 2 container. The option can be used only when encrypting with public-key certificate 
(see [Recipients](#Recipients)). In all other cases, CDOC ver. 2 format container is created. Tool gives an error if the option is used with any other encryption method.

- `--genlabel` - causes machine-readable label generation for the lock instead of using label provided with `--rcpt` option. The machine-readable label follows the 
format described in [5.1.2.1 KeyLabel recommendations](https://open-eid.github.io/CDOC2/1.1/02_protocol_and_cryptography_spec/ch03_container_format/#keylabel-recommendations) 
chapter of *CDOC2 container format* specification, and differs depending on selected encryption method.

- `--library` - path to the PKCS11 library that handles smart-card related operations. The option is needed only in MacOS and Linux when `p11sk` or `p11pk` encryption 
method is used (see [Recipients](#Recipients)). In Windows the tool uses API provided by Windows. In all other cases the option is ignored.

- `--server ID URL(s)` - specifies a key or share server. The recipient key will be stored in server instead of container. For key server the URL is either fetch 
or send URL. For share server it is comma-separated list of share server URLs.

- `--accept SERVER_CERT_FILENAME` - path to server's TLS certificate file. The certificate must be in DER format. Needed only if a key or shared server is used, i.e. 
`--server` option is specified.

- `--out OUTPUTFILE` - CDOC file name to be created. This option is mandatory. If the file name is provided without path then the file is created in current working 
directory.

- `FILE` - one or more files to be encrypted. At least one file must be provided.

### Recipients

One ore more recipients can be specified, each with its own encryption method. At least one recipient must be specified.

| Form | Description |
| ---    | ---         |
| `[label]:cert:CERTIFICATE_HEX` | Encryption public-key from certificate. The certificate must be provided as hex-encoded string |
| `[label]:skey:SECRET_KEY_HEX` | Symmetric encryption with AES key. The key must be provided as hex-encoded string |
| `[label]:pkey:SECRET_KEY_HEX` | Encryption with public-key. The key must be provided as hex-encoded string |
| `[label]:pfkey:PUB_KEY_FILE` | Encryption with public-key where the key is provided via path to DER file with EC (**secp384r1** curve) public key |
| `[label]:pw:PASSWORD` | Encryption with derive key using PWBKDF |
| `[label]:p11sk:SLOT:[PIN]:[PKCS11 ID]:[PKCS11 LABEL]` | Encryption with AES key from PKCS11 module |
| `[label]:p11pk:SLOT:[PIN]:[PKCS11 ID]:[PKCS11 LABEL]` | Encryption with public key from PKCS11 module |
| `[label]:share:ID` | use key share server with given ID (personal code) |

If the `label` is omitted then the `--genlabel` option must be specified at command-line. Otherwise, the tool generates an error. If both, `label` and `--genlabel` 
option are provided then depending on encryption method, the `label` may be ignored, but may be also used a part of machine-readable label, like in encrypting with 
symmetric key and password case. Refer [Appendix D](https://open-eid.github.io/CDOC2/1.1/02_protocol_and_cryptography_spec/appendix_d_keylabel/) section of 
*CDOC2 container format* specification for examples of machine-readable key-labels.

### Examples

In all examples file *abc.txt* from user's *Documents* directory is used a source file to be encrypted. The result container is created in current working directory 
where also *cdoc-tool* executable is located.

Encrypt the file with password *Test123*. In result, *abc.txt-pw.cdoc* is created.

    ./cdoc-tool encrypt --rcpt Test:pw:Test123 --out abc.txt-pw.cdoc ~/Documents/abc.txt

Encrypt the file with public-key from Estonian ID card and machine-readable label. In result, *abc.txt-p11pk.cdoc* is created.

    ./cdoc-tool encrypt --rcpt :p11pk:0:::Isikutuvastus --genlabel --out abc.txt-p11pk.cdoc --library /opt/homebrew/lib/opensc-pkcs11.so ~/Documents/abc.txt

Encrypt the file with public-key from file *ec-secp384r1-pub.der*, located in current working directory. The key file can be located also in any other directory,
but in that case full path must be specified. In result, *abc.txt-pfkey.cdoc* is created.

    ./cdoc-tool encrypt --rcpt :pfkey:ec-secp384r1-pub.der --genlabel --out abc.txt-pfkey.cdoc ~/Documents/abc.txt

Encrypt the file with AES key provided via command-line. Use provided label *Test* as a part of machine-readable key-label. In result, *abc.txt-aes.cdoc* is created.

    ./cdoc-tool encrypt --rcpt Test:skey:E165475C6D8B9DD0B696EE2A37D7176DFDF4D7B510406648E70BAE8E80493E5E --genlabel --out abc.txt-aes.cdoc ~/Documents/abc.txt

Encrypt the file with public-key from RIA test key server. **VPN connection to RIA must be established!** In result, *abc.txt-ks.cdoc* is created.

    ./doc-tool encrypt --rcpt Test:p11pk:0:::Isikutuvastus --library /opt/homebrew/lib/opensc-pkcs11.so --server 00000000-0000-0000-0000-000000000000 https://cdoc2-keyserver.test.riaint.ee:8443 --accept keyserver-cert.der --out abc.txt-ks.cdoc ~/Documents/abc.txt

## Decryption

Syntax for decrypting of an encrypted file differs dramatically from encryption and is following:

```bash
cdoc-tool decrypt OPTIONS FILE [OUTPUT_DIR]
```

### Options

Following options are supported:

- `--label LABEL` - CDOC container's lock label. Either the label or label's index must be provided.
- `--label_idx INDEX` - CDOC container's lock 1-based label index. Either the label or label's index must be provided.
- `--slot SLOT` - PKCS11 slot number. Usually 0.
- `--password PASSWORD` - lock's password if the file was encrypted with password.
- `--secret SECRET` - secret phrase (AES key) if the file was encrypted with symmetric key.
- `--pin PIN` - PKCS11 (smart-card's) pin code.
- `--key-id` - PKCS11 key ID.
- `--key-label` - PKCS11 key label.
- `--library PKCS11_LIBRARY` - path to the PKCS11 library. Same as in encryption case.
- `--server ID URL(s)` - specifies a key or share server. Same as in encryption case.
- `--accept SERVER_CERT_FILENAME` - path to server's TLS certificate file. Same as in encryption case.
- `FILE` - encrypted file to be decrypted.
- `OUTPUT_DIR` - output directory where the files are decrypted. If not specified then current working directory is used. If there is already a file with same name 
then it is overwritten.

### Examples

In all examples the same container file is used as the file to be decrypted that was created previously in encryption examples.

Decrypt file abc.txt-pw.cdoc with key label *Test* and password *Test123*.

    ./cdoc-tool decrypt --label Test --password Test123 abc.txt-pw.cdoc

Decrypt file *abc.txt-p11pk.cdoc* with key label index 1 and Estonian ID card by using PIN code *1234*.

    ./cdoc-tool decrypt --label_idx 1 --pin 1234 --slot 0 --key-label Isikutuvastus --library /opt/homebrew/lib/opensc-pkcs11.so abc.txt-p11pk.cdoc

Decrypt file *abc.txt-ks.cdoc* with key label *Test* and private-key from RIA test key server. **VPN connection to RIA must be established!** PIN code *1234* is used.

    ./cdoc-tool decrypt --library /opt/homebrew/lib/opensc-pkcs11.so --server 00000000-0000-0000-0000-000000000000 https://cdoc2-keyserver.test.riaint.ee:8444 --accept keyserver-cert.der --label Test --slot 0 --pin 1234 --key-label Isikutuvastus abc.txt-ks.cdoc out

## See the Locks

Syntax for seeing the locks that are in container is following:

```bash
cdoc-tool locks FILE
```

The command does not have any options and only argument is the encrypted container file, which locks will be displayed.

### Example

Displays the locks of *abc.txt-aes.cdoc* file:

    ./cdoc-tool locks abc.txt-aes.cdoc

