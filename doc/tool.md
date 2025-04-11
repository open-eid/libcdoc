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
- `--library PKCS11_LIBRARY` - path to the PKCS11 library. Same as in encryption case.
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
