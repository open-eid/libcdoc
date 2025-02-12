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

#ifndef __CDOCREADER_H__
#define __CDOCREADER_H__
 
#include <cdoc/Configuration.h>
#include <cdoc/CryptoBackend.h>
#include <cdoc/Io.h>
#include <cdoc/NetworkBackend.h>

namespace libcdoc {

/**
 * @brief The CDocReader class
 * An abstract class fro CDoc1 and CDoc2 readers. Provides unified interface for loading and decryption.
 */
class CDOC_EXPORT CDocReader {
public:
	virtual ~CDocReader() = default;

    const int version;

	/**
	 * @brief Get decryption locks in given document
	 * @return a vector of locks
	 */
    virtual const std::vector<Lock> getLocks() = 0;
	/**
     * @brief Finds the lock index for given certificate
	 *
	 * Returns the first lock that can be opened by the private key of the certificate holder.
	 * @param cert a x509 certificate (der)
     * @return lock index or error code
	 */
    virtual result_t getLockForCert(const std::vector<uint8_t>& cert) = 0;
	/**
     * @brief Fetches FMK from given lock
	 *
     * Fetches FMK (File Master Key) from the lock with given index. Depending on the lock type it uses a relevant CryptoBackend and/or
	 * NetworkBackend method to either fetch secret and derive key or perform external decryption of encrypted KEK.
	 * @param fmk The FMK of the document
     * @param lock_idx the index of a lock (in the document lock list)
	 * @return error code or OK
	 */
    virtual result_t getFMK(std::vector<uint8_t>& fmk, unsigned int lock_idx) = 0;

	// Pull interface
    /**
     * @brief beginDecryption start decrypting document
     *
     * Starts decryption of the document. This may involve parsing and decrypting headers, checking
     * file and key integrity etc.
     * @param fmk File Master Key of the document
     * @return error code or OK
     */
    virtual result_t beginDecryption(const std::vector<uint8_t>& fmk) = 0;
    /**
     * @brief nextFile start decrypting the next file
     *
     * Begins decrypting the next file in document. On success the file name and size are filled and the
     * method returns OK. If there are no more file in the document, END_OF_STREAM is returned.
     * It is OK to call nextFile before reading the whole data from the previous one.
     * @param name the name of the next file
     * @param size the size of the next file
     * @return error code, OK or END_OF_STREAM
     */
    virtual result_t nextFile(std::string& name, int64_t& size) = 0;
    /**
     * @brief readData read data from the current file
     *
     * Read bytes from the current file into the buffer. The number of bytes read is always the
     * requested number, unless end of file is reached or error occurs. Thus the end of file is marked
     * by returning 0.
     * @param dst destination byte buffer
     * @param size the number of bytes to read
     * @return the number of bytes actually read or error code
     */
    virtual result_t readData(uint8_t *dst, size_t size) = 0;
    /**
     * @brief finishDecryption finish decryption of file
     *
     * Finishes the decryption of file. This may onvolve releasing buffers, closing hardware keys etc.
     * @return error code or OK
     */
    virtual result_t finishDecryption() = 0;

    /**
     * @brief nextFile start decrypting the next file
     * @param info a FileInfo structure
     * @return error code, OK or END_OF_STREAM
     */
    result_t nextFile(FileInfo& info) { return nextFile(info.name, info.size); }

	// Push interface
	/**
	 * @brief Decrypt document
	 * Decrypts the encrypted content and writes files to provided output object
	 * @param fmk The FMK of the document
	 * @param consumer a consumer of decrypted files
	 * @return error code or OK
	 */
    virtual result_t decrypt(const std::vector<uint8_t>& fmk, MultiDataConsumer *consumer) = 0;

	/**
	 * @brief get the error text of the last failed operation
	 * @return error description, empty string if no errors
	 */
	std::string getLastErrorStr() const { return last_error; }

	/**
	 * @brief try to determine the cdoc file version
	 * @param path a path to file
     * @return version or error code if not a readable CDoc file
	 */
    static int getCDocFileVersion(const std::string& path);
    /**
     * @brief try to determine the cdoc file version
     * @param src the container source
     * @return version or error code if not a readable CDoc file
     */
    static int getCDocFileVersion(DataSource *src);

    /**
     * @brief createReader create CDoc document reader
     *
     * Creates a new document reader if source is a valid CDoc container (either version 1 or 2).
     * The network backend may be null if keyservers are not used.
     * @param src the container source
     * @param take_ownership if true the source is deleted in reader destructor
     * @param conf a configuration object
     * @param crypto a cryptographic backend implementation
     * @param network a network backend implementation
     * @return a new CDocReader or null
     */
    static CDocReader *createReader(DataSource *src, bool take_ownership, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network);
    /**
     * @brief createReader create CDoc document reader
     *
     * Creates a new document reader if file is a valid CDoc container (either version 1 or 2)
     * The network backend may be null if keyservers are not used.
     * @param path the path to file
     * @param conf a configuration object
     * @param crypto a cryptographic backend implementation
     * @param network a network backend implementation
     * @return a new CDocReader or null
     */
    static CDocReader *createReader(const std::string& path, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network);
    static CDocReader *createReader(std::istream& ifs, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network);

#if LIBCDOC_TESTING
    virtual int64_t testConfig(std::vector<uint8_t>& dst);
    virtual int64_t testNetwork(std::vector<std::vector<uint8_t>>& dst);
#endif
protected:
	explicit CDocReader(int _version) : version(_version) {};

	void setLastError(const std::string& message) { last_error = message; }

	std::string last_error;

	Configuration *conf = nullptr;
	CryptoBackend *crypto = nullptr;
	NetworkBackend *network = nullptr;
};

} // namespace libcdoc

#endif // CDOCREADER_H
