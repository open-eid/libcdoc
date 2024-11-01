#ifndef __CDOCREADER_H__
#define __CDOCREADER_H__

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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <libcdoc/Configuration.h>
#include <libcdoc/CryptoBackend.h>
#include <libcdoc/Exports.h>
#include <libcdoc/Io.h>
#include <libcdoc/Lock.h>
#include <libcdoc/NetworkBackend.h>

namespace libcdoc {

/**
 * @brief The CDocReader class
 * An abstract class fro CDoc1 and CDoc2 readers. Provides unified interface for loading and decryption.
 */
class CDOC_EXPORT CDocReader {
public:
	virtual ~CDocReader() = default;

	int version;

	/**
	 * @brief Get decryption locks in given document
	 * @return a vector of locks
	 */
	virtual std::vector<Lock> getLocks() = 0;
	/**
	 * @brief Fetches the lock for certificate
	 *
	 * Returns the first lock that can be opened by the private key of the certificate holder.
	 * @param lock reference to result
	 * @param cert a x509 certificate (der)
	 * @return true if lock was found
	 */
	virtual bool getLockForCert(Lock& lock, const std::vector<uint8_t>& cert) = 0;
	/**
	 * @brief Fetches FMK from provided lock
	 *
	 * Fetches FMK (File Master Key) from the provided decryption lock. Depending on the lock type it uses a relevant CryptoBackend and/or
	 * NetworkBackend method to either fetch secret and derive key or perform external decryption of encrypted KEK.
	 * @param fmk The FMK of the document
	 * @param lock a lock (from document lock list)
	 * @return error code or OK
	 */
	virtual int getFMK(std::vector<uint8_t>& fmk, const libcdoc::Lock& lock) = 0;

	// Pull interface
	virtual int beginDecryption(const std::vector<uint8_t>& fmk) = 0;
	virtual int nextFile(std::string& name, int64_t& size) = 0;
	virtual int64_t readData(uint8_t *dst, size_t size) = 0;
	virtual int finishDecryption() = 0;


	// Push interface
	/**
	 * @brief Decrypt document
	 * Decrypts the encrypted content and writes files to provided output object
	 * @param fmk The FMK of the document
	 * @param consumer a consumer of decrypted files
	 * @return error code or OK
	 */
	virtual int decrypt(const std::vector<uint8_t>& fmk, MultiDataConsumer *consumer) = 0;

	/**
	 * @brief get the error text of the last failed operation
	 * @return error description, empty string if no errors
	 */
	std::string getLastErrorStr() const { return last_error; }

	/**
	 * @brief try to determine the cdoc file version
	 * @param path a path to file
	 * @return version, -1 if not a valid CDoc file
	 */
	static int getCDocFileVersion(const std::string& path);

	static CDocReader *createReader(const std::string& path, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network);
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
