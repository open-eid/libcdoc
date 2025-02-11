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

#ifndef __CDOCWRITER_H__
#define __CDOCWRITER_H__
 
#include <cdoc/Io.h>
#include <cdoc/Configuration.h>
#include <cdoc/CryptoBackend.h>
#include <cdoc/NetworkBackend.h>

namespace libcdoc {

class CDOC_EXPORT CDocWriter {
public:
	virtual ~CDocWriter();

	const int version;

	/* Push interface */
	/**
	 * @brief prepares the stream for encryption
	 *
	 * This may involve creating cryptographic ciphers, building headers and writing the
	 * initial part of the stream
	 * @return error code or OK
	 */
    virtual result_t beginEncryption() = 0;
	/**
	 * @brief add recipient to container
	 * @param rcpt a Recipient structure
	 * @return error code or OK
	 */
    virtual result_t addRecipient(const Recipient& rcpt) = 0;
	/**
	 * @brief start new file
	 *
	 * Start streaming the new file into output stream
	 * @param name the name to be used in stream
	 * @param size the size of the file
	 * @return  error code or OK
	 */
    virtual result_t addFile(const std::string& name, size_t size) = 0;
	/**
	 * @brief write the data of current file to encrypted stream
	 *
	 * A single file may safely be written in multiple parts as long as the total size matches
	 * @param src a source buffer
	 * @param size the size of data in buffer
	 * @return size or error code
	 */
    virtual result_t writeData(const uint8_t *src, size_t size) = 0;
	/**
	 * @brief finalizes the encryption stream
	 *
	 * This may involve flushing file, calculating checksum and closing the stream (if owned by CDocWriter)
	 * @return error code or OK
	 */
    virtual result_t finishEncryption() = 0;

	/* Pull interface */
	/**
	 * @brief encrypt data and send to the output
	 * @param src MultiDataSource providing input files (named chunks)
	 * @param recipients a list of recipients for whom locks will be encoded into file
	 * @return error code or OK
	 */
    virtual result_t encrypt(MultiDataSource& src, const std::vector<libcdoc::Recipient>& recipients) { return NOT_IMPLEMENTED; }
	/**
	 * @brief get the textual error of the last failed operation
	 * @return error description, empty string of no errors
	 */
	std::string getLastErrorStr() { return last_error; }

	/**
	 * @brief create CDoc writer
	 * @param version
	 * @param dst DataConsumer where output is written
	 * @param take_ownership whether to close dst at the end of encryption and delete with CDocWiter
	 * @param conf
	 * @param crypto
	 * @param network
	 * @return
	 */
	static CDocWriter *createWriter(int version, DataConsumer *dst, bool take_ownership, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network);
	static CDocWriter *createWriter(int version, std::ostream& ofs, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network);
	static CDocWriter *createWriter(int version, const std::string& path, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network);
protected:
	explicit CDocWriter(int _version, DataConsumer *dst, bool take_ownership);

	void setLastError(const std::string& message) { last_error = message; }

	std::string last_error;
	DataConsumer *dst;
	bool owned;

	Configuration *conf = nullptr;
	CryptoBackend *crypto = nullptr;
	NetworkBackend *network = nullptr;
};

} // namespace libcdoc

#endif // CDOCWRITER_H
