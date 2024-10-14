#ifndef __CDOCWRITER_H__
#define __CDOCWRITER_H__

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

#include "Recipient.h"
#include "Io.h"

#include "Configuration.h"
#include "CryptoBackend.h"
#include "NetworkBackend.h"

namespace libcdoc {

class CDocWriter {
public:
	virtual ~CDocWriter() = default;

	int version;

	/* Push interface */
	virtual int beginEncryption(DataConsumer& dst) = 0;
	virtual int addRecipient(const libcdoc::Recipient& rcpt) = 0;
	virtual int addFile(const std::string& name, size_t size) = 0;
	virtual int writeData(const uint8_t *src, size_t size) = 0;
	virtual int finishEncryption(bool close_dst = true) = 0;

	/* Pull interface */
	/**
	 * @brief encrypt data and send to the output
	 * @param dst DataConsumer where output is written
	 * @param src MultiDataSource providing input files (named chunks)
	 * @param recipients a list of recipients for whom locks will be encoded into file
	 * @return error code or OK
	 */
	virtual int encrypt(DataConsumer& dst, MultiDataSource& src, const std::vector<libcdoc::Recipient>& recipients) = 0;
	/**
	 * @brief get the textual error of the last failed operation
	 * @return error description, empty string of no errors
	 */
	std::string getLastErrorStr() { return last_error; }

	static CDocWriter *createWriter(int version, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network);
protected:
	explicit CDocWriter(int _version) : version(_version) {};

	void setLastError(const std::string& message) { last_error = message; }

	std::string last_error;

	Configuration *conf = nullptr;
	CryptoBackend *crypto = nullptr;
	NetworkBackend *network = nullptr;
};

} // namespace libcdoc

#endif // CDOCWRITER_H
