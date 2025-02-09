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

#ifndef __CDOC2_WRITER_H__
#define __CDOC2_WRITER_H__

#include "CDocWriter.h"

class CDoc2Writer final: public libcdoc::CDocWriter {
public:
	explicit CDoc2Writer(libcdoc::DataConsumer *dst, bool take_ownership);
	~CDoc2Writer();

	int beginEncryption() override final;
	int addRecipient(const libcdoc::Recipient& rcpt) override final;
	int addFile(const std::string& name, size_t size) override final;
	int64_t writeData(const uint8_t *src, size_t size) override final;
	int finishEncryption() override final;

	int encrypt(libcdoc::MultiDataSource& src, const std::vector<libcdoc::Recipient>& keys) override final;
private:
	struct Private;

	std::unique_ptr<Private> priv;

	int encryptInternal(libcdoc::MultiDataSource& src, const std::vector<libcdoc::Recipient>& keys);
	int writeHeader(const std::vector<uint8_t>& header, const std::vector<uint8_t>& hhk);
	int buildHeader(std::vector<uint8_t>& header, const std::vector<libcdoc::Recipient>& keys, const std::vector<uint8_t>& fmk);
};

#endif
