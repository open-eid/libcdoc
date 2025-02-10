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

#pragma once

#include <string>
#include <vector>

#include "CDocWriter.h"

class CDoc1Writer : public libcdoc::CDocWriter
{
public:
	CDoc1Writer(libcdoc::DataConsumer *dst, bool take_ownership, const std::string &method = "http://www.w3.org/2009/xmlenc11#aes256-gcm");
	~CDoc1Writer();

	int beginEncryption() override final;
	int addRecipient(const libcdoc::Recipient& rcpt) override final;
	int addFile(const std::string& name, size_t size) override final;
	int64_t writeData(const uint8_t *src, size_t size) override final;
	int finishEncryption() override final;

	int encrypt(libcdoc::MultiDataSource& src, const std::vector<libcdoc::Recipient>& keys) final;
private:
	CDoc1Writer(const CDoc1Writer &) = delete;
	CDoc1Writer &operator=(const CDoc1Writer &) = delete;
	class Private;
	Private *d;
};
