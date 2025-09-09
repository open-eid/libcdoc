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

#ifndef __CDOC2_READER_H__
#define __CDOC2_READER_H__

#include "CDocReader.h"

#include <memory>

class CDoc2Reader final: public libcdoc::CDocReader {
public:
	~CDoc2Reader() final;

    const std::vector<libcdoc::Lock>& getLocks() override final;
    libcdoc::result_t getLockForCert(const std::vector<uint8_t>& cert) override final;
    libcdoc::result_t getFMK(std::vector<uint8_t>& fmk, unsigned int lock_idx) override final;
    libcdoc::result_t decrypt(const std::vector<uint8_t>& fmk, libcdoc::MultiDataConsumer *consumer) override final;

	// Pull interface
    libcdoc::result_t beginDecryption(const std::vector<uint8_t>& fmk) override final;
    libcdoc::result_t nextFile(std::string& name, int64_t& size) override final;
    libcdoc::result_t readData(uint8_t *dst, size_t size) override final;
    libcdoc::result_t finishDecryption() override final;

	CDoc2Reader(libcdoc::DataSource *src, bool take_ownership = false);

	static bool isCDoc2File(const std::string& path);
    static bool isCDoc2File(libcdoc::DataSource *src);
private:
	struct Private;

	std::unique_ptr<Private> priv;
};

#endif
