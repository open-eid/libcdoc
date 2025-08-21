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

#include "CDocWriter.h"

#include <memory>

namespace libcdoc
{

struct TarConsumer;

class CDoc2Writer final: public libcdoc::CDocWriter {
public:
	explicit CDoc2Writer(libcdoc::DataConsumer *dst, bool take_ownership);
    CDOC_DISABLE_COPY(CDoc2Writer);
    ~CDoc2Writer() noexcept final;

    libcdoc::result_t beginEncryption() final;
    libcdoc::result_t addRecipient(const libcdoc::Recipient& rcpt) final;
    libcdoc::result_t addFile(const std::string& name, size_t size) final;
    libcdoc::result_t writeData(const uint8_t *src, size_t size) final;
    libcdoc::result_t finishEncryption() final;

    libcdoc::result_t encrypt(libcdoc::MultiDataSource& src, const std::vector<libcdoc::Recipient>& keys) final;
private:
    libcdoc::result_t writeHeader(const std::vector<libcdoc::Recipient> &recipients);
    libcdoc::result_t buildHeader(std::vector<uint8_t>& header, const std::vector<libcdoc::Recipient>& keys, const std::vector<uint8_t>& fmk);

    std::unique_ptr<libcdoc::TarConsumer> tar;
    std::vector<libcdoc::Recipient> recipients;
};

}
