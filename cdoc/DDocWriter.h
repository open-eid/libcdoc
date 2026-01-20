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

#include "XmlWriter.h"

namespace libcdoc {
struct DataSource;

class DDOCWriter final: public XMLWriter
{
public:
    DDOCWriter(DataConsumer &dst);
    ~DDOCWriter() noexcept final;

    int64_t addFile(const std::string &name, const std::string &mime, size_t size, libcdoc::DataSource &src);
    int64_t addFile(const std::string &name, const std::string &mime, const std::vector<unsigned char> &data);

private:
    DDOCWriter(const DDOCWriter &) = delete;
    DDOCWriter &operator=(const DDOCWriter &) = delete;
    int fileCount = 0;
};

}
