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

#include <cstdint>
#include <istream>
#include <string>
#include <vector>

namespace libcdoc {

struct DataSource;

class XMLReader
{
public:
	XMLReader(libcdoc::DataSource *src, bool delete_on_close = false);
    virtual ~XMLReader() noexcept;

	std::string attribute(const char *attr) const;
	bool isElement(const char *element) const;
	bool isEndElement() const;
	bool read();
	std::vector<uint8_t> readBase64();
	std::string readText();

private:
	struct Private;
	Private *d;
};

} // namespace libcdoc
