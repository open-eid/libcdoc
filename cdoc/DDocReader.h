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

#include "XmlReader.h"

namespace libcdoc {

struct MultiDataConsumer;

struct DDOCReader: public XMLReader
{
    using XMLReader::XMLReader;
	struct File
	{
		std::string name, mime;
		std::vector<uint8_t> data;
	};
    int64_t parse(MultiDataConsumer *dst);

    int64_t files(std::vector<DDOCReader::File> &files);
};

} // namespace libcdoc
