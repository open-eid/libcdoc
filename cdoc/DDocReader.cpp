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

#include "DDocReader.h"
#include "CDoc.h"
#include "Io.h"
#include "XmlReader.h"

using namespace libcdoc;

int
DDOCReader::parse(libcdoc::DataSource *src, libcdoc::MultiDataConsumer *dst)
{
	XMLReader reader(src);
	while(reader.read()) {
		if(reader.isEndElement()) continue;
		// EncryptedData
		if(!reader.isElement("DataFile")) continue;
		std::string name = reader.attribute("Filename");
		std::vector<uint8_t> content = reader.readBase64();
        int result = dst->open(name, content.size());
        if (result != libcdoc::OK) return result;
        int64_t n_written = dst->write(content.data(), content.size());
        if (n_written < 0) return (int) n_written;
        result = dst->close();
        if (result != libcdoc::OK) return result;
    }
    return (dst->isError()) ? libcdoc::IO_ERROR : libcdoc::OK;
}

struct DDocFileListConsumer : public libcdoc::MultiDataConsumer {
	std::vector<DDOCReader::File> files;

	explicit DDocFileListConsumer() = default;
	int64_t write(const uint8_t *src, size_t size) override final {
		DDOCReader::File& file = files.back();
		file.data.insert(file.data.end(), src, src + size);
		return size;
	}
    libcdoc::result_t close() override final { return libcdoc::OK; }
	bool isError() override final { return false; }
    libcdoc::result_t open(const std::string& name, int64_t size) override final {
		files.push_back({name, "application/octet-stream", {}});
		return libcdoc::OK;
	}
};

std::vector<DDOCReader::File>
DDOCReader::files(const std::vector<uint8_t> &data)
{
	libcdoc::VectorSource src(data);
	DDocFileListConsumer list;
	parse(&src, &list);
	return std::move(list.files);
}
