#include "DDocReader.h"
#include "CDoc.h"

#include "XmlReader.h"

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

struct FileListConsumer : public libcdoc::MultiDataConsumer {
	std::vector<DDOCReader::File> files;

	explicit FileListConsumer() = default;
	int64_t write(const uint8_t *src, size_t size) override final {
		DDOCReader::File& file = files.back();
		file.data.insert(file.data.end(), src, src + size);
		return size;
	}
	int close() override final { return libcdoc::OK; }
	bool isError() override final { return false; }
	int open(const std::string& name, int64_t size) override final {
		files.push_back({name, "application/octet-stream", {}});
		return libcdoc::OK;
	}
};

std::vector<DDOCReader::File>
DDOCReader::files(const std::vector<uint8_t> &data)
{
	libcdoc::VectorSource src(data);
	FileListConsumer list;
	parse(&src, &list);
	return std::move(list.files);
}
