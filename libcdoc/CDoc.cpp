#include <fstream>

#include "CDoc1Writer.h"
#include "CDoc1Reader.h"
#include "CDoc2Writer.h"
#include "CDoc2Reader.h"

namespace libcdoc {

struct Result {
    const int64_t code;
    const std::string_view message;
};

static constexpr Result results[] = {
    {OK, "OK"},
    {END_OF_STREAM, "End of stream"},
    {NOT_IMPLEMENTED, "Method not implemented"},
    {NOT_SUPPORTED, "Method not supported"},
    {WRONG_ARGUMENTS, "Wrong arguments to a method"},
    {WORKFLOW_ERROR, "Wrong workflow sequence"},
    {IO_ERROR, "Input/Output error"},
    {OUTPUT_ERROR, "Output error"},
    {OUTPUT_STREAM_ERROR, "Output stream error"},
    {INPUT_ERROR, "Input error"},
    {INPUT_STREAM_ERROR, "Input stream error"},
    {DATA_FORMAT_ERROR, "Invalid data format"},
    {CRYPTO_ERROR, "Cryptography error"},
    {ZLIB_ERROR, "ZLib error"},
    {PKCS11_ERROR, "PKCS11 error"},
    {HASH_MISMATCH, "Hash mismatch"},
    {CONFIGURATION_ERROR, "Configuration error"},
    {UNSPECIFIED_ERROR, "Unspecified error"},
    };

static constexpr int n_results = sizeof(results) / sizeof(Result);

CDOC_EXPORT std::string
getErrorStr(int64_t code) {
    for (auto& r : results) {
        if (r.code == code) return std::string(r.message);
    }
    return std::format("Unknown result code {}", code);
}

}

bool
libcdoc::Configuration::getBoolean(const std::string_view& param, bool def_val)
{
	std::string val = getValue(param);
    if (val.empty()) return def_val;
	return val == "true";
}

int
libcdoc::Configuration::getInt(const std::string_view& param, int def_val)
{
    std::string val = getValue(param);
    if (val.empty()) return def_val;
    return std::stoi(val);
}

std::string
libcdoc::NetworkBackend::getLastErrorStr(int code) const
{
	switch (code) {
	case OK:
		return "";
	case NOT_IMPLEMENTED:
		return "NetworkBackend: Method not implemented";
	case INVALID_PARAMS:
		return "NetworkBackend: Invalid parameters";
	case NETWORK_ERROR:
		return "NetworkBackend: Network error";
	default:
		break;
	}
	return "Internal error";
}

int
libcdoc::CDocReader::getCDocFileVersion(const std::string& path)
{
	if (CDoc2Reader::isCDoc2File(path)) return 2;
	// fixme: better check
	static const std::string XML_TAG("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
	std::vector<char>buf(XML_TAG.size());
	std::ifstream ifs(path);
	if (!ifs.is_open()) return -1;
	ifs.read(buf.data(), XML_TAG.size());
	if (ifs.gcount() != XML_TAG.size()) return -1;
	if (XML_TAG.compare(0, XML_TAG.size(), buf.data())) return -1;
	return 1;
}

libcdoc::CDocReader *
libcdoc::CDocReader::createReader(const std::string& path, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network)
{
	int version = getCDocFileVersion(path);
	CDocReader *reader;
	if (version == 1) {
		reader = new CDoc1Reader(path);
	} else if (version == 2) {
		reader = new CDoc2Reader(path);
	} else {
		return nullptr;
	}
	reader->conf = conf;
	reader->crypto = crypto;
    reader->network = network;
	return reader;
}

libcdoc::CDocWriter::CDocWriter(int _version, DataConsumer *_dst, bool take_ownership)
	: version(_version), dst(_dst), owned(take_ownership)
{
};

libcdoc::CDocWriter::~CDocWriter()
{
	if (owned) delete(dst);
}

libcdoc::CDocWriter *
libcdoc::CDocWriter::createWriter(int version, DataConsumer *dst, bool take_ownership, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network)
{
	CDocWriter *writer;
	if (version == 1) {
		writer = new CDoc1Writer(dst, take_ownership);
	} else if (version == 2) {
		writer = new CDoc2Writer(dst, take_ownership);
	} else {
		return nullptr;
	}
    writer->conf = conf;
	writer->crypto = crypto;
	writer->network = network;
	return writer;
}

libcdoc::CDocWriter *
libcdoc::CDocWriter::createWriter(int version, std::ostream& ofs, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network)
{
	libcdoc::DataConsumer *dst = new libcdoc::OStreamConsumer(&ofs, false);
	return createWriter(version, dst, true, conf, crypto, network);
}

libcdoc::CDocWriter *
libcdoc::CDocWriter::createWriter(int version, const std::string& path, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network)
{
	libcdoc::DataConsumer *dst = new libcdoc::OStreamConsumer(path);
	return createWriter(version, dst, true, conf, crypto, network);
}
