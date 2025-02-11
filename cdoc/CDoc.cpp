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

#include "CDoc1Writer.h"
#include "CDoc1Reader.h"
#include "CDoc2Writer.h"
#include "CDoc2Reader.h"

#include <iostream>

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
    {NOT_FOUND, "Object not found"},
    {UNSPECIFIED_ERROR, "Unspecified error"},
    };

static constexpr int n_results = sizeof(results) / sizeof(Result);

std::string
getErrorStr(int64_t code) {
    for (auto& r : results) {
        if (r.code == code) return std::string(r.message);
    }
    return "Unknown result code " + std::to_string(code);
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

#if LIBCDOC_TESTING
int64_t
libcdoc::Configuration::test(std::vector<uint8_t>& dst)
{
    std::cerr << "Configuration::test::Native superclass" << std::endl;
    return OK;
}
#endif

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

#if LIBCDOC_TESTING
int64_t
libcdoc::NetworkBackend::test(std::vector<std::vector<uint8_t>> &dst)
{
    std::cerr << "NetworkBackend::test::Native superclass" << std::endl;
    return OK;
}
#endif


int
libcdoc::CDocReader::getCDocFileVersion(DataSource *src)
{
    if (src->seek(0) != libcdoc::OK) return libcdoc::IO_ERROR;
    if (CDoc2Reader::isCDoc2File(src)) return 2;
    src->seek(0);
    if (CDoc1Reader::isCDoc1File(src)) return 1;
    return libcdoc::NOT_SUPPORTED;
}

int
libcdoc::CDocReader::getCDocFileVersion(const std::string& path)
{
    IStreamSource ifs(path);
    return getCDocFileVersion(&ifs);
}

libcdoc::CDocReader *
libcdoc::CDocReader::createReader(DataSource *src, bool take_ownership, Configuration *conf, CryptoBackend *crypto, NetworkBackend *network)
{
    int version = getCDocFileVersion(src);
    std::cerr << "CDocReader::createReader: version " << version << std::endl;
    if (src->seek(0) != libcdoc::OK) return nullptr;
    CDocReader *reader;
	if (version == 1) {
        reader = new CDoc1Reader(src, take_ownership);
	} else if (version == 2) {
        reader = new CDoc2Reader(src, take_ownership);
	} else {
		return nullptr;
	}
	reader->conf = conf;
	reader->crypto = crypto;
    reader->network = network;
	return reader;
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

#if LIBCDOC_TESTING
int64_t
libcdoc::CDocReader::testConfig(std::vector<uint8_t>& dst)
{
    std::cerr << "CDocReader::testConfig::Native superclass" << std::endl;
    if (conf) {
        std::cerr << "CDocReader::testConfig this=" << this << " conf=" << conf << std::endl;
        return conf->test(dst);
    }
    std::cerr << "CDocReader::testConfig::conf is null" << std::endl;
    return WORKFLOW_ERROR;
}

int64_t
libcdoc::CDocReader::testNetwork(std::vector<std::vector<uint8_t>>& dst)
{
    std::cerr << "CDocReader::testNetwork::Native superclass" << std::endl;
    if (network) {
        std::cerr << "CDocReader::testNetwork this=" << this << " network=" << network << std::endl;
        return network->test(dst);
    }
    std::cerr << "CDocReader::testNetwork::network is null" << std::endl;
    return WORKFLOW_ERROR;
}
#endif

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
