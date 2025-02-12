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

#include "Io.h"

namespace libcdoc {

static constexpr size_t BLOCK_SIZE = 65536;

std::string
DataConsumer::getLastErrorStr(int code) const
{
	switch (code) {
    case OK:
		return "";
	case OUTPUT_ERROR:
		return "DataConsumer: Output error";
	case OUTPUT_STREAM_ERROR:
		return "DataConsumer: Output stream error";
	default:
		break;
	}
	return "DataConsumer: Internal error";
}

std::string
DataSource::getLastErrorStr(int code) const
{
	switch (code) {
    case OK:
		return "";
	case INPUT_ERROR:
		return "DataConsumer: Input error";
	case INPUT_STREAM_ERROR:
		return "DataConsumer: Intput stream error";
	default:
		break;
	}
	return "DataConsumer: Internal error";
}

int64_t
DataConsumer::writeAll(DataSource& src)
{
	static const size_t BUF_SIZE = 64 * 1024;
	uint8_t buf[BUF_SIZE];
	size_t total_read = 0;
	while (!src.isEof()) {
		int64_t n_read = src.read(buf, BUF_SIZE);
		if (n_read < 0) return n_read;
		if (n_read > 0) {
			int64_t n_written = write(buf, n_read);
			if (n_written < 0) return n_written;
			total_read += n_written;
		}
	}
	return total_read;
}

int64_t
DataSource::skip(size_t size) {
	uint8_t b[BLOCK_SIZE];
	size_t total_read = 0;
	while (total_read < size) {
		size_t to_read = std::min<size_t>(size - total_read, BLOCK_SIZE);
		int64_t n_read = read(b, to_read);
		if (n_read < 0) return n_read;
		total_read += n_read;
	}
	return total_read;
}

IStreamSource::IStreamSource(const std::string& path)
	: IStreamSource(new std::ifstream(path), true)
{
}

OStreamConsumer::OStreamConsumer(const std::string& path)
	: OStreamConsumer(new std::ofstream(path), true)
{
}

FileListSource::FileListSource(const std::string& base, const std::vector<std::string>& files)
	: _base(base), _files(files), _current(-1)
{
}

int64_t
FileListSource::read(uint8_t *dst, size_t size)
{
	if ((_current < 0) || (_current >= _files.size())) return WORKFLOW_ERROR;
	_ifs.read((char *) dst, size);
	return (_ifs.bad()) ? INPUT_STREAM_ERROR : _ifs.gcount();
}

bool
FileListSource::isError()
{
    if ((_current < 0) || (_current >= _files.size())) return OK;
	return _ifs.bad();
}

bool
FileListSource::isEof()
{
	if (_current < 0) return false;
	if (_current >= _files.size()) return true;
	return _ifs.eof();
}

libcdoc::result_t
FileListSource::getNumComponents()
{
	return _files.size();
}

libcdoc::result_t
FileListSource::next(std::string& name, int64_t& size)
{
	_ifs.close();
	_current += 1;
	if (_current >= _files.size()) return END_OF_STREAM;
	std::filesystem::path path(_base);
	path.append(_files[_current]);
	if (!std::filesystem::exists(path)) return IO_ERROR;
	_ifs.open(path, std::ios_base::in);
	if (_ifs.bad()) return IO_ERROR;
	name = _files[_current];
	size = std::filesystem::file_size(path);
    return OK;
}

} // namespace libcdoc
