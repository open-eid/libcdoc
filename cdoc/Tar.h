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

#ifndef TAR_H
#define TAR_H

#include <cdoc/Io.h>

#include <cstring>
#include <string>
#include <cstdio>

namespace libcdoc {

struct TAR {
	explicit TAR() = default;

	static bool files(libcdoc::DataSource *src, bool &warning, libcdoc::MultiDataConsumer *dst);
	static bool save(libcdoc::DataConsumer& dst, libcdoc::MultiDataSource& src);
};

struct TarConsumer : public MultiDataConsumer
{
public:
	TarConsumer(DataConsumer *dst, bool take_ownership);
	~TarConsumer();

    libcdoc::result_t write(const uint8_t *src, size_t size) override final;
    libcdoc::result_t close() override final;
	bool isError() override final;
    libcdoc::result_t open(const std::string& name, int64_t size) override final;
private:
	DataConsumer *_dst;
	bool _owned;
	int64_t _current_size;
	int64_t _current_written;
};

struct TarSource : public MultiDataSource
{
public:
	TarSource(DataSource *src, bool take_ownership);
	~TarSource();
    libcdoc::result_t read(uint8_t *dst, size_t size) override final;
	bool isError() override final;
	bool isEof() override final;
    libcdoc::result_t getNumComponents() override final { return NOT_IMPLEMENTED; };
    libcdoc::result_t next(std::string& name, int64_t& size) override final;
private:
	DataSource *_src;
	bool _owned;
	bool _eof;
	int _error;
	size_t _block_size;
	size_t _data_size;
	size_t _pos;
};

} // namespace libcdoc

#endif // TAR_H
