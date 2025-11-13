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

#ifndef __LIBCDOC_UTILS_H__
#define __LIBCDOC_UTILS_H__

#include "Io.h"

#include <algorithm>
#include <iostream>
#include <sstream>

namespace libcdoc {

std::string toBase64(const uint8_t *data, size_t len);

static std::string toBase64(const std::vector<uint8_t> &data) {
    return toBase64(data.data(), data.size());
}

std::vector<uint8_t> fromBase64(const std::string& data);

template <typename F>
static std::string toHex(const F &data)
{
    std::stringstream os;
    os << std::hex << std::uppercase << std::setfill('0');
    for(const auto &i: data)
        os << std::setw(2) << (static_cast<int>(i) & 0xFF);
    return os.str();
}

static std::vector<uint8_t>
fromHex(std::string_view hex) {
    std::vector<uint8_t> val(hex.size() / 2);
    char c[3] = {0};
    for (size_t i = 0; i < (hex.size() & 0xfffffffe); i += 2) {
        std::copy(hex.cbegin() + i, hex.cbegin() + i + 2, c);
        val[i / 2] = (uint8_t) strtol(c, NULL, 16);
    }
    return std::move(val);
}

static std::vector<std::string>
split(const std::string &s, char delim = ':') {
    std::vector<std::string> result;
    std::stringstream ss(s);
    std::string item;
    while (getline (ss, item, delim)) {
        result.push_back (item);
    }
    return result;
}

static std::string
join(const std::vector<std::string> &parts, const std::string_view sep)
{
	std::string result;
	for (auto& part : parts) {
		if (part != parts.front()) result += sep;
		result += part;
	}
    return result;
}

std::vector<std::string> JsonToStringArray(std::string_view json);

// Get time in seconds since the Epoch

double getTime();
double timeFromISO(std::string_view iso);
std::string timeToISO(double time);

static std::vector<uint8_t>
readAllBytes(std::istream& ifs)
{
	std::vector<uint8_t> dst;
	uint8_t b[4096];
	while (!ifs.eof()) {
		ifs.read((char *) b, 4096);
		if (ifs.bad()) return {};
		dst.insert(dst.end(), b, b + ifs.gcount());
	}
    return dst;
}

static std::vector<uint8_t>
readAllBytes(std::string_view filename)
{
    std::filesystem::path keyFilePath(filename);
    if (!std::filesystem::exists(keyFilePath)) {
        std::cerr << "readAllBytes(): File '" << filename << "' does not exist" << std::endl;
        return {};
    }
    std::ifstream keyStream(keyFilePath, std::ios_base::in | std::ios_base::binary);
    if (!keyStream) {
        std::cerr << "readAllBytes(): Opening '" << filename << "' failed." << std::endl;
        return {};
    }
    return readAllBytes(keyStream);
}

int parseURL(const std::string& url, std::string& host, int& port, std::string& path, bool end_with_slash = false);
std::string buildURL(const std::string& host, int port);

struct urlEncode {
    std::string_view src;
    friend std::ostream& operator<<(std::ostream& escaped, urlEncode src);
};

std::string urlDecode(const std::string &src);

} // namespace libcdoc

#endif // UTILS_H
