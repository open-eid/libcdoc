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

#ifndef __WRAPPER_H__
#define __WRAPPER_H__

#include <vector>

namespace libcdoc {

struct DataBuffer {
    std::vector<uint8_t> *data;

    DataBuffer() : data(&vec) {}
    DataBuffer(std::vector<uint8_t> *_data) : data(_data) {}

    const std::vector<uint8_t>& getData() { return *data; }
    void setData(const std::vector<uint8_t>& _data) { *data = _data; }

    void reset() { data = &vec; }
private:
    std::vector<uint8_t> vec;
};

struct CertificateList {
    std::vector<std::vector<uint8_t>> *data;

    CertificateList() : data(&vec) {}
    CertificateList(std::vector<std::vector<uint8_t>> *_data) : data(_data) {}

    const std::vector<std::vector<uint8_t>>& getData() { return *data; }
    void setData(const std::vector<std::vector<uint8_t>>& _data) { *data = _data; }

    void clear() { data->clear(); }
    size_t size() { return data->size(); }
    void addCertificate(const std::vector<uint8_t>& cert) { data->push_back(cert); }
    const std::vector<uint8_t>& getCertificate(unsigned int idx) { return data->at(idx); }

    void reset() { data = &vec; }
private:
    std::vector<std::vector<uint8_t>> vec;
};

}

#endif
