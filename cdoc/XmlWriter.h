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
#include <functional>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace libcdoc {

struct DataConsumer;

class XMLWriter
{
public:
    struct NS { std::string_view prefix, ns; };

    virtual ~XMLWriter() noexcept;

protected:
    // XMLWriter is a base class for concrete writers (DDOCWriter, CDoc1Writer);
    // the element-building vocabulary is only used by subclasses.
    XMLWriter(DataConsumer &dst);

    int64_t writeStartElement(NS ns, std::string_view name, const std::map<std::string_view, std::string> &attr);
    int64_t writeEndElement(NS ns);
    int64_t writeElement(NS ns, std::string_view name, const std::function<int64_t()> &f = nullptr);
    int64_t writeElement(NS ns, std::string_view name, const std::map<std::string_view, std::string> &attr, const std::function<int64_t()> &f = nullptr);
    int64_t writeBase64Element(NS ns, std::string_view name, const std::function<int64_t(DataConsumer &)> &f, const std::map<std::string_view, std::string> &attr = {});
    int64_t writeBase64Element(NS ns, std::string_view name, const std::vector<unsigned char> &data, const std::map<std::string_view, std::string> &attr = {});
    int64_t writeTextElement(NS ns, std::string_view name, const std::map<std::string_view, std::string> &attr, std::string_view data);

private:
    int64_t write(std::string_view str);
    int64_t writeBase64(const uint8_t *src, size_t len); // encodes directly to dst
    void escape(std::string_view in, bool attribute);    // XML-escapes into buf

    DataConsumer &dst;
    std::string buf;                     // reusable scratch for building tags/text
    std::vector<std::string> stack;      // open element qualified names, for end tags
    std::map<std::string_view, int> nsmap;
};

} // namespace libcdoc
