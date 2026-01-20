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

#include "utils/memory.h"

#include <cstdint>
#include <functional>
#include <map>
#include <string>

struct _xmlTextWriter;

namespace libcdoc {

struct DataConsumer;

class XMLWriter
{
public:
    struct NS { const char *prefix, *ns; };

    XMLWriter(DataConsumer &dst);
    virtual ~XMLWriter() noexcept;

    int64_t writeStartElement(NS ns, const std::string &name, const std::map<std::string, std::string> &attr);
    int64_t writeEndElement(NS ns);
    int64_t writeElement(NS ns, const std::string &name, const std::function<int64_t()> &f = nullptr);
    int64_t writeElement(NS ns, const std::string &name, const std::map<std::string, std::string> &attr, const std::function<int64_t()> &f = nullptr);
    int64_t writeBase64Element(NS ns, const std::string &name, const std::function<int64_t(DataConsumer &)> &f, const std::map<std::string, std::string> &attr = {});
    int64_t writeBase64Element(NS ns, const std::string &name, const std::vector<unsigned char> &data, const std::map<std::string, std::string> &attr = {});
    int64_t writeTextElement(NS ns, const std::string &name, const std::map<std::string, std::string> &attr, const std::string &data);

private:
    unique_free_t<_xmlTextWriter> w;
    std::map<std::string_view, int> nsmap;
};

} // namespace libcdoc
