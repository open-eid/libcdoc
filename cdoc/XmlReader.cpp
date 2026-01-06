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

#include "XmlReader.h"

#include "Crypto.h"

#include <libxml/xmlreader.h>

using namespace libcdoc;

using pcxmlChar = const xmlChar *;

#if LIBXML_VERSION >= 21300
constexpr int XML_READ_FLAGS = XML_PARSE_NONET|XML_PARSE_HUGE|XML_PARSE_NODICT|XML_PARSE_NO_XXE;
#else
constexpr int XML_READ_FLAGS = XML_PARSE_NONET|XML_PARSE_HUGE|XML_PARSE_NODICT;
#endif

static std::string tostring(pcxmlChar tmp)
{
    std::string result;
    if(!tmp)
        return result;
    result = (const char*)tmp;
    return result;
}

XMLReader::XMLReader(libcdoc::DataSource &src)
    : d(xmlReaderForIO([](void *context, char *buffer, int len) -> int {
        auto *src = reinterpret_cast<DataSource *>(context);
        auto result = src->read((uint8_t *) buffer, len);
        return result >= OK ? result : -1;
    }, nullptr, &src, nullptr, nullptr, XML_READ_FLAGS))
{}

XMLReader::~XMLReader() noexcept
{
    xmlFreeTextReader(d);
}

std::string XMLReader::attribute(const char *attr) const
{
    xmlChar *tmp = xmlTextReaderGetAttribute(d, pcxmlChar(attr));
    std::string result = tostring(tmp);
    xmlFree(tmp);
    return result;
}

bool XMLReader::isEndElement() const
{
    return xmlTextReaderNodeType(d) == XML_READER_TYPE_END_ELEMENT;
}

bool XMLReader::isElement(const char *elem) const
{
    return xmlStrEqual(xmlTextReaderConstLocalName(d), pcxmlChar(elem)) == 1;
}

bool XMLReader::read()
{
    return xmlTextReaderRead(d) == 1;
}

std::vector<uint8_t> XMLReader::readBase64()
{
    xmlTextReaderRead(d);
    return libcdoc::Crypto::decodeBase64(xmlTextReaderConstValue(d));
}

std::string XMLReader::readText()
{
    xmlTextReaderRead(d);
    return tostring(xmlTextReaderConstValue(d));
}
