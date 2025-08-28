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

#include "XmlWriter.h"

#include "Io.h"

#include "utils/memory.h"

#include <libxml/xmlwriter.h>

#include <array>

using namespace libcdoc;

using pcxmlChar = xmlChar *;

struct XMLWriter::Private
{
    Private(libcdoc::DataConsumer &_dst): dst(_dst) {}
    libcdoc::DataConsumer &dst;
    std::map<std::string, int> nsmap;

    unique_ptr_t<xmlFreeTextWriter> w = make_unique_ptr<xmlFreeTextWriter>(xmlNewTextWriter(
        xmlOutputBufferCreateIO(xmlOutputWriteCallback, nullptr, this, nullptr)));

    static int xmlOutputWriteCallback (void *context, const char *buffer, int len);
};

int
XMLWriter::Private::xmlOutputWriteCallback (void *context, const char *buffer, int len)
{
    auto *d = reinterpret_cast<XMLWriter::Private *>(context);
    return d->dst.write((uint8_t *) buffer, len);
}

XMLWriter::XMLWriter(libcdoc::DataConsumer &dst)
    : d(std::make_unique<Private>(dst))
{
    if(d->w)
        xmlTextWriterStartDocument(d->w.get(), nullptr, "UTF-8", nullptr);
}

XMLWriter::~XMLWriter() noexcept
{
    if(d->w)
        xmlTextWriterEndDocument(d->w.get());
}

int64_t XMLWriter::writeStartElement(const NS &ns, const std::string &name, const std::map<std::string, std::string> &attr)
{
    if(!d->w)
        return WRONG_ARGUMENTS;
    auto pos = d->nsmap.find(ns.prefix);
    if (pos != d->nsmap.cend())
        pos->second++;
    else
        pos = d->nsmap.insert({ns.prefix, 1}).first;
    if(xmlTextWriterStartElementNS(d->w.get(),
            ns.prefix.empty() ? nullptr : pcxmlChar(ns.prefix.c_str()),
            pcxmlChar(name.c_str()),
            pos->second > 1 ? nullptr : pcxmlChar(ns.ns.c_str())) == -1)
        return IO_ERROR;
    for(const auto &[name, content]: attr)
    {
        if(xmlTextWriterWriteAttribute(d->w.get(), pcxmlChar(name.c_str()), pcxmlChar(content.c_str())) == -1)
            return IO_ERROR;
    }
    return OK;
}

int64_t XMLWriter::writeEndElement(const NS &ns)
{
    if(!d->w)
        return WRONG_ARGUMENTS;
    if(xmlTextWriterEndElement(d->w.get()) == -1)
        return IO_ERROR;
    if(auto pos = d->nsmap.find(ns.prefix); pos != d->nsmap.cend())
        pos->second--;
    return OK;
}

int64_t XMLWriter::writeElement(const NS &ns, const std::string &name, const std::function<int64_t()> &f)
{
    if(auto rv = writeStartElement(ns, name, {}); rv != OK)
        return rv;
    if(int64_t rv = OK; f && (rv = f()) != OK)
        return rv;
    return writeEndElement(ns);
}

int64_t XMLWriter::writeElement(const NS &ns, const std::string &name, const std::map<std::string, std::string> &attr, const std::function<int64_t()> &f)
{
    if(auto rv = writeStartElement(ns, name, attr); rv != OK)
        return rv;
    if(int64_t rv = OK; f && (rv = f()) != OK)
        return rv;
    return writeEndElement(ns);
}

int64_t XMLWriter::writeBase64Element(const NS &ns, const std::string &name, const std::function<int64_t(DataConsumer&)> &f, const std::map<std::string, std::string> &attr)
{
    if(auto rv = writeStartElement(ns, name, attr); rv != OK)
        return rv;

    struct Base64Consumer : public DataConsumer {
        xmlTextWriterPtr w;
        std::array<uint8_t, 3> buf {}; // buffer up to 2 leftover bytes
        size_t bufSize = 0;
        Base64Consumer(xmlTextWriterPtr _w) : w(_w) {}
        result_t write(const uint8_t *src, size_t size) final {
            if(!src || size == 0)
                return OK;

            size_t pos = 0;
            if(bufSize > 0) {
                pos = std::min(buf.size() - bufSize, size);
                std::copy(src, src + pos, buf.begin() + bufSize);
                bufSize += pos;
                if (bufSize < 3) {
                    return result_t(size);
                }
                if (xmlTextWriterWriteBase64(w, reinterpret_cast<const char*>(buf.data()), 0, buf.size()) == -1)
                    return IO_ERROR;
                bufSize = 0;
            }

            // Write largest contiguous chunk with length multiple of 3
            size_t remaining = size - pos;
            if(size_t fullTriples = remaining - (remaining % 3); fullTriples > 0) {
                if (xmlTextWriterWriteBase64(w, reinterpret_cast<const char*>(src), pos, fullTriples) == -1)
                    return IO_ERROR;
                pos += fullTriples;
            }

            // Buffer leftover (0..2) bytes for next write/close
            if(bufSize = size - pos; bufSize > 0) {
                std::copy(src + pos, src + size, buf.begin());
            }

            return result_t(size);
        }
        result_t close() final {
            if (bufSize > 0) {
                // write remaining 1..2 bytes so base64 padding is applied only at the end
                if(xmlTextWriterWriteBase64(w, reinterpret_cast<const char*>(buf.data()), 0, bufSize) == -1)
                    return IO_ERROR;
            }
            bufSize = 0;
            return OK;
        }
        bool isError() final { return false; }
    } base64Consumer {d->w.get()};
    if(auto rv = f(base64Consumer); rv < 0)
        return rv;
    if(auto rv = base64Consumer.close(); rv < 0)
        return rv;
    return writeEndElement(ns);
}

int64_t XMLWriter::writeBase64Element(const NS &ns, const std::string &name, const std::vector<xmlChar> &data, const std::map<std::string, std::string> &attr)
{
    if(auto rv = writeStartElement(ns, name, attr); rv != OK)
        return rv;
    if(xmlTextWriterWriteBase64(d->w.get(), reinterpret_cast<const char*>(data.data()), 0, data.size()) == -1)
        return IO_ERROR;
    return writeEndElement(ns);
}

int64_t XMLWriter::writeTextElement(const NS &ns, const std::string &name, const std::map<std::string, std::string> &attr, const std::string &data)
{
    if(auto rv = writeStartElement(ns, name, attr); rv != OK)
        return rv;
    if(xmlTextWriterWriteString(d->w.get(), pcxmlChar(data.c_str())) == -1)
        return IO_ERROR;
    return writeEndElement(ns);
}
