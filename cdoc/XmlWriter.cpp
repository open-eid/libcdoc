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

#include <algorithm>
#include <array>

using namespace libcdoc;

XMLWriter::XMLWriter(DataConsumer &dst)
    : dst(dst)
{
    write(R"(<?xml version="1.0" encoding="UTF-8"?>)");
}

XMLWriter::~XMLWriter() noexcept = default;

// XML-escape `in` into the scratch buffer. In attribute context '"' is also escaped.
void XMLWriter::escape(std::string_view in, bool attribute)
{
    for(char c: in)
    {
        switch(c)
        {
        case '&': buf += "&amp;"; break;
        case '<': buf += "&lt;"; break;
        case '>': buf += "&gt;"; break;
        case '"': if(attribute) { buf += "&quot;"; break; } [[fallthrough]];
        default: buf += c;
        }
    }
}

int64_t XMLWriter::write(std::string_view str)
{
    return dst.write(reinterpret_cast<const uint8_t*>(str.data()), str.size()) < 0 ? IO_ERROR : OK;
}

int64_t XMLWriter::writeStartElement(NS ns, std::string_view name, const std::map<std::string_view, std::string> &attr)
{
    std::string qname;
    if(!ns.prefix.empty())
        (qname += ns.prefix) += ':';
    qname += name;

    buf.clear();
    buf += '<';
    buf += qname;
    // Declare the namespace only on its first (outermost) open element; nested
    // elements with the same prefix inherit it.
    if(auto &count = nsmap[ns.prefix]; ++count == 1 && !ns.ns.empty())
    {
        buf += !ns.prefix.empty() ? " xmlns:" : " xmlns";
        if(!ns.prefix.empty())
            buf += ns.prefix;
        buf += "=\"";
        buf += ns.ns; // namespace URIs are compile-time constants, no escaping needed
        buf += '"';
    }
    for(const auto &[aname, avalue]: attr)
    {
        (buf += ' ') += aname;
        buf += "=\"";
        escape(avalue, true);
        buf += '"';
    }
    buf += '>';
    stack.push_back(std::move(qname));
    return write(buf);
}

int64_t XMLWriter::writeEndElement(NS ns)
{
    if(stack.empty())
        return WRONG_ARGUMENTS;
    buf.clear();
    buf += "</";
    buf += stack.back();
    buf += '>';
    stack.pop_back();
    if(auto pos = nsmap.find(ns.prefix); pos != nsmap.cend())
        pos->second--;
    return write(buf);
}

int64_t XMLWriter::writeElement(NS ns, std::string_view name, const std::function<int64_t()> &f)
{
    return writeElement(ns, name, {}, f);
}

int64_t XMLWriter::writeElement(NS ns, std::string_view name, const std::map<std::string_view, std::string> &attr, const std::function<int64_t()> &f)
{
    if(auto rv = writeStartElement(ns, name, attr); rv != OK)
        return rv;
    if(int64_t rv = OK; f && (rv = f()) != OK)
        return rv;
    return writeEndElement(ns);
}

// Base64-encode `len` bytes straight into a stack buffer and bulk-write to dst,
// with no per-chunk heap allocation. `len` need not be a multiple of 3 — padding
// is emitted for the 1..2 byte remainder, so for streamed output pass whole
// triples on every chunk except the final tail (padding is then written once).
int64_t XMLWriter::writeBase64(const uint8_t *src, size_t len)
{
    constexpr char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::array<char, 4092> buf; // multiple of 4; flushed once full
    size_t n = 0, i = 0;
    for(; i + 3 <= len; i += 3)
    {
        uint32_t v = uint32_t(src[i]) << 16 | uint32_t(src[i + 1]) << 8 | src[i + 2];
        buf[n++] = B64[v >> 18 & 63];
        buf[n++] = B64[v >> 12 & 63];
        buf[n++] = B64[v >> 6 & 63];
        buf[n++] = B64[v & 63];
        if(n == buf.size())
        {
            if(dst.write(reinterpret_cast<const uint8_t*>(buf.data()), n) < 0)
                return IO_ERROR;
            n = 0;
        }
    }
    if(size_t rem = len - i; rem == 1)
    {
        uint32_t v = uint32_t(src[i]) << 16;
        buf[n++] = B64[v >> 18 & 63];
        buf[n++] = B64[v >> 12 & 63];
        buf[n++] = '=';
        buf[n++] = '=';
    }
    else if(rem == 2)
    {
        uint32_t v = uint32_t(src[i]) << 16 | uint32_t(src[i + 1]) << 8;
        buf[n++] = B64[v >> 18 & 63];
        buf[n++] = B64[v >> 12 & 63];
        buf[n++] = B64[v >> 6 & 63];
        buf[n++] = '=';
    }
    if(n > 0 && dst.write(reinterpret_cast<const uint8_t*>(buf.data()), n) < 0)
        return IO_ERROR;
    return OK;
}

int64_t XMLWriter::writeBase64Element(NS ns, std::string_view name, const std::function<int64_t(DataConsumer&)> &f, const std::map<std::string_view, std::string> &attr)
{
    if(auto rv = writeStartElement(ns, name, attr); rv != OK)
        return rv;

    struct Base64Consumer: public DataConsumer {
        XMLWriter &w;
        std::array<uint8_t, 3> buf {}; // up to 2 leftover bytes between writes
        size_t bufSize = 0;
        Base64Consumer(XMLWriter &w): w(w) {}
        result_t write(const uint8_t *src, size_t size) noexcept final {
            if(!src || size == 0)
                return OK;
            size_t pos = 0;
            if(bufSize > 0) {
                pos = std::min(buf.size() - bufSize, size);
                std::copy(src, src + pos, buf.begin() + bufSize);
                bufSize += pos;
                if(bufSize < 3)
                    return result_t(size);
                if(w.writeBase64(buf.data(), buf.size()) != OK)
                    return IO_ERROR;
                bufSize = 0;
            }
            // Emit the largest chunk whose length is a multiple of 3 (no padding).
            size_t remaining = size - pos;
            if(size_t fullTriples = remaining - remaining % 3; fullTriples > 0) {
                if(w.writeBase64(src + pos, fullTriples) != OK)
                    return IO_ERROR;
                pos += fullTriples;
            }
            // Buffer the trailing 0..2 bytes for the next write / close().
            if(bufSize = size - pos; bufSize > 0)
                std::copy(src + pos, src + size, buf.begin());
            return result_t(size);
        }
        result_t close() noexcept final {
            if(bufSize > 0 && w.writeBase64(buf.data(), bufSize) != OK)
                return IO_ERROR;
            bufSize = 0;
            return OK;
        }
        bool isError() noexcept final { return false; }
    } base64Consumer {*this};
    if(auto rv = f(base64Consumer); rv < 0)
        return rv;
    if(auto rv = base64Consumer.close(); rv < 0)
        return rv;
    return writeEndElement(ns);
}

int64_t XMLWriter::writeBase64Element(NS ns, std::string_view name, const std::vector<unsigned char> &data, const std::map<std::string_view, std::string> &attr)
{
    if(auto rv = writeStartElement(ns, name, attr); rv != OK)
        return rv;
    if(!data.empty() && writeBase64(data.data(), data.size()) != OK)
        return IO_ERROR;
    return writeEndElement(ns);
}

int64_t XMLWriter::writeTextElement(NS ns, std::string_view name, const std::map<std::string_view, std::string> &attr, std::string_view data)
{
    if(auto rv = writeStartElement(ns, name, attr); rv != OK)
        return rv;
    // writeStartElement already flushed buf, so it is free to reuse for the text.
    buf.clear();
    escape(data, false);
    if(write(buf) != OK)
        return IO_ERROR;
    return writeEndElement(ns);
}
