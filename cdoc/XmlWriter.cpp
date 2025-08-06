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

using namespace libcdoc;

typedef const xmlChar *pcxmlChar;

struct XMLWriter::Private
{
    unique_ptr_t<xmlFreeTextWriter> w = make_unique_ptr<xmlFreeTextWriter>(xmlNewTextWriter(
        xmlOutputBufferCreateIO(xmlOutputWriteCallback, xmlOutputCloseCallback, this, nullptr)));
	std::map<std::string, int> nsmap;

	libcdoc::DataConsumer* dst = nullptr;
	bool dst_owned = false;

	static int xmlOutputWriteCallback (void *context, const char *buffer, int len);
	static int xmlOutputCloseCallback (void *context);
};

int
XMLWriter::Private::xmlOutputWriteCallback (void *context, const char *buffer, int len)
{
	auto *d = reinterpret_cast<XMLWriter::Private *>(context);
	return d->dst->write((uint8_t *) buffer, len);
}

int
XMLWriter::Private::xmlOutputCloseCallback (void *context)
{
	auto *d = reinterpret_cast<XMLWriter::Private *>(context);
	return d->dst->close();
}

XMLWriter::XMLWriter(libcdoc::DataConsumer* dst)
	: d(new Private)
{
	d->dst = dst;
    xmlTextWriterStartDocument(d->w.get(), nullptr, "UTF-8", nullptr);
}

XMLWriter::XMLWriter(std::vector<uint8_t>& vec)
	: XMLWriter(new libcdoc::VectorConsumer(vec))
{
	d->dst_owned = true;
}

XMLWriter::~XMLWriter()
{
    xmlTextWriterEndDocument(d->w.get());
    // Force XmlTextWriter to finish before deleting consumer
    d->w.reset();
	if(d->dst && d->dst_owned) delete d->dst;
	delete d;
}

int64_t XMLWriter::writeStartElement(const NS &ns, const std::string &name, const std::map<std::string, std::string> &attr)
{
    if(!d->w)
        return WRONG_ARGUMENTS;
	std::map<std::string, int>::iterator pos = d->nsmap.find(ns.prefix);
	if (pos != d->nsmap.cend())
		pos->second++;
	else
		pos = d->nsmap.insert({ns.prefix, 1}).first;
    if(xmlTextWriterStartElementNS(d->w.get(), ns.prefix.empty() ? nullptr : pcxmlChar(ns.prefix.c_str()),
        pcxmlChar(name.c_str()), pos->second > 1 ? nullptr : pcxmlChar(ns.ns.c_str())) == -1)
        return IO_ERROR;
	for(auto i = attr.cbegin(), end = attr.cend(); i != end; ++i)
	{
        if(xmlTextWriterWriteAttribute(d->w.get(), pcxmlChar(i->first.c_str()), pcxmlChar(i->second.c_str())) == -1)
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
    if(std::map<std::string, int>::iterator pos = d->nsmap.find(ns.prefix);
        pos != d->nsmap.cend())
		pos->second--;
    return OK;
}

int64_t XMLWriter::writeElement(const NS &ns, const std::string &name, const std::function<uint64_t()> &f)
{
    if(auto rv = writeStartElement(ns, name, {}); rv != OK)
        return rv;
    if(uint64_t rv = OK; f && (rv = f()) != OK)
        return rv;
    return writeEndElement(ns);
}

int64_t XMLWriter::writeElement(const NS &ns, const std::string &name, const std::map<std::string, std::string> &attr, const std::function<uint64_t()> &f)
{
    if(auto rv = writeStartElement(ns, name, attr); rv != OK)
        return rv;
    if(uint64_t rv = OK; f && (rv = f()) != OK)
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
