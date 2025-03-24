#define __CONFIGURATION_CPP__

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

#include "Configuration.h"

#include "ILogger.h"
#include "Utils.h"

#include "json/picojson/picojson.h"

namespace libcdoc {

bool
libcdoc::Configuration::getBoolean(std::string_view param, bool def_val) const
{
	std::string val = getValue(param);
    if (val.empty()) return def_val;
	return val == "true";
}

int
libcdoc::Configuration::getInt(std::string_view param, int def_val) const
{
    std::string val = getValue(param);
    if (val.empty()) return def_val;
    return std::stoi(val);
}

struct JSONConfiguration::Private {
    picojson::object root = {};
};

JSONConfiguration::JSONConfiguration()
: d(new Private())
{
}

JSONConfiguration::JSONConfiguration(std::istream& ifs)
: d(new Private())
{
    parse(ifs);
}

JSONConfiguration::JSONConfiguration(std::string_view file)
: d(new Private())
{
    parse(file);
}

JSONConfiguration::~JSONConfiguration()
{
    delete d;
}

bool
JSONConfiguration::parse(std::istream& ifs)
{
    picojson::value val;
    ifs >> val;
    std::string err = picojson::get_last_error();
    if(!err.empty()) {
        LOG_ERROR("Error parsing configuration: {}", err);
        return false;
    }
    if(!val.is<picojson::object>()) {
        LOG_ERROR("Configuration file is not JSON object");
        return false;
    }
    d->root = val.get<picojson::object>();
    return true;
}

bool
JSONConfiguration::parse(std::string_view file)
{
    std::ifstream ifs(file, std::ios::binary);
    if (ifs.bad()) {
        LOG_ERROR("Cannot open {}", file);
        return false;
    }
    return parse(ifs);
}

std::string
JSONConfiguration::getValue(std::string_view domain, std::string_view param) const
{
    picojson::object& obj = d->root;
    if (!domain.empty()) {
        if (d->root.contains(std::string(domain))) {
            LOG_DBG("Fetching {}", domain);
            picojson::value& val = d->root.at(std::string(domain));
            if (!val.is<picojson::object>()) return {};
            LOG_DBG("IS object");
            obj = val.get<picojson::object>();
        } else {
            return {};
        }
    }
    LOG_DBG("Querying {}", param);
    if (!obj.contains(std::string(param))) return {};
    LOG_DBG("Obj contains {}", param);
    picojson::value val = obj.at(std::string(param));
    if (!val.is<std::string>()) return {};
    return val.get<std::string>();
}

}
