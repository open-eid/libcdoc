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

#ifndef __CONFIGURATION_H__
#define __CONFIGURATION_H__

#include <cdoc/CDoc.h>

#include <cstdint>
namespace libcdoc {

/**
 * @brief A configuration provider.
 * Subclasses can implement different configuration systems (registry, .ini files etc.) by overriding getValue.
 */
struct CDOC_EXPORT Configuration {
    //static constexpr std::string_view USE_KEYSERVER = "USE_KEYSERVER";
    //static constexpr std::string_view KEYSERVER_ID = "KEYSERVER_ID";
    /* Keyserver domain */
    static constexpr char const *KEYSERVER_SEND_URL = "KEYSERVER_SEND_URL";
    static constexpr char const *KEYSERVER_FETCH_URL = "KEYSERVER_FETCH_URL";

	Configuration() = default;
	virtual ~Configuration() = default;

    virtual std::string getValue(const std::string_view& domain, const std::string_view& param) {return {};}

    std::string getValue(const std::string_view& param) {return getValue({}, param);}
    bool getBoolean(const std::string_view& param, bool def_val = false);
    int getInt(const std::string_view& param, int def_val = 0);

	Configuration (const Configuration&) = delete;
	Configuration& operator= (const Configuration&) = delete;

#if LIBCDOC_TESTING
    virtual int64_t test(std::vector<uint8_t>& dst);
#endif
};

} // namespace libcdoc

#endif // CONFIGURATION_H
