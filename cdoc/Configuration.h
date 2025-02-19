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
 *
 * Subclasses can implement different configuration systems (registry, .ini files etc.) by overriding getValue.
 */
struct CDOC_EXPORT Configuration {
    /**
     * @brief Get send URL of keyserver
     */
    static constexpr char const *KEYSERVER_SEND_URL = "KEYSERVER_SEND_URL";
    /**
     * @brief Get fetch URL of keyserver
     */
    static constexpr char const *KEYSERVER_FETCH_URL = "KEYSERVER_FETCH_URL";

	Configuration() = default;
	virtual ~Configuration() = default;

    /**
     * @brief get a value of configuration parameter
     *
     * Get a string value of configuration parameter.
     * @param domain the parameter domain. For keyservers this is the server ID.
     * @param param the parameter name.
     * @return a string value or empty string if parameter is not defined.
     */
    virtual std::string getValue(const std::string_view& domain, const std::string_view& param) {return {};}

    /**
     * @brief get a value of configuration parameter from default domain
     * @param param the parameter name.
     * @return a string value or empty string if parameter is not defined.
     */
    std::string getValue(const std::string_view& param) {return getValue({}, param);}
    /**
     * @brief get boolean value of configuration parameter from default domain
     * @param param the parameter name
     * @param def_val the default value to return if parameter is not set
     * @return the parameter value
     */
    bool getBoolean(const std::string_view& param, bool def_val = false);
    /**
     * @brief get integer value of configuration parameter from default domain
     * @param param the parameter name
     * @param def_val the default value to return if parameter is not set
     * @return the key value
     */
    int getInt(const std::string_view& param, int def_val = 0);

	Configuration (const Configuration&) = delete;
	Configuration& operator= (const Configuration&) = delete;

#if LIBCDOC_TESTING
    virtual int64_t test(std::vector<uint8_t>& dst);
#endif
};

} // namespace libcdoc

#endif // CONFIGURATION_H
