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

#ifndef TOOLCONF_H
#define TOOLCONF_H

#include "Configuration.h"

namespace libcdoc {

/**
 * @brief The class implements libcdoc::Configuration and holds configuration for cdoc_tool.
 */
struct ToolConf : public Configuration {
    struct ServerData {
        std::string ID;
        std::string SEND_URL;
        std::string FETCH_URL;
    };

    /**
     * @brief Version of CDOC container to be created, either 1 or 2.
     */
    int cdocVersion = 2;

    /**
     * @brief If a Smart-card handling library has to be loaded or not.
     */
    bool libraryRequired = false;

    /**
     * @brief Full path to the Smart-card handling library to be used.
     */
    std::string library;

    bool use_keyserver = false;
    std::vector<ServerData> servers;

    /**
     * @brief Files to be encrypted, or file to be decrypted.
     */
    std::vector<std::string> input_files;

    /**
     * @brief The name of CDOC container file to be created, or path where to decrypt the files from CDOC container.
     */
    std::string out;

    /**
     * @brief If the label has to be generated.
     */
    bool gen_label = false;

    std::string getValue(std::string_view domain, std::string_view param) const final {
        for (auto& sdata : servers) {
            if (sdata.ID == domain) {
                if (param == Configuration::KEYSERVER_SEND_URL) {
                    return sdata.SEND_URL;
                } else if (param == Configuration::KEYSERVER_FETCH_URL) {
                    return sdata.FETCH_URL;
                }
            }
        }
        return {};
    }
};


}


#endif // TOOLCONF_H
