#ifndef TOOLCONF_H
#define TOOLCONF_H

#include <vector>
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

    std::string getValue(const std::string_view& domain, const std::string_view& param) override final {
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
