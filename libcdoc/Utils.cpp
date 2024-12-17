#define __UTILS_CPP__

#include "Utils.h"

#include <openssl/evp.h>
#include <openssl/http.h>

namespace libcdoc {

std::string
toBase64(const uint8_t *data, size_t len)
{
    std::string result(((len + 2) / 3) * 4, 0);
    int size = EVP_EncodeBlock((uint8_t *) result.data(), data, int(len));
    result.resize(size);
    return result;
}

int
parseURL(const std::string& url, std::string& host, int& port, std::string& path)
{
    char *phost, *ppath;
    int pport;
    if (!OSSL_HTTP_parse_url(url.c_str(),
                             nullptr, // SSL
                             nullptr, // user
                             &phost,
                             nullptr, // port (str)
                             &pport,
                             &ppath,
                             nullptr, // query
                             nullptr // frag
        )) {
        return libcdoc::DATA_FORMAT_ERROR;
    }
    host = phost;
    port = pport;
    path = ppath;
    OPENSSL_free(phost);
    OPENSSL_free(ppath);
    return OK;
}

std::string
urlEncode(const std::string_view &src)
{
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (auto i = src.begin(), n = src.end(); i != n; ++i) {
        std::string::value_type c = (*i);
        // Keep alphanumeric and other accepted characters intact
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
            continue;
        }
        // Any other characters are percent-encoded
        escaped << std::uppercase;
        escaped << '%' << std::setw(2) << int((unsigned char) c);
        escaped << std::nouppercase;
    }
    return escaped.str();
}

std::string
urlDecode(std::string &src)
{
    std::string ret;
    ret.reserve(64);
    for (int i = 0; i < src.length(); i++) {
        if (src[i] == '%') {
            int val;
            sscanf(src.substr(i + 1, 2).c_str(), "%x", &val);
            char ch = static_cast<char>(val);
            ret += ch;
            i += 2;
        } else {
            ret += src[i];
        }
    }
    return ret;
}

} // Namespace libcdoc

