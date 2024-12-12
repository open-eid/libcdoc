#ifndef __NETWORKBACKEND_H__
#define __NETWORKBACKEND_H__

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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <libcdoc/CryptoBackend.h>
#include <libcdoc/Exports.h>
#include <libcdoc/Recipient.h>

#include <vector>

namespace libcdoc {

struct CDOC_EXPORT NetworkBackend {
	static constexpr int OK = 0;
	static constexpr int NOT_IMPLEMENTED = -300;
	static constexpr int INVALID_PARAMS = -301;
	static constexpr int NETWORK_ERROR = -302;

	NetworkBackend() = default;
	virtual ~NetworkBackend() = default;

	virtual std::string getLastErrorStr(int code) const;

	/**
	 * @brief send key material to keyserver
     *
     * The default implementation uses internal http client and peer TLS certificate list.
     * @param dst the transaction id (capsule id) on server
     * @param recipient
	 * @param key_material
	 * @param type algorithm type, currently either "rsa" or "ecc_secp384r1"
	 * @return error code or OK
	 */
    virtual int sendKey (std::string& dst, const std::string& url, const Recipient& recipient, const std::vector<uint8_t> &key_material, const std::string& type);
	/**
	 * @brief fetch key material from keyserver
     * @param dst a destination container for key material
     * @param recipient_key
	 * @param transaction_id
	 * @return error code or OK
	 */
    virtual int fetchKey (std::vector<uint8_t>& dst, const std::string& url, const std::string& transaction_id) = 0;

    /**
     * @brief get client TLS certificate in der format
     * @param dst a destination container for certificate
     * @return error code or OK
     */
    virtual int getClientTLSCertificate(std::vector<uint8_t>& dst) = 0;

    /**
     * @brief get a list of peer TLS certificates in der format
     * @param dst a destination container for certificate
     * @return error code or OK
     */
    virtual int getPeerTLSCerticates(std::vector<std::vector<uint8_t>> &dst) = 0;

    /**
     * @brief sign TLS digest with client's private key
     * @param dst a destination container for signature
     * @param algorithm signing algorithm
     * @param digest data to be signed
     * @return error code or OK
     */
    virtual int signTLS(std::vector<uint8_t>& dst, CryptoBackend::HashAlgorithm algorithm, const std::vector<uint8_t> &digest) {
        return NOT_IMPLEMENTED;
    }

    NetworkBackend (const NetworkBackend&) = delete;
	NetworkBackend& operator= (const NetworkBackend&) = delete;
};

struct CDOC_EXPORT DefaultNetworkBackend : public NetworkBackend {
    explicit DefaultNetworkBackend();
    ~DefaultNetworkBackend();

    int fetchKey (std::vector<uint8_t>& result, const std::string& url, const std::string& transaction_id) override final;
};

} // namespace libcdoc

#endif // NETWORKBACKEND_H
