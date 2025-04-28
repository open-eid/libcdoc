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

#include "Crypto.h"
#include "CryptoBackend.h"
#include "ILogger.h"
#include "Utils.h"

#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/rand.h>

namespace libcdoc {

std::string
CryptoBackend::getLastErrorStr(result_t code) const
{
	switch (code) {
    case OK:
		return "";
	case NOT_IMPLEMENTED:
		return "CryptoBackend: Method not implemented";
	case INVALID_PARAMS:
		return "CryptoBackend: Invalid parameters";
	case OPENSSL_ERROR:
		return "CryptoBackend: OpenSSL error";
	default:
		break;
	}
	return "Internal error";
}

libcdoc::result_t
CryptoBackend::random(std::vector<uint8_t>& dst, unsigned int size)
{
	dst.resize(size);
	int result = RAND_bytes(dst.data(), size);
    return (result < 0) ? OPENSSL_ERROR : OK;
}

libcdoc::result_t
CryptoBackend::deriveConcatKDF(std::vector<uint8_t>& dst, const std::vector<uint8_t> &publicKey, const std::string &digest,
							   const std::vector<uint8_t> &algorithmID, const std::vector<uint8_t> &partyUInfo, const std::vector<uint8_t> &partyVInfo,
                               unsigned int idx)
{
	std::vector<uint8_t> shared_secret;
    int result = deriveECDH1(shared_secret, publicKey, idx);
    if (result != OK) return result;
	dst = libcdoc::Crypto::concatKDF(digest, ECC_KEY_LEN, shared_secret, algorithmID, partyUInfo, partyVInfo);
    return (dst.empty()) ? OPENSSL_ERROR : OK;
}

libcdoc::result_t
CryptoBackend::deriveHMACExtract(std::vector<uint8_t>& dst, const std::vector<uint8_t> &public_key, const std::vector<uint8_t> &salt, unsigned int idx)
{
	std::vector<uint8_t> shared_secret;
    int result = deriveECDH1(shared_secret, public_key, idx);
    if (result != OK) return result;
	dst = libcdoc::Crypto::extract(shared_secret, salt);
    return (dst.empty()) ? OPENSSL_ERROR : OK;
}

libcdoc::result_t
CryptoBackend::getKeyMaterial(std::vector<uint8_t>& key_material, const std::vector<uint8_t>& pw_salt, int32_t kdf_iter, unsigned int idx)
{
	if (kdf_iter > 0) {
		if (pw_salt.empty()) return INVALID_PARAMS;
		std::vector<uint8_t> secret;
        int result = getSecret(secret, idx);
		if (result < 0) return result;

        LOG_DBG("Secret: {}", toHex(secret));

		key_material = libcdoc::Crypto::pbkdf2_sha256(secret, pw_salt, kdf_iter);
		std::fill(secret.begin(), secret.end(), 0);
		if (key_material.empty()) return OPENSSL_ERROR;
	} else {
        int result = getSecret(key_material, idx);
		if (result < 0) return result;
        LOG_DBG("Secret: {}", toHex(key_material));
        if (key_material.size() != 32) {
            return INVALID_PARAMS;
        }
	}

    LOG_DBG("Key material: {}", toHex(key_material));

    return OK;
}

libcdoc::result_t
CryptoBackend::extractHKDF(std::vector<uint8_t>& kek_pm, const std::vector<uint8_t>& salt, const std::vector<uint8_t>& pw_salt,
                           int32_t kdf_iter, unsigned int idx)
{
	if (salt.empty()) return INVALID_PARAMS;
	if ((kdf_iter > 0) && pw_salt.empty()) return INVALID_PARAMS;
	std::vector<uint8_t> key_material;
    int result = getKeyMaterial(key_material, pw_salt, kdf_iter, idx);
	if (result) return result;
	kek_pm = libcdoc::Crypto::extract(key_material, salt);
	std::fill(key_material.begin(), key_material.end(), 0);
	if (kek_pm.empty()) return OPENSSL_ERROR;

    LOG_TRACE_KEY("Extract: {}", kek_pm);

    return OK;
}

} // namespace libcdoc
