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

#ifndef SSLCERTIFICATE_H
#define SSLCERTIFICATE_H

#include "Exports.h"

#include "utils/memory.h"

#include <string>
#include <vector>

using X509 = struct x509_st;

namespace libcdoc {

class Certificate {
public:
	enum Algorithm {
		RSA,
		ECC
	};

    unique_free_t<X509> cert;

    explicit Certificate(const std::vector<uint8_t>& cert) noexcept;

	std::string getCommonName() const;
	std::string getGivenName() const;
	std::string getSurname() const;
    std::string getSerialNumber() const;

	std::vector<std::string> policies() const;

	std::vector<uint8_t> getPublicKey() const;
    Algorithm getAlgorithm() const;

    std::vector<uint8_t> getDigest();
};

} // Namespace

#endif // SSLCERTIFICATE_H
