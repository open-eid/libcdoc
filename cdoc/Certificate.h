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

#include <string>
#include <vector>

namespace libcdoc {

class CDOC_EXPORT Certificate {
public:
	enum Algorithm {
		RSA,
		ECC
	};

    std::vector<uint8_t> cert;

    Certificate(const std::vector<uint8_t>& cert) : cert(cert) {}

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
