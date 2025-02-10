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

#pragma once

#include <iostream>
#include "ILogger.h"

namespace libcdoc
{

class ConsoleLogger : public ILogger
{
public:
    virtual void LogMessage(libcdoc::LogLevel level, const char* file, int line, const std::string& message) override
    {
        // We ignore by default the file name and line number, and call LogMessage with the level and message.
        if (level <= minLogLevel)
        {
            std::ostream& ofs = level < LogLevelInfo ? std::cerr : std::cout;
            ofs << message << std::endl;
        }
    }
};


}
