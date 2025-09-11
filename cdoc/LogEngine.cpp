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

#include "ILogger.h"

#include <map>
#include <mutex>

using namespace  std;

namespace libcdoc
{
/**
 * @brief Logging Engine implementation.
 *
 * The Logging Engine holds all instances of registered loggers and
 * logs a log message to all the instances.
 */
struct LogEngine final : public ILogger
{
    void LogMessage(libcdoc::ILogger::LogLevel level, std::string_view file, int line, std::string_view message) final
    {
        lock_guard<mutex> guard(loggers_protector);
        for (const auto &[_, logger] : loggers)
        {
            logger->LogMessage(level, file, line, message);
        }
    }

    int AddLogger(ILogger* logger)
    {
        lock_guard<mutex> guard(loggers_protector);
        loggers[++currentLoggerCookie] = logger;
        return currentLoggerCookie;
    }

    ILogger* RemoveLogger(int cookie)
    {
        lock_guard<mutex> guard(loggers_protector);
        ILogger* tmp = loggers[cookie];
        loggers.erase(cookie);
        return tmp;
    }

    void setLogger(ILogger *logger) {
        lock_guard<mutex> guard(loggers_protector);
        while (!loggers.empty()) {
            delete loggers.begin()->second;
            loggers.erase(loggers.begin()->first);
        }
        loggers[0] = logger;
    }

private:
    // Current Cookie value
    int currentLoggerCookie = 0;

    // The map with registered loggers.
    map<int, ILogger*> loggers;

    // Loggers map concurrency protector
    mutex loggers_protector;
};

// Default logger's instance - Logging Engine instance.
static LogEngine defaultLogEngine;

// It is essential to define shared functions and variables with namespace. Otherwise, the linker won't find them.

int
ILogger::addLogger(ILogger* logger)
{
    return defaultLogEngine.AddLogger(logger);
}

ILogger*
ILogger::removeLogger(int cookie)
{
    return defaultLogEngine.RemoveLogger(cookie);
}

ILogger*
ILogger::getLogger()
{
    return &defaultLogEngine;
}

void
ILogger::setLogger(ILogger *logger)
{
    defaultLogEngine.setLogger(logger);
}


}
