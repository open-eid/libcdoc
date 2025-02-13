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
class LogEngine final : public ILogger
{
public:
    LogEngine() : currentLoggerCookie(0) {}

    LogEngine(const LogEngine&) = delete;
    LogEngine(LogEngine&&) noexcept = delete;

    void LogMessage(libcdoc::LogLevel level, const char* file, int line, const std::string& message) override
    {
        lock_guard<mutex> guard(loggers_protector);
        for (map<int, ILogger*>::const_reference logger : loggers)
        {
            logger.second->LogMessage(level, file, line, message);
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

private:
    // Current Cookie value
    int currentLoggerCookie;

    // The map with registered loggers.
    map<int, ILogger*> loggers;

    // Loggers map concurrency protector
    mutex loggers_protector;
};

// Default logger's instance - Logging Engine instance.
static LogEngine defaultLogEngine;

// Currentlty used logger's instance.
static ILogger* cdoc_logger = &defaultLogEngine;

// It is essential to define shared functions and variables with namespace. Otherwise, the linker won't find them.

int STDCALL add_logger(ILogger* logger)
{
    return defaultLogEngine.AddLogger(logger);
}

ILogger* STDCALL remove_logger(int cookie)
{
    return defaultLogEngine.RemoveLogger(cookie);
}

ILogger* STDCALL get_logger()
{
    return cdoc_logger;
}

}
