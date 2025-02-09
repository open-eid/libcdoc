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

#include <map>
#include <mutex>
#include "Exports.h"
#include "ILogger.h"

using namespace  std;

/**
 * @brief Logging Engine implementation.
 *
 * The Logging Engine holds all instances of registered loggers and
 * logs a log message to all the instances.
 */
class LogEngine final : public libcdoc::ILogger
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

// Global Logging Engine instance.
static LogEngine logEngine;

// It is essential to define shared functions and variables with namespace. Otherwise, the linker won't find them.

CDOC_EXPORT libcdoc::ILogger* libcdoc::Logger = &logEngine;

int libcdoc::add_logger(ILogger* logger)
{
    return logEngine.AddLogger(logger);
}

libcdoc::ILogger* libcdoc::remove_logger(int cookie)
{
    return logEngine.RemoveLogger(cookie);
}
