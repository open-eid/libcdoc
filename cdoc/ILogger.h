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

#ifndef __ILOGGER_H__INCLUDED__
#define __ILOGGER_H__INCLUDED__

#include <cdoc/Exports.h>

#include <string>

#ifdef __GNUC__
#define FMT_HEADER_ONLY
#include "fmt/format.h"
#define FORMAT fmt::format
#else
#define FORMAT std::format
#endif

namespace libcdoc
{

/**
 * @brief Log-level enumeration to indicate severity of the log message.
 */
enum LogLevel
{
    /**
     * @brief Most critical level. Application is about to abort.
     */
    LogLevelFatal,

    /**
     * @brief Errors where functionality has failed or an exception have been caught.
     */
    LogLevelError,

    /**
     * @brief Warnings about validation issues or temporary failures that can be recovered.
     */
    LogLevelWarning,

    /**
     * @brief Information that highlights progress or application lifetime events.
     */
    LogLevelInfo,

    /**
     * @brief Debugging the application behavior from internal events of interest.
     */
    LogLevelDebug,

    /**
     * @brief Most verbose level. Used for development, NOP in production code.
     */
    LogLevelTrace
};


/**
 * @brief Generic interface to implement a logger.
 */
class CDOC_EXPORT ILogger
{
public:
    ILogger() : minLogLevel(LogLevelWarning) {}
    virtual ~ILogger() {}

    /**
     * @brief Logs given message with given severity, file name and line number.
     * @param level Severity of the log message.
     * @param file File name where the log message was recorded.
     * @param line Line number in the file where the log message was recorded.
     * @param message The log message.
     *
     * Every class implementing the ILogger interface must implement the member function.
     * Default implementation does nothing.
     */
    virtual void LogMessage(LogLevel level, const char* file, int line, const std::string& message) {}

    /**
     * @brief Returns current minimum log level of the logger.
     * @return Minimum log level.
     */
    LogLevel GetMinLogLevel() const noexcept { return minLogLevel; }

    /**
     * @brief Sets minimum log level for the logger.
     * @param level minimum level to log.
     *
     * Sets minimum level of log messages to log. For example, if the minimum log level is set
     * to LogLevelInfo (default), then LogLevelFatal, LogLevelError, LogLevelWarning and LogLevelInfo
     * messages are logged, but not LogLevelDebug or LogLevelTrace messages.
     */
    void SetMinLogLevel(LogLevel level) noexcept { minLogLevel = level; }

protected:
    /**
     * @brief Minimum level of log messages to log.
     */
    LogLevel minLogLevel;
};


/**
 * @brief Global logger's instance.
 */
CDOC_EXPORT extern ILogger* Logger;

/**
 * @brief Adds ILogger implementation to logging queue.
 * @param logger Logger's instance to be added.
 * @return Unique cookie identifying the logger's instance in the logging queue.
 */
CDOC_EXPORT int add_logger(ILogger* logger);

/**
 * @brief Removes logger's instance from the logging queue.
 * @param cookie Unique cookie returned by the add_logger function when the logger was added.
 * @return Pointer to ILogger object that is removed. It's up to user to free the resources.
 */
CDOC_EXPORT ILogger* remove_logger(int cookie);


#define LOG(l,...) Logger->LogMessage((l), __FILE__, __LINE__, FORMAT(__VA_ARGS__))
#define LOG_ERROR(...) Logger->LogMessage(libcdoc::LogLevelError, __FILE__, __LINE__, FORMAT(__VA_ARGS__))
#define LOG_WARN(...) Logger->LogMessage(libcdoc::LogLevelWarning, __FILE__, __LINE__, FORMAT(__VA_ARGS__))
#define LOG_INFO(...) Logger->LogMessage(libcdoc::LogLevelInfo, __FILE__, __LINE__, FORMAT(__VA_ARGS__))
#define LOG_DBG(...) Logger->LogMessage(libcdoc::LogLevelDebug, __FILE__, __LINE__, FORMAT(__VA_ARGS__))

#ifdef NDEBUG
#define LOG_TRACE(m)
#else
#define LOG_TRACE(...) Logger->LogMessage(libcdoc::LogLevelTrace, __FILE__, __LINE__, FORMAT(__VA_ARGS__))
#endif

}

#endif
