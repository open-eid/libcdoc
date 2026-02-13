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

#ifdef __cpp_lib_format
#include <format>
namespace fmt = std;
#else
#define FMT_HEADER_ONLY
#include "fmt/format.h"
#endif

#include <CDoc.h>

#define FORMAT fmt::format

namespace libcdoc
{

/**
 * @brief Generic interface to implement a logger.
 */
class CDOC_EXPORT ILogger
{
public:
    /**
     * @brief Logs given message with given severity, file name and line number.
     * 
     * It tests the log level and if <= min_level invokes logMessage
     * 
     * @param level Severity of the log message.
     * @param file File name where the log message was recorded.
     * @param line Line number in the file where the log message was recorded.
     * @param msg The log message.
     */
    void log(LogLevel level, std::string_view file, int line, std::string_view msg) {
        if (level <= min_level) logMessage(level, file, line, msg);
    }

    /**
     * @brief Sets minimum log level for the logger.
     * @param level minimum level to log.
     *
     * Sets minimum level of log messages to log. For example, if the minimum log level is set
     * to LogLevelInfo (default), then LogLevelFatal, LogLevelError, LogLevelWarning and LogLevelInfo
     * messages are logged, but not LogLevelDebug or LogLevelTrace messages.
     */
    void setMinLogLevel(LogLevel level) noexcept { min_level = level; }
protected:
    /**
     * @brief Logs given message with given severity, file name and line number.
     * 
     * Every class implementing the ILogger interface must implement this member function.
     * The efault implementation does nothing.
     * The level should be checked by caller, thus the implementation should expect that level <= min_level
     * 
     * @param level Severity of the log message.
     * @param file File name where the log message was recorded.
     * @param line Line number in the file where the log message was recorded.
     * @param msg The log message.
     */
    virtual void logMessage(LogLevel level, std::string_view file, int line, std::string_view msg) {}

    /**
     * @brief Minimum level of log messages to log.
     */
    LogLevel min_level = LEVEL_WARNING;
};

typedef ILogger Logger;

#ifndef SWIG
template<typename... Args>
static inline void LogFormat(LogLevel level, std::string_view file, int line, fmt::format_string<Args...> fmt, Args&&... args)
{
    auto msg = fmt::format(fmt, std::forward<Args>(args)...);
    libcdoc::log(level, file, line, msg);
}

static inline void LogFormat(LogLevel level, std::string_view file, int line, std::string_view msg)
{
    libcdoc::log(level, file, line, msg);
}
#endif

#define LOG(l,...) LogFormat((l), __FILE__, __LINE__, __VA_ARGS__)
#define LOG_ERROR(...) LogFormat(libcdoc::LEVEL_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_WARN(...) LogFormat(libcdoc::LEVEL_WARNING, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_INFO(...) LogFormat(libcdoc::LEVEL_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_DBG(...) LogFormat(libcdoc::LEVEL_DEBUG, __FILE__, __LINE__, __VA_ARGS__)

#ifdef NDEBUG
#define LOG_TRACE(...)
#define LOG_TRACE_KEY(MSG, KEY)
#else
#define LOG_TRACE(...) LogFormat(libcdoc::LEVEL_TRACE, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_TRACE_KEY(MSG, KEY) LogFormat(libcdoc::LEVEL_TRACE, __FILE__, __LINE__, MSG, toHex(KEY))
#endif

}

#endif
