#ifndef __ILOGGER_H__INCLUDED__
#define __ILOGGER_H__INCLUDED__

#include <string>
#include "Exports.h"

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

#ifndef NDEBUG
    /**
     * @brief Most verbose level. Used for development and seldom enabled in production.
     */
    LogLevelTrace
#endif
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
     * @param minLogLevel minimum level to log.
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
extern ILogger* Logger;

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


#define LOG(l,m) Logger->LogMessage((l), __FILE__, __LINE__, (m))
#define LOG_ERROR(m) Logger->LogMessage(libcdoc::LogLevelError, __FILE__, __LINE__, (m))
#define LOG_WARN(m) Logger->LogMessage(libcdoc::LogLevelWarning, __FILE__, __LINE__, (m))
#define LOG_INFO(m) Logger->LogMessage(libcdoc::LogLevelInfo, __FILE__, __LINE__, (m))
#define LOG_DBG(m) Logger->LogMessage(libcdoc::LogLevelDebug, __FILE__, __LINE__, (m))

#ifdef NDEBUG
#define LOG_TRACE(m)
#else
#define LOG_TRACE(m) Logger->LogMessage(libcdoc::LogLevelTrace, __FILE__, __LINE__, (m))
#endif

}

#endif
