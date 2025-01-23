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
    LogEngine() : minLogLevel(libcdoc::LogLevelInfo), currentLoggerCookie(0) {}

    LogEngine(const LogEngine&) = delete;
    LogEngine(LogEngine&&) noexcept = delete;

    void LogMessage(libcdoc::LogLevel level, const std::string& message) override
    {
        if (level <= minLogLevel)
        {
            lock_guard<mutex> guard(loggers_protector);
            for (map<int, shared_ptr<ILogger>>::const_reference logger : loggers)
            {
                logger.second->LogMessage(level, message);
            }
        }
    }

    int AddLogger(shared_ptr<ILogger> logger)
    {
        lock_guard<mutex> guard(loggers_protector);
        loggers[++currentLoggerCookie] = logger;
        return currentLoggerCookie;
    }

    void RemoveLogger(int cookie)
    {
        lock_guard<mutex> guard(loggers_protector);
        loggers.erase(cookie);
    }

    void SetMinLogLevel(libcdoc::LogLevel level) noexcept
    {
        minLogLevel = level;
    }

private:
    // Minimum log level of messages to be logged.
    libcdoc::LogLevel minLogLevel;

    // Current Cookie value
    int currentLoggerCookie;

    // The map with registered loggers.
    map<int, shared_ptr<ILogger>> loggers;

    // Loggers map concurrency protector
    mutex loggers_protector;
};

// Global Logging Engine instance.
static LogEngine logEngine;

// It is essential to define shared functions and variables with namespace. Otherwise, the linker won't find them.

CDOC_EXPORT libcdoc::ILogger* libcdoc::Logger = &logEngine;

CDOC_EXPORT int libcdoc::add_logger(std::shared_ptr<libcdoc::ILogger> logger)
{
    return logEngine.AddLogger(logger);
}

CDOC_EXPORT void libcdoc::remove_logger(int cookie)
{
    logEngine.RemoveLogger(cookie);
}

CDOC_EXPORT void libcdoc::set_min_loglevel(libcdoc::LogLevel minLogLevel)
{
    logEngine.SetMinLogLevel(minLogLevel);
}
