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

    void LogMessage(libcdoc::LogLevel level, const std::string& message) override
    {
        lock_guard<mutex> guard(loggers_protector);
        for (map<int, ILogger*>::const_reference logger : loggers)
        {
            logger.second->LogMessage(level, message);
        }
    }

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

CDOC_EXPORT int libcdoc::add_logger(ILogger* logger)
{
    return logEngine.AddLogger(logger);
}

CDOC_EXPORT libcdoc::ILogger* libcdoc::remove_logger(int cookie)
{
    return logEngine.RemoveLogger(cookie);
}
