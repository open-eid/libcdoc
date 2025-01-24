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
