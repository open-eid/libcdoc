#pragma once

#include <iostream>
#include "ILogger.h"

namespace libcdoc
{

class ConsoleLogger : public ILogger
{
public:
    void LogMessage(LogLevel level, const std::string& message) override
    {
        std::ostream& ofs = level < LogLevelInfo ? std::cerr : std::cout;
        ofs << message << std::endl;
    }
};


}
