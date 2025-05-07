#ifndef CELOGIN_POWERVM_TARGET
#pragma once

#include <functional>
#include <iostream>
#include <string>
namespace celogin
{
enum class LogLevel
{
    DEBUG,
    INFO,
    WARNING,
    ERROR
};
template <typename OutputStream>
class Logger
{
  public:
    Logger(LogLevel level, OutputStream& outputStream) :
        currentLogLevel(level), output(outputStream)
    {}
    template <typename T, typename... Rest>
    void print(const T& message, const Rest&... rest) const
    {
        output << message << " ";
        print(rest...);
    }
    void print() const
    {
        output << "\n";
        output.flush();
    }
    template <typename... Args>
    void log(const char* filename, int lineNumber, LogLevel level,
             const Args&... message) const
    {
        if (isLogLevelEnabled(level))
        {
            output << filename << ":" << lineNumber << " ";
            print(message...);
        }
    }

    void setLogLevel(LogLevel level)
    {
        currentLogLevel = level;
    }
    OutputStream& getOutputStream()
    {
        return output;
    }

  private:
    LogLevel currentLogLevel;
    OutputStream& output;

    bool isLogLevelEnabled(LogLevel level) const
    {
        return level >= currentLogLevel;
    }
};
struct DummyOutput
{
    template <typename T>
    DummyOutput& operator<<(const T&)
    {
        return *this;
    }
};
struct CallBackLogger
{
    std::function<void(const std::string&)> loggerFunction;
    std::string message;
    CallBackLogger& operator<<(const std::string& data)
    {
        message += data;
        return *this;
    }
    CallBackLogger& operator<<(const char* data)
    {
        message += data;
        return *this;
    }
    CallBackLogger& operator<<(bool data)
    {
        message += (data ? "true" : "false");
        return *this;
    }
    CallBackLogger& operator<<(int data)
    {
        char buffer[32];
        snprintf(buffer, sizeof(buffer), "%d", data);
        message += buffer;
        return *this;
    }

    template <typename T>
    CallBackLogger& operator<<(const T& data)
    {

        return *this;
    }
    void flush()
    {
        if (loggerFunction)
        {
            loggerFunction(message);
        }

        message = std::string(); // Clear message after logging
    }
};

inline Logger<CallBackLogger>& getLogger()
{
    static CallBackLogger callBackLogger;
    static Logger<CallBackLogger> logger(LogLevel::DEBUG, callBackLogger);
    return logger;
}

} // namespace celogin

// Macros for clients to use logger
#define CE_LOG_DEBUG(message, ...)                                             \
    celogin::getLogger().log(__FILE__, __LINE__, celogin::LogLevel::DEBUG,     \
                             "Debug :", message, ##__VA_ARGS__)
#define CE_LOG_INFO(message, ...)                                              \
    celogin::getLogger().log(__FILE__, __LINE__, celogin::LogLevel::INFO,      \
                             "Info :", message, ##__VA_ARGS__)
#define CE_LOG_WARNING(message, ...)                                           \
    celogin::getLogger().log(__FILE__, __LINE__, celogin::LogLevel::WARNING,   \
                             "Warning :", message, ##__VA_ARGS__)
#define CE_LOG_ERROR(message, ...)                                             \
    celogin::getLogger().log(__FILE__, __LINE__, celogin::LogLevel::ERROR,     \
                             "Error :", message, ##__VA_ARGS__)
#else

#ifndef _CE_LOGGER_HPP
#define _CE_LOGGER_HPP
#define CE_LOG_DEBUG(message, ...)
#define CE_LOG_INFO(message, ...)
#define CE_LOG_WARNING(message, ...)
#define CE_LOG_ERROR(message, ...)
#endif /* _CE_LOGGER_HPP */

#endif
