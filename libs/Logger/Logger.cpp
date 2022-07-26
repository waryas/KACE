
#include "Logger.h"
#include <stdarg.h>
#include <windows.h>

#include <mutex>

//#include "../../dependanices/spdlog-1.8.5/include/spdlog/sinks/basic_file_sink.h"
//#include "spdlog/spdlog.h"

static bool isInit = false;

inline __declspec(align(0x1000)) static char sBuffer[1024] = { 0 };
inline __declspec(align(0x1000)) static wchar_t wBuffer[1024] = { 0 };

std::mutex logMutex;

void Logger::Log(const char* format, ...) {
    std::lock_guard<std::mutex> guard(logMutex);

    va_list args;
    va_start(args, format);
    vsprintf_s(sBuffer, format, args);
    va_end(args);

    printf("[TID:%08x]  %s", GetCurrentThreadId(), sBuffer);
    fflush(stdout);
}

void Logger::Log(wchar_t* format, ...) {
    std::lock_guard<std::mutex> guard(logMutex);

    va_list args;
    va_start(args, format);
    vswprintf_s(wBuffer, format, args);
    va_end(args);

    printf("[TID:%08x]  %ls", GetCurrentThreadId(), wBuffer);
    fflush(stdout);
}
