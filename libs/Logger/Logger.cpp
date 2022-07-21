
#include "Logger.h"
#include <stdarg.h>
#include <windows.h>

//#include "../../dependanices/spdlog-1.8.5/include/spdlog/sinks/basic_file_sink.h"
//#include "spdlog/spdlog.h"

static bool isInit = false;

inline __declspec(align(0x1000))  static char sBuffer[1024] = { 0 };
inline __declspec(align(0x1000)) static  wchar_t wBuffer[1024] = { 0 };

void Logger::Log(const char *format, ...) {



	
	va_list args;
	va_start(args, format);
	vprintf(format, args);
	va_end(args);
	
	
	//spdlog::info(buffer);
}


void Logger::Log(wchar_t *format, ...) {
	va_list args;
	va_start(args, format);
	vwprintf(format, args);
	va_end(args);

}
