#pragma once

#include <string>

class Logger {


public:
	static void Log(const char* std, ...);
	static void Log(wchar_t* std, ...);

};