#include "libs/PEMapper/pefile.h"
#include "libs/Logger/Logger.h"

#include "provider.h"
#include <stdio.h>


extern const char* prototypedMsg = "\033[38;5;46mPrototyped\033[0m\n";
extern const char* passthroughMsg = "\033[38;5;11mPassthrough\033[0m\n";
extern const char* notimplementedMsg = "\033[38;5;9mNot Implemented\033[0m\n";

inline __declspec(align(0x1000)) const HMODULE ntdll = LoadLibraryA("ntdll.dll");

uint64_t unimplemented_stub() {
	Logger::Log("\t\t\033[38;5;9mINSIDE STUB, RETURNING 0\033[0m\n");
	return 0;
}