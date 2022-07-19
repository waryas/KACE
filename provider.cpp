#include "libs/PEMapper/pefile.h"
#include "provider.h"
#include <stdio.h>
#include <spdlog/spdlog.h>

extern const char* prototypedMsg = "\033[38;5;46mPrototyped\033[0m";
extern const char* passthroughMsg = "\033[38;5;11mPassthrough\033[0m";
extern const char* notimplementedMsg = "\033[38;5;9mNot Implemented\033[0m";

uint64_t unimplemented_stub() {
	spdlog::warn("\t\t\033[38;5;9mINSIDE STUB, RETURNING 0\033[0m");
	return 0;
}