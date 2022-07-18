#pragma once

#include <inttypes.h>

#define STUB_UNIMPLEMENTED 1//If you define this, every non prototyped function will return 0 instead of exiting

extern const char* prototypedMsg;
extern const char* passthroughMsg;
extern const char* notimplementedMsg;


void custom_printf(const char* buffer, ...);


#define printf(x,...) custom_printf(x, __VA_ARGS__)
uint64_t unimplemented_stub();


#define MONITOR_DATA_ACCESS