#pragma once
#include "provider.h"

namespace Provider::CNG {
	int Initialize();
	static int Init = Provider::CNG::Initialize();

};