#pragma once
#include "../common.h"
#include "../api/getapi.h"
#include "../obfuscation/MetaString.h"

namespace logs {

	VOID Init(LPCWSTR LogFile);
	VOID Write(LPCWSTR Format, ...);

}