#pragma once

#include <initguid.h>

#define LOG_FILE ("procmon.log")
#define SESSION_NAME (L"KERNEL_LOGGER_NAME")
constexpr int MAX_SESSION_NAME_SIZE = 1024;
constexpr bool REFLECT_TO_STDOUT = true;

DEFINE_GUID(
    PROVIDER_GUID,
    0x22FB2CD6, 0x0E7B, 0x422B, 0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16 // microsoft-windows-kernel-process 
);

DEFINE_GUID(
    TCPIP_PROVIDER_GUID,
	0x2F07E2EE, 0x15DB, 0x40F1, 0x90, 0xEF, 0x9D, 0x7B, 0xA2, 0x82, 0x18, 0x8A // microsoft-windows-tcpip
);