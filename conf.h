#pragma once

#include <initguid.h>

#define LOG_FILE ("procmon.log")
#define SESSION_NAME (L"ProcessMonitorSession")
constexpr int MAX_SESSION_NAME_SIZE = 1024;
constexpr bool REFLECT_TO_STDOUT = true;

DEFINE_GUID(
    PROVIDER_GUID,
    0x22FB2CD6, 0x0E7B, 0x422B, 0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16 // microsoft-windows-kernel-process 
);
//DEFINE_GUID(
//    PROVIDER_GUID,
//    0x1C95126E, 0x7EEA, 0x49A9, 0xA3, 0xFE, 0xA3, 0x78, 0xB0, 0x3D, 0xDB, 0x4D
//);
