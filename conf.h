#pragma once

#include <initguid.h>

#define LOG_FILE ("procmon.log")
#define SESSION_NAME (L"KERNEL_LOGGER_NAME")

constexpr int MAX_SESSION_NAME_SIZE = 1024;
constexpr bool REFLECT_TO_STDOUT = true;
constexpr int MAX_DLL_NAME_SIZE = 1024;
constexpr int MAX_DLL_ARR_SIZE = 1024;

DEFINE_GUID(
    PROCESS_PROVIDER_GUID,
    0x22FB2CD6, 0x0E7B, 0x422B, 0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16 // microsoft-windows-kernel-process 
);
