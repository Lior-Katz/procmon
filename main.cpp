#include <iostream>
#include <fstream>
#include <stdexcept>
#include <cstddef>
#include <Windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <string>
#include <psapi.h>
#include <regex>
#include <unordered_map>
#include <winternl.h>
#include "conf.h"

using std::cout;
using std::endl;
using std::ofstream;
using std::runtime_error;
using std::string;
using std::to_string;
using std::vector;

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

#define INVALID_PROC_NAME "[FIND PROCESS NAME FAILED]"

constexpr unsigned int PROCESS_CREATED_EVENT_ID = 1;
constexpr unsigned int PROCESS_EXITED_EVENT_ID = 2;
constexpr unsigned int WAIT_REASON_SUSPENDED = 5;


std::unordered_map<ULONG, string> procDict; // PID -> Process Name

struct TracePropsWithName
{
	EVENT_TRACE_PROPERTIES props;
	WCHAR sessionName[MAX_SESSION_NAME_SIZE];
};

struct TraceContext
{
	std::ostream *output;
	string procNameRegex;
};

typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

typedef struct _VM_COUNTERS_EX
{
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivateUsage;
} VM_COUNTERS_EX, * PVM_COUNTERS_EX;

typedef struct _system_thread_information_t
{                                    /* win32/win64 */
	LARGE_INTEGER KernelTime;          /* 00/00 */
	LARGE_INTEGER UserTime;            /* 08/08 */
	LARGE_INTEGER CreateTime;          /* 10/10 */
	DWORD         dwTickCount;         /* 18/18 */
	LPVOID        StartAddress;        /* 1c/20 */
	CLIENT_ID     ClientId;            /* 20/28 */
	DWORD         dwCurrentPriority;   /* 28/38 */
	DWORD         dwBasePriority;      /* 2c/3c */
	DWORD         dwContextSwitches;   /* 30/40 */
	DWORD         dwThreadState;       /* 34/44 */
	DWORD         dwWaitReason;        /* 38/48 */
	DWORD         dwUnknown;           /* 3c/4c */
} system_thread_information_t, * p_system_thread_information_t;


typedef struct _system_process_information_t {
//#ifdef __WINESRC__                  /* win32/win64 */
	ULONG NextEntryOffset;             /* 00/00 */
	DWORD dwThreadCount;               /* 04/04 */
	LARGE_INTEGER WorkingSetPrivateSize; /* 08/08 */
	ULONG HardFaultCount;              /* 10/10 */
	ULONG NumberOfThreadsHighWatermark;/* 14/14 */
	ULONGLONG CycleTime;               /* 18/18 */
	LARGE_INTEGER CreationTime;        /* 20/20 */
	LARGE_INTEGER UserTime;            /* 28/28 */
	LARGE_INTEGER KernelTime;          /* 30/30 */
	UNICODE_STRING ProcessName;        /* 38/38 */
	DWORD dwBasePriority;              /* 40/48 */
	HANDLE UniqueProcessId;            /* 44/50 */
	HANDLE ParentProcessId;            /* 48/58 */
	ULONG HandleCount;                 /* 4c/60 */
	ULONG SessionId;                   /* 50/64 */
	ULONG_PTR UniqueProcessKey;        /* 54/68 */
	VM_COUNTERS_EX vmCounters;         /* 58/70 */
	IO_COUNTERS ioCounters;            /* 88/d0 */
	system_thread_information_t threadInfo[1];   /* b8/100 */
} system_process_information_t, * p_system_process_information_t;

ofstream OpenLogFile()
{
	ofstream file(LOG_FILE);

	if (!file.is_open())
	{
		throw runtime_error("Unable to open log file");
	}

	return file;
}

void Trace(std::ostream &file, const string &msg)
{
	file << msg << endl;

	if (REFLECT_TO_STDOUT)
	{
		cout << msg << endl;
	}
}

NtQuerySystemInformation_t LoadNtQuerySystemInformation()
{
	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
	if (!hNtdll)
	{
		hNtdll = LoadLibraryW(L"ntdll.dll");
		if (!hNtdll)
		{
			std::cerr << "Failed to load ntdll.dll\n";
			throw runtime_error("Failed to load ntdll.dll");
		}
	}

	auto func = reinterpret_cast<NtQuerySystemInformation_t>(
		GetProcAddress(hNtdll, "NtQuerySystemInformation")
		);

	if (!func)
	{
		std::cerr << "Failed to resolve NtQuerySystemInformation\n";
		throw runtime_error("Failed to resolve NtQuerySystemInformation");
	}

	return func;
}

bool IsProcessSuspended(DWORD pid)
{
	NtQuerySystemInformation_t NtQuerySystemInformation = LoadNtQuerySystemInformation();
	unsigned long returnLength = 0;
	NtQuerySystemInformation(SystemProcessInformation, nullptr, 0, &returnLength);

	std::vector<BYTE> buffer(returnLength);
	NTSTATUS status = NtQuerySystemInformation(SystemProcessInformation, buffer.data(), returnLength, &returnLength);
	if (!NT_SUCCESS(status))
	{
		throw runtime_error("Failed querying system information to check if process is suspended");
	}
	system_process_information_t* pInfo = reinterpret_cast<system_process_information_t*>(buffer.data());
	while (true)
	{
		if ((DWORD)(uintptr_t)pInfo->UniqueProcessId == pid)
		{
			break;
		}
		if (pInfo->NextEntryOffset == 0)
			throw runtime_error("Process not found when checking if it's suspended");
		pInfo = reinterpret_cast<system_process_information_t*>(reinterpret_cast<BYTE*>(pInfo) + pInfo->NextEntryOffset);
	}

	// iterate threads to find if any of them are not suspended
	bool suspended = true;
	for (DWORD i = 0; i < pInfo->dwThreadCount; i++) {
		system_thread_information_t threadInfo = pInfo->threadInfo[i];
		if (threadInfo.dwWaitReason != WAIT_REASON_SUSPENDED)
		{
			suspended = false;
		}
	}
	return suspended;
}

string GetProcNameByPid(DWORD pid, HANDLE hProcess)
{
	char buffer[MAX_PATH] = {0};
	DWORD size = MAX_PATH;

	if (QueryFullProcessImageNameA(hProcess, 0, buffer, &size))
	{
		string fullPath(buffer);

		// Extract file name only
		size_t pos = fullPath.find_last_of("\\/");
		return (pos != string::npos) ? fullPath.substr(pos + 1) : fullPath;
	}

	DWORD error = GetLastError();

	return INVALID_PROC_NAME;
}

ULONG GetPidFromEvent(PEVENT_RECORD pEvent)
{
	ULONG resultPid = pEvent->EventHeader.ProcessId; // fallback

	ULONG bufferSize = 0;
	TDHSTATUS status = TdhGetEventInformation(pEvent, 0, nullptr, nullptr, &bufferSize);

	if (status != ERROR_INSUFFICIENT_BUFFER)
	{
		return resultPid;
	}

	std::unique_ptr<BYTE[]> buffer(new BYTE[bufferSize]);
	PTRACE_EVENT_INFO pInfo = reinterpret_cast<PTRACE_EVENT_INFO>(buffer.get());

	status = TdhGetEventInformation(pEvent, 0, nullptr, pInfo, &bufferSize);
	if (status != ERROR_SUCCESS)
	{
		return resultPid;
	}

	for (USHORT i = 0; i < pInfo->TopLevelPropertyCount; i++)
	{
		PWSTR propName = (PWSTR)((PBYTE)pInfo + pInfo->EventPropertyInfoArray[i].NameOffset);

		if (_wcsicmp(propName, L"ProcessID") == 0)
		{
			ULONG pid = 0;
			PROPERTY_DATA_DESCRIPTOR propDesc = {};
			propDesc.PropertyName = (ULONGLONG)L"ProcessID";
			propDesc.ArrayIndex = ULONG_MAX;

			TDHSTATUS status = TdhGetProperty(
				pEvent,
				0,
				nullptr,
				1,
				&propDesc,
				sizeof(pid),
				(PBYTE)&pid);

			if (status == ERROR_SUCCESS)
			{
				resultPid = pid;
			}
		}
	}

	return resultPid;
}

bool FilterProcName(string procName, string procNameRegex)
{
	try
	{
		std::regex pattern(procNameRegex, std::regex_constants::icase);

		return std::regex_match(procName, pattern);
	}
	catch (const std::regex_error &)
	{
		// invalid regex == no match
		return false;
	}
}

void LogLoadedDlls(ULONG pid, std::ostream &file, HANDLE hProcess)
{
	HMODULE modulesArr[MAX_DLL_ARR_SIZE];
	DWORD bytesNeeded;
	if (EnumProcessModulesEx(hProcess, modulesArr, sizeof(modulesArr), &bytesNeeded, LIST_MODULES_ALL) == 0)
	{
		Trace(file, "Error in EnumProcessModules: " + to_string(GetLastError()));
		return;
	}
	if (bytesNeeded > sizeof(modulesArr))
	{
		Trace(file, "Error in EnumProcessModules: There are too many modules loaded");
		return;
	}

	for (HMODULE modHandle : modulesArr)
	{
		char dllName[MAX_DLL_NAME_SIZE];
		if (GetModuleFileNameA(modHandle, dllName, MAX_DLL_NAME_SIZE) == 0 && GetLastError() != ERROR_MOD_NOT_FOUND)
		{
			Trace(file, "Error in GetModuleFileNameA: " + to_string(GetLastError()));
			return;
		}

		if (GetLastError() != ERROR_MOD_NOT_FOUND)
		{
			Trace(file, string("Loaded DLL Name: ") + dllName);
		}
	}
}

VOID WINAPI ProcessEventRecordCallback(PEVENT_RECORD pEvent)
{
	if (pEvent == nullptr)
	{
		return;
	}

	TraceContext *ctx = static_cast<TraceContext *>(pEvent->UserContext);
	if (!ctx)
		return;

	ULONG pid = GetPidFromEvent(pEvent);
	auto eventId = pEvent->EventHeader.EventDescriptor.Id;

	if (eventId != PROCESS_CREATED_EVENT_ID && eventId != PROCESS_EXITED_EVENT_ID)
		return;

	std::ostream *output = static_cast<std::ostream *>(ctx->output);

	HANDLE hProcess = NULL;
	string procName;
	if (eventId != PROCESS_EXITED_EVENT_ID)
	{
		hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
		if (hProcess == NULL)
		{
			if (GetLastError() != ERROR_INVALID_PARAMETER) { // skip invalid pid
				Trace(*output, "Error in OpenProcess: " + to_string(GetLastError()));
			}
			procDict[pid] = INVALID_PROC_NAME;
			return;
		}

		procName = GetProcNameByPid(pid, hProcess);
		procDict[pid] = procName;
	}
	else
	{
		auto it = procDict.find(pid);
		if (it != procDict.end())
		{
			procName = it->second;
			procDict.erase(it);
		}
	}

	if (procName == INVALID_PROC_NAME) {
		return;
	}

	if (!procName.empty() && FilterProcName(procName, ctx->procNameRegex))
	{
		bool isSuspended = eventId == PROCESS_CREATED_EVENT_ID && IsProcessSuspended(pid);
		string msg = (eventId == PROCESS_CREATED_EVENT_ID) ? "[+]" : "[-]";
		msg += " PID: " + to_string(pid) + "; Process Name: " + procName + (isSuspended ? " [SUSPENDED]" : "");
		Trace(*output, msg);

		if (eventId == PROCESS_CREATED_EVENT_ID && !isSuspended)
		{
			Trace(*output, "------------------ Loaded DLLs for " + procName + " ------------------");
			LogLoadedDlls(pid, *output, hProcess);
			Trace(*output, "-----------------------------------------------------------");
		}
	}
	CloseHandle(hProcess);
}

VOID WINAPI EventRecordCallback(const PEVENT_RECORD pEvent)
{
	if (!pEvent)
		return;
	try
	{
		if (IsEqualGUID(pEvent->EventHeader.ProviderId, PROCESS_PROVIDER_GUID))
		{
			ProcessEventRecordCallback(pEvent);
		}
	}
	catch (const runtime_error& e)
	{
		cout << e.what();
		// should keep running.
	}
}

CONTROLTRACE_ID CreateTraceSession(wchar_t *session_name, TracePropsWithName *trace, const vector<LPCGUID>& providers)
{
	ULONG bufferSize = sizeof(TracePropsWithName);
	ZeroMemory(trace, bufferSize);

	trace->props.Wnode.BufferSize = bufferSize;
	trace->props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;

	trace->props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
	trace->props.LoggerNameOffset = offsetof(TracePropsWithName, sessionName);
	wcscpy_s(trace->sessionName, session_name);

	auto res = ControlTraceW(0, session_name, &trace->props, EVENT_TRACE_CONTROL_STOP);
	if (res != ERROR_SUCCESS)
	{
		throw runtime_error("Failed closing old trace session: " + to_string(res));
	}
	CONTROLTRACE_ID traceId = 0;
	res = StartTraceW(&traceId, session_name, &trace->props);
	if (res != ERROR_SUCCESS)
	{
		throw runtime_error("Failed starting trace session: " + to_string(res));
	}

	for (const auto& provider : providers)
	{
		res = EnableTraceEx2(traceId, provider, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0, 0, 0, NULL);
		if (res != ERROR_SUCCESS)
		{
			throw runtime_error("Failed enabling trace provider: " + to_string(res));
		}
	}
	return traceId;
}

PROCESSTRACE_HANDLE OpenTraceSession(wchar_t *session_name, void *context)
{
	EVENT_TRACE_LOGFILE Logfile;
	ZeroMemory(&Logfile, sizeof(Logfile));
	Logfile.LogFileName = nullptr;
	Logfile.LoggerName = session_name;
	Logfile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
	Logfile.EventRecordCallback = EventRecordCallback;
	Logfile.Context = context;
	auto trace_handle = OpenTraceW(&Logfile);
	if (trace_handle == INVALID_PROCESSTRACE_HANDLE)
	{
		throw runtime_error("Failed opening trace session");
	}
	return trace_handle;
}

int main(int argc, char *argv[])
{
	try
	{
		if (argc < 2)
		{
			std::cout << "Usage: procmon.exe <Process Regex>" << std::endl;
			return 1;
		}

		string procNameRegex = argv[1];
		ofstream logFile = OpenLogFile();

		TraceContext context;
		context.output = &logFile;
		context.procNameRegex = procNameRegex;

		wchar_t session_name[] = SESSION_NAME;
		const vector<LPCGUID> providers{const_cast<LPGUID>(&PROCESS_PROVIDER_GUID)};

		TracePropsWithName trace;

		CONTROLTRACE_ID traceId = CreateTraceSession(session_name, &trace, providers);
		cout << "Trace session created with id: " << traceId << endl;

		PROCESSTRACE_HANDLE process_trace_handle = OpenTraceSession(session_name, static_cast<void *>(&context));
		cout << "Trace session opened" << endl;

		cout << "-------------------------- Process Monitor -------------------------------" << endl;
		auto res = ProcessTrace(&process_trace_handle, 1, nullptr, nullptr);
		if (res != ERROR_SUCCESS)
		{
			throw runtime_error("Failed process trace session: " + to_string(res));
		}
		cout << "Trace session processed" << endl;

		logFile.close();
		res = ControlTraceW(traceId, session_name, &trace.props, EVENT_TRACE_CONTROL_STOP);
		if (res != ERROR_SUCCESS)
		{
			throw runtime_error("Failed closing trace session: " + to_string(res));
		}
		res = CloseTrace(process_trace_handle);
		if (res != ERROR_SUCCESS)
		{
			throw runtime_error("Faild closing process trace session" + to_string(res));
		}
	}
	catch (const std::runtime_error &e)
	{
		cout << e.what() << endl;
	}
	return 0;
}