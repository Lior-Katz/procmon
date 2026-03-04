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

#include "conf.h"

using std::cout;
using std::endl;
using std::ofstream;
using std::runtime_error;
using std::string;
using std::to_string;

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

constexpr unsigned int PROCESS_CREATED_EVENT_ID = 1;
constexpr unsigned int PROCESS_EXITED_EVENT_ID = 2;

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

string GetProcNameByPid(DWORD pid)
{
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (!hProcess)
	{
		return "GET PROC NAME FAILED";
	}

	char buffer[MAX_PATH] = {0};
	DWORD size = MAX_PATH;

	if (QueryFullProcessImageNameA(hProcess, 0, buffer, &size))
	{
		CloseHandle(hProcess);

		string fullPath(buffer);

		// Extract file name only
		size_t pos = fullPath.find_last_of("\\/");
		return (pos != string::npos) ? fullPath.substr(pos + 1) : fullPath;
	}

	DWORD error = GetLastError();
	CloseHandle(hProcess);

	return "GET PROC NAME FAILED";
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
	catch (const std::regex_error &e)
	{
		// invalid regex == no match
		return false;
	}
}

VOID WINAPI EventRecordCallback(PEVENT_RECORD pEvent)
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
	
	string procName;
	if (eventId != PROCESS_EXITED_EVENT_ID){
		procName = GetProcNameByPid(pid);
		procDict[pid] = procName;
	} else {
		auto it = procDict.find(pid);
		if (it != procDict.end())
		{
			procName = it->second;
			procDict.erase(it);
		}
	}

	if (!procName.empty() && FilterProcName(procName, ctx->procNameRegex))
	{
		string msg = (eventId == PROCESS_CREATED_EVENT_ID) ? "[+]" : "[-]";
		msg += " PID: " + to_string(pid) + "; Process Name: " + procName;
		Trace(*output, msg);
	}
}

void CreateTraceSession(wchar_t *session_name, CONTROLTRACE_ID *traceId, TracePropsWithName *trace)
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
	res = StartTraceW(traceId, session_name, &trace->props);
	if (res != ERROR_SUCCESS)
	{
		throw runtime_error("Failed starting trace session: " + to_string(res));
	}

	res = EnableTraceEx2(*traceId, (LPCGUID)&PROVIDER_GUID, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0, 0, 0, NULL);
	if (res != ERROR_SUCCESS)
	{
		throw runtime_error("Failed enabling trace provider: " + to_string(res));
	}
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
			std::cout << "Usage: procmon.exe <process regex>" << std::endl;
			return 1;
		}

		string procNameRegex = argv[1];
		ofstream logFile = OpenLogFile();

		TraceContext context;
		context.output = &logFile;
		context.procNameRegex = procNameRegex;

		wchar_t session_name[] = SESSION_NAME;

		CONTROLTRACE_ID traceId = 0;
		TracePropsWithName trace;

		CreateTraceSession(session_name, &traceId, &trace);
		cout << "Trace session created with id: " << traceId << endl;

		PROCESSTRACE_HANDLE process_trace_handle = OpenTraceSession(session_name, static_cast<void *>(&context));
		cout << "Trace session opened" << endl;

		cout << "--------------------------------------" << endl;
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