#include <iostream>
#include <fstream>
#include <stdexcept>
#include <cstddef>
#include <Windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <string>

#include "conf.h"

using std::cout;
using std::endl;
using std::ofstream;
using std::runtime_error;
using std::to_string;

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

constexpr unsigned int PROCESS_CREATED_EVENT_ID = 4688;
constexpr unsigned int PROCESS_EXITED_EVENT_ID = 4689;

struct TracePropsWithName
{
	EVENT_TRACE_PROPERTIES props;
	WCHAR sessionName[MAX_SESSION_NAME_SIZE];
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

void Trace(std::ostream &file, const std::string &msg)
{
	file << msg << endl;

	if (REFLECT_TO_STDOUT)
	{
		cout << msg << endl;
	}
}

void WINAPI EventRecordCallback(PEVENT_RECORD pEvent)
{
	cout << "Event received" << endl;
	if (pEvent == nullptr)
	{
		return;
	}

	cout << "Received event with id: " << pEvent->EventHeader.EventDescriptor.Id << endl;

	// PTRACE_EVENT_INFO pInfo;
	// ULONG bufferSize = 0;

	// // Call TdhGetEventInformation once to get the required buffer size
	// TDHSTATUS status = TdhGetEventInformation(pEvent, 0, NULL, NULL, &bufferSize);

	// if (status == ERROR_INSUFFICIENT_BUFFER)
	// {
	// 	std::unique_ptr<BYTE[]> buffer(new BYTE[bufferSize]);
	// 	PTRACE_EVENT_INFO pInfo = reinterpret_cast<PTRACE_EVENT_INFO>(buffer.get());

	// 	// Call TdhGetEventInformation a second time to get the actual event information
	// 	status = TdhGetEventInformation(pEvent, 0, NULL, pInfo, &bufferSize);

	// 	if (status != ERROR_SUCCESS){
	// 		cout << "TdhGetEventInformation initial call failed with status " << status << endl;
	// 	}

	// 	PWSTR eventName = (PWSTR)((PBYTE)pInfo + pInfo->EventNameOffset);
	// 	wprintf(L"Received event: %s\n", eventName);
	// 	// Further parsing of properties would go here, often using TdhFormatProperty
	// 	// or directly accessing the property data based on the pInfo structure.

	// }
	// else if (status != ERROR_SUCCESS)
	// {
	// 	cout << "TdhGetEventInformation initial call failed with status " << status << endl;
	// }

	unsigned long pid = pEvent->EventHeader.ProcessId;
	auto event_id = pEvent->EventHeader.EventDescriptor.Id;

	if (event_id != PROCESS_CREATED_EVENT_ID && event_id != PROCESS_EXITED_EVENT_ID)
		return;

	std::ostream *output = static_cast<std::ostream *>(pEvent->UserContext);
	std::string msg = "Event id: " + std::to_string(event_id) + "; pid: " + std::to_string(pid);
	Trace(*output, msg);
}

void CreateTraceSession(wchar_t *session_name, CONTROLTRACE_ID *traceId, TracePropsWithName *trace)
{
	ULONG bufferSize = sizeof(TracePropsWithName);
	ZeroMemory(trace, bufferSize);

	trace->props.Wnode.BufferSize = bufferSize;
	trace->props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;

	trace->props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
	trace->props.LoggerNameOffset = offsetof(TracePropsWithName, sessionName);
	;
	wcscpy_s(trace->sessionName, session_name);

	auto res = StartTraceW(traceId, session_name, &trace->props);
	if (res != ERROR_SUCCESS)
	{
		throw runtime_error("Failed starting trace session: " + to_string(res));
	}

	LPCGUID ProviderGuid = &PROVIDER_GUID;
	res = EnableTraceEx2(*traceId, (LPCGUID)&ProviderGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0, 0, 0, NULL);
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

int main()
{
	try
	{
		ofstream logFile = OpenLogFile();
		wchar_t session_name[] = SESSION_NAME;

		CONTROLTRACE_ID traceId = 0;
		TracePropsWithName trace;
		CreateTraceSession(session_name, &traceId, &trace);
		cout << "Trace session created with id: " << traceId << endl;

		PROCESSTRACE_HANDLE process_trace_handle = OpenTraceSession(session_name, static_cast<void *>(&logFile));
		cout << "Trace session opened" << endl;

		auto res = ProcessTrace(&process_trace_handle, 1, nullptr, nullptr);
		if (res != ERROR_SUCCESS)
		{
			throw runtime_error("Failed process trace session: " + to_string(res));
		}
		cout << "Trace session processed" << endl;

		logFile.close();
		ControlTraceW(traceId, session_name, &trace.props, EVENT_TRACE_CONTROL_STOP);
		CloseTrace(process_trace_handle);
	}
	catch (const std::runtime_error &e)
	{
		cout << e.what() << endl;
	}
	return 0;
}