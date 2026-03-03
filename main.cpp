#include <iostream>
#include <Windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <string>

#include "utils.h"
#include "conf.h"

using std::runtime_error;
using std::cout;
using std::endl;
using std::ofstream;

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

constexpr unsigned int PROCESS_CREATED_EVENT_ID = 4688;
constexpr unsigned int PROCESS_EXITED_EVENT_ID = 4689;
constexpr LPCSTR SESSION_NAME = "MySession";

struct TracePropsWithName
{
	EVENT_TRACE_PROPERTIES props;
	WCHAR sessionName[MAX_SESSION_NAME_SIZE];
};

std::ofstream OpenLogFile()
{
	std::ofstream file(LOG_FILE);

	if (!file.is_open())
	{
		throw runtime_error("Unable to open log file");
	}

	return file;
}

void Trace(std::ostream& file, const std::string& msg)
{
	file << msg << std::endl;

	if (REFLECT_TO_STDOUT)
	{
		std::cout << msg << std::endl;
	}
}

void EventRecordCallback(PEVENT_RECORD pEvent)
{
	if (pEvent == nullptr) {
		return;
	}

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
	// 		std::cout << "TdhGetEventInformation initial call failed with status " << status << std::endl;
	// 	}
		
	// 	PWSTR eventName = (PWSTR)((PBYTE)pInfo + pInfo->EventNameOffset);
	// 	wprintf(L"Received event: %s\n", eventName);
	// 	// Further parsing of properties would go here, often using TdhFormatProperty
	// 	// or directly accessing the property data based on the pInfo structure.
		
	// }
	// else if (status != ERROR_SUCCESS)
	// {
	// 	std::cout << "TdhGetEventInformation initial call failed with status " << status << std::endl;
	// }

	unsigned long pid = pEvent->EventHeader.ProcessId;
	auto event_id = pEvent->EventHeader.EventDescriptor.Id;

	if (event_id != PROCESS_CREATED_EVENT_ID  && event_id != PROCESS_EXITED_EVENT_ID)
	{
		return;
	}
	
	std::ostream *output = static_cast<std::ostream *>(pEvent->UserContext);
	std::string msg = "Event id: " + std::to_string(event_id) + "; pid: " + std::to_string(pid);
	Trace(*output, msg);
}

void CreateTraceSession(wchar_t* session_name)
{
	TracePropsWithName trace;
	//EVENT_TRACE_PROPERTIES props = trace.props;
	ULONG propsSize = sizeof(trace.props);

	ULONG bufferSize = sizeof(trace); // extra space for the session name
	ZeroMemory(&trace, bufferSize);

	trace.props.Wnode.BufferSize = bufferSize;
	trace.props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	trace.props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
	trace.props.LoggerNameOffset = offsetof(TracePropsWithName, sessionName);;
	wcscpy_s(trace.sessionName, session_name);

	auto res = StartTraceW(NULL, session_name, &trace.props);
	if (res != ERROR_SUCCESS)
	{
		cout << "Got error code " << res << " from StartTraceW" << endl;
		throw runtime_error("Failed starting trace session");
	}
}

PROCESSTRACE_HANDLE OpenTraceSession(wchar_t* session_name, void *context)
{
	PEVENT_TRACE_LOGFILE Logfile;
	ZeroMemory(&Logfile, sizeof(Logfile));
	Logfile->LogFileName = nullptr;
	Logfile->LoggerName = session_name;
	Logfile->ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
	Logfile->EventRecordCallback = EventRecordCallback;
	Logfile->Context = context;
	auto trace_handle = OpenTraceW(Logfile);
	if (trace_handle == INVALID_PROCESSTRACE_HANDLE)
	{
		throw runtime_error("Failed opening trace session");
	}
	return trace_handle;
}

void main()
{
	std::ofstream logFile = OpenLogFile();
	wchar_t session_name[] = L"MySession"; // FIXME: fill log session name
	CreateTraceSession(session_name);
	auto process_trace_handle = OpenTraceSession(session_name, static_cast<void*>(&logFile));
	ProcessTrace(&process_trace_handle, 1, nullptr, nullptr);
}