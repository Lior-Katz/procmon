#include <iostream>
#include <Windows.h>
#include <evntrace.h>
#include <tdh.h>

#include "err.h"
#include "utils.h"
#include "conf.h"
#include "main.h"

using std::runtime_error;

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")


void Trace(std::ostream file, std::wstring msg){
	file << msg << std::endl;
	
	if (REFLECT_TO_STDOUT){
		std::cout << msg << std:endl;
	}	
}


void EventCallback(PEVENT_RECORD pEvent)
{
	// TdhGetEventInformation(
	// 	pEvent,

	// )
	unsigned long pid = pEvent->EventHeader.ProcessId
	

	TRACE(...)
}

void CreateTraceSession(const LPWSTR session_name)
{
	PEVENT_TRACE_PROPERTIES props;
	ULONG props_size = sizeof(EVENT_TRACE_PROPERTIES);

	ULONG bufferSize = props_size + MAX_SESSION_NAME_SIZE; // extra space for the session name
	ZeroMemory(props, bufferSize);

	props->Wnode.BufferSize = bufferSize;
	props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
	props->LoggerNameOffset = props_size;

	if (StartTraceW(NULL, session_name, props) != ERROR_SUCCESS){
		throw runtime_error("Failed starting trace session");

	}
}

PROCESSTRACE_HANDLE OpenTraceSession(const LPWSTR session_name, void* context)
{
	PEVENT_TRACE_LOGFILE Logfile;
	ZeroMemory(&Logfile, sizeof(Logfile));
	Logfile->LogFileName = nullptr;
	Logfile->LoggerName = session_name;
	Logfile->ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
	Logfile->EventRecordCallback = EventCallback;
	Logfile->Context = context;
	auto trace_handle = OpenTraceW(Logfile);
	if (trace_handle == INVALID_PROCESSTRACE_HANDLE)
	{
		throw runtime_error("Failed opening trace session");
	}
	return trace_handle;
}

int main()
{
	LPWSTR session_name = L""; // FIXME: fill log session name
	CreateTraceSession(session_name, &std::cout);
	auto process_trace_handle = OpenTraceSession(session_name);
	ProcessTrace(&process_trace_handle, 1, nullptr, nullptr);
}