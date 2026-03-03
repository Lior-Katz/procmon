#include "TraceSession.h"
#include <string>
#include <stdexcept>
#include <evntcons.h>
#include <iostream>

using std::runtime_error;
using std::to_string;
using std::cout;
using std::endl;
using std::wstring;
using std::string;



TraceSession::TraceSession(wchar_t* session_name) : m_trace_id(0)
{
	size_t bufferSize = sizeof(TracePropsWithName);
	ZeroMemory(&m_trace_props, bufferSize);

	m_trace_props.props.Wnode.BufferSize = bufferSize;
	m_trace_props.props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;

	m_trace_props.props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
	m_trace_props.props.LoggerNameOffset = offsetof(TracePropsWithName, session_name);;
	wcscpy_s(m_trace_props.session_name, session_name);

	auto res = StartTraceW(&m_trace_id, m_trace_props.session_name, &m_trace_props.props);
	if (res == ERROR_ALREADY_EXISTS)
	{
		wstring ws(m_trace_props.session_name);
		throw runtime_error("Trace session " + std::string(ws.begin(), ws.end()) + " already exists");
	}
	if (res != ERROR_SUCCESS)
	{
		throw runtime_error("Failed starting trace session: " + to_string(res));
	}
}

TraceSession::~TraceSession()
{
	cout << "Destroying trace session" << endl;
	Stop();
	if (m_trace_id != 0)
	{
		cout << "Deleting opened session" << endl;
		ControlTraceW(m_trace_id, m_trace_props.session_name, &m_trace_props.props, EVENT_TRACE_CONTROL_STOP);
		m_trace_id = 0;
	}
}

void TraceSession::Start(PEVENT_RECORD_CALLBACK callback, void* context)
{
	EVENT_TRACE_LOGFILE Logfile;
	ZeroMemory(&Logfile, sizeof(Logfile));
	Logfile.LogFileName = nullptr;
	Logfile.LoggerName = m_trace_props.session_name;
	Logfile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
	Logfile.EventRecordCallback = callback;
	Logfile.Context = context;
	auto trace_handle = OpenTraceW(&Logfile);
	if (trace_handle == INVALID_PROCESSTRACE_HANDLE)
	{
		throw runtime_error("Failed opening trace session");
	}
	m_trace_handle = trace_handle;
	ProcessTrace(&m_trace_handle, 1, nullptr, nullptr);
}

void TraceSession::Stop()
{
	cout << "Stopping trace session" << endl;
	CloseTrace(m_trace_handle);
}
