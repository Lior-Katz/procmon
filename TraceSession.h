#pragma once
#include <Windows.h>
#include <evntrace.h>
#include "conf.h"

class TraceSession
{
	public:
	TraceSession(wchar_t* session_name);
	~TraceSession();
	void Start(PEVENT_RECORD_CALLBACK callback, void* context);
	void Stop();

private:
	struct TracePropsWithName
	{
		EVENT_TRACE_PROPERTIES props;
		WCHAR session_name[MAX_SESSION_NAME_SIZE];
	};

	CONTROLTRACE_ID m_trace_id;
	TracePropsWithName m_trace_props;
	PROCESSTRACE_HANDLE m_trace_handle;
};

