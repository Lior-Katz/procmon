#pragma once

#include <iostream>
#include <fstream>
#include "conf.h"


#define WRITE_TO_FILE(msg) \
	std::ofstream file(LOG_FILE, std::ios::app); \
	if (file.is_open()) {						 \
		file << msg << std::endl;				 \
		file.close();							 \
	}


#define TRACE(msg)				   \
	std::cout << msg << std::endl; \
	WRITE_TO_FILE(msg)			   \
	

#define TRACE_ERR(msg)  \
	TRACE("[X] "#msg)	\