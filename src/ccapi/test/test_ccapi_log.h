#ifndef _TEST_CCAPI_LOG_H_
#define _TEST_CCAPI_LOG_H_

#include <stdio.h>
#include <stdarg.h>
#include "test_ccapi_globals.h"

#define log_error(format, ...) \
		_log_error(__FILE__, __LINE__, format , ## __VA_ARGS__)

void _log_error_v(const char *file, int line, const char *format, va_list ap);
void _log_error(const char *file, int line, const char *format, ...) __attribute__ ((format (printf, 3, 4)));

void test_header(const char *msg);
void test_footer(const char *msg, int err);

#endif /* _TEST_CCAPI_LOG_H_ */
