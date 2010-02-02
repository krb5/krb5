/*
 * Copyright (c) 2005 Massachusetts Institute of Technology
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/* $Id$ */

#include<tchar.h>

#include<shlwapi.h>
#include<khmapp.h>

#include<stdio.h>

#if DEBUG
#include<assert.h>
#endif

#define LOGFILENAME "nidmdbg.log"

CRITICAL_SECTION cs_log;
FILE * logfile = NULL;
BOOL log_started = FALSE;

wchar_t *
severity_string(kherr_severity severity) {
    switch(severity) {
    case KHERR_FATAL:
	return L"FATAL";

    case KHERR_ERROR:
	return L"ERROR";

    case KHERR_WARNING:
	return L"Warning";

    case KHERR_INFO:
	return L"Info";

    case KHERR_DEBUG_3:
	return L"Debug(3)";

    case KHERR_DEBUG_2:
	return L"Debug(2)";

    case KHERR_DEBUG_1:
	return L"Debug(1)";

    case KHERR_NONE:
	return L"(None)";

    default:
	return L"(Unknown severity)";
    }
}

void
fprint_systime(FILE * f, SYSTEMTIME *psystime) {
    fprintf(logfile,
            "%d-%d-%d %02d:%02d:%02d.%03d",

            (int) psystime->wYear,
            (int) psystime->wMonth,
            (int) psystime->wDay,

            (int) psystime->wHour,
            (int) psystime->wMinute,
            (int) psystime->wSecond,
            (int) psystime->wMilliseconds);
}

void KHMAPI
debug_event_handler(enum kherr_ctx_event e,
		    kherr_context * c) {
    kherr_event * evt;

    EnterCriticalSection(&cs_log);

    if (!logfile)
	goto _done;

    if (e == KHERR_CTX_BEGIN) {
        SYSTEMTIME systime;

        GetSystemTime(&systime);
	fprintf(logfile,
		"%d\t",
		c->serial);

        fprint_systime(logfile, &systime);

        fprintf(logfile,
                "\t<< Context begin --\n");

    } else if (e == KHERR_CTX_DESCRIBE) {
	evt = kherr_get_desc_event(c);
	if (evt) {
	    kherr_evaluate_event(evt);
	    fprintf(logfile,
		    "%d\t  Description: %S\n",
		    c->serial,
		    (evt->long_desc)? evt->long_desc: evt->short_desc);
	}
    } else if (e == KHERR_CTX_END) {
        SYSTEMTIME systime;

	fprintf(logfile,
		"%d\t",
		c->serial);

        GetSystemTime(&systime);
        fprint_systime(logfile, &systime);

        fprintf(logfile,
                "\t>> Context end --\n");

    } else if (e == KHERR_CTX_EVTCOMMIT) {
	evt = kherr_get_last_event(c);
	if (evt && (evt->short_desc || evt->long_desc)) {
	    SYSTEMTIME systime;

	    kherr_evaluate_event(evt);
	    FileTimeToSystemTime(&evt->time_ft, &systime);
	    
	    fprintf(logfile,
		    "%d[%d](%S)\t",
		    c->serial,
		    evt->thread_id,
		    (evt->facility ? evt->facility: L""));

            fprint_systime(logfile, &systime);

            fprintf(logfile,
                    "\t%S: %S %S%S%S %S%S%S\n",

		    severity_string(evt->severity),

		    (evt->short_desc ? evt->short_desc: L""),

		    (evt->short_desc ? L"(":L""),
		    (evt->long_desc ? evt->long_desc: L""),
		    (evt->short_desc ? L")":L""),

		    (evt->suggestion ? L"[":L""),
		    (evt->suggestion ? evt->suggestion: L""),
		    (evt->suggestion ? L"]":L"")
		    );
	}
    }

 _done:

    LeaveCriticalSection(&cs_log);
}

void khm_get_file_log_path(khm_size cb_buf, wchar_t * buf) {
#ifdef DEBUG
    assert(cb_buf > sizeof(wchar_t));
#endif
    *buf = L'\0';

    GetTempPath((DWORD) cb_buf / sizeof(wchar_t), buf);

    StringCbCat(buf, cb_buf, _T(LOGFILENAME));
}

void khm_start_file_log(void) {
    wchar_t temppath[MAX_PATH];
    khm_handle cs_cw = NULL;
    khm_int32 t = 0;

    EnterCriticalSection(&cs_log);

    if (log_started)
	goto _done;

    if (KHM_FAILED(khc_open_space(NULL, L"CredWindow", 0, &cs_cw)))
	goto _done;

    if (KHM_FAILED(khc_read_int32(cs_cw, L"LogToFile", &t)) ||
	!t)
	goto _done;

    khm_get_file_log_path(sizeof(temppath), temppath);

    logfile = NULL;
#if _MSC_VER >= 1400 && __STDC_WANT_SECURE_LIB__
    _wfopen_s(&logfile, temppath, L"w");
#else
    logfile = _wfopen(temppath, L"w");
#endif
    kherr_add_ctx_handler(debug_event_handler,
			  KHERR_CTX_BEGIN |
			  KHERR_CTX_END |
			  KHERR_CTX_DESCRIBE |
			  KHERR_CTX_EVTCOMMIT,
			  0);

    log_started = TRUE;

 _done:
    if (cs_cw)
	khc_close_space(cs_cw);

    LeaveCriticalSection(&cs_log);
}

void khm_stop_file_log(void) {

    EnterCriticalSection(&cs_log);

    if (!log_started)
	goto _done;

    kherr_remove_ctx_handler(debug_event_handler, 0);

    if (logfile)
	fclose (logfile);
    logfile = NULL;

    log_started = FALSE;

 _done:
    LeaveCriticalSection(&cs_log);
}

void khm_init_debug(void) {
    InitializeCriticalSection(&cs_log);

    khm_start_file_log();
}

void khm_exit_debug(void) {
    khm_stop_file_log();

    DeleteCriticalSection(&cs_log);
}
