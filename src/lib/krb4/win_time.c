/*
 * win_time.c
 * 
 * Glue code for pasting Kerberos into the Windows environment.
 *
 * Originally written by John Gilmore, Cygnus Support, May '94.
 * Public Domain.
 */

#include "krb.h"

#include <sys/types.h>
#include <time.h>
#include <sys/timeb.h>
#include <stdio.h>
#include <windows.h>
#include <dos.h>

#ifdef _WIN32

unsigned KRB4_32
win_time_gmt_unixsec (usecptr)
    unsigned KRB4_32	*usecptr;
{
    struct _timeb timeptr;

    _ftime(&timeptr);                           /* Get the current time */

    if (usecptr)
	*usecptr = timeptr.millitm * 1000;

    return timeptr.time + CONVERT_TIME_EPOCH;
}

#else

/*
 * Time handling.  Translate Unix time calls into Kerberos internal 
 * procedure calls.  See ../../include/c-win.h.
 *
 * Due to the fact that DOS time can be unreliable we have reverted
 * to using the AT hardware clock and converting it to Unix time.
 */

unsigned KRB4_32
win_time_gmt_unixsec (usecptr)
	unsigned KRB4_32	*usecptr;
{
	struct tm tm;
	union _REGS inregs;
	union _REGS outregs;
	struct _timeb now;
	time_t time;

	_ftime(&now);

	#if 0
		if (usecptr)
			*usecptr = now.millitm * 1000;
	#endif

	/* Get time from AT hardware clock INT 0x1A, AH=2 */
	memset(&inregs, 0, sizeof(inregs));
	inregs.h.ah = 2;

	_int86(0x1a, &inregs, &outregs);

	/* 0x13 = decimal 13, hence the decoding below */
	tm.tm_sec = 10 * ((outregs.h.dh & 0xF0) >> 4) + (outregs.h.dh & 0x0F);
	tm.tm_min = 10 * ((outregs.h.cl & 0xF0) >> 4) + (outregs.h.cl & 0x0F);
	tm.tm_hour = 10 * ((outregs.h.ch & 0xF0) >> 4) + (outregs.h.ch & 0x0F);

	/* Get date from AT hardware clock INT 0x1A, AH=4 */
	memset(&inregs, 0, sizeof(inregs));
	inregs.h.ah = 4;

	_int86(0x1a, &inregs, &outregs);

	tm.tm_mday = 10 * ((outregs.h.dl & 0xF0) >> 4) + (outregs.h.dl & 0x0F);
	tm.tm_mon = 10 * ((outregs.h.dh & 0xF0) >> 4) + (outregs.h.dh & 0x0F) - 1;
	tm.tm_year = 10 * ((outregs.h.cl & 0xF0) >> 4) + (outregs.h.cl & 0x0F);
	tm.tm_year += 100 * ((10 * (outregs.h.ch & 0xF0) >> 4)
	            + (outregs.h.ch & 0x0F) - 19);

    	tm.tm_wday = 0;
	tm.tm_yday = 0;
	tm.tm_isdst = now.dstflag;

	time = mktime(&tm);

	if (usecptr)
		*usecptr = 0;

	return time + CONVERT_TIME_EPOCH;
}

#endif

/*
 * This routine figures out the current time epoch and returns the
 * conversion factor.  It exists because 
 * Microloss screwed the pooch on the time() and _ftime() calls in
 * its release 7.0 libraries.  They changed the epoch to Dec 31, 1899!
 * Idiots...   We try to cope.
 */

static struct tm jan_1_70 = {0, 0, 0, 1, 0, 70};
static long epoch = 0;
static int epoch_set = 0;

long
win_time_get_epoch()
{

	if (!epoch_set) {
		epoch = - mktime (&jan_1_70);	/* Seconds til 1970 localtime */
		epoch += timezone;		/* Seconds til 1970 GMT */
		epoch_set = 1;
	}
	return epoch;
}
