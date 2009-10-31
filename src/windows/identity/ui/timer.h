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

#ifndef __KHIMAIRA_TIMER_H
#define __KHIMAIRA_TIMER_H

/* note that the ordering of the first few enum constants are
   significant.  The values of the constants up to KHUI_N_TTYPES are
   used as indices.  */
typedef enum tag_khui_timer_type {
    KHUI_TTYPE_ID_EXP = 0,      /* Identity expiration */
    KHUI_TTYPE_ID_CRIT,         /* Identity critical */
    KHUI_TTYPE_ID_WARN,         /* Identity warning */
    KHUI_TTYPE_CRED_EXP,        /* Credential expiration */
    KHUI_TTYPE_CRED_CRIT,       /* Credential critical */
    KHUI_TTYPE_CRED_WARN,       /* Credential warning */

    KHUI_N_TTYPES,              /* Count of the timers that we
                                   aggregate for notifications */

    KHUI_TTYPE_ID_MARK,         /* Identity marker */

    KHUI_TTYPE_ID_RENEW,        /* Identity auto renewal */
    KHUI_TTYPE_CRED_RENEW,      /* Credential renewal */

#if 0
    KHUI_TTYPE_BMSG,            /* Custom. Sends broadcast message
                                   when triggered.*/
    KHUI_TTYPE_SMSG,            /* Custom. Sends subscription message
                                   when triggered. */
#endif
} khui_timer_type;

typedef struct tag_khui_timer_event {
    khm_handle       key;
    khui_timer_type  type;

    khm_int64 expire;    /* time at which the timer expires */
    khm_int64 offset;    /* time offset at which the event that the
                            timer warns of happens */
    void *           data;
    khm_int32        flags;
} khui_timer_event;

#define KHUI_TRIGGER_TIMER_ID 48
#define KHUI_REFRESH_TIMER_ID 49

#define KHUI_REFRESH_TIMEOUT 5000

#define KHUI_TE_FLAG_EXPIRED 0x00000001
#define KHUI_TE_FLAG_STALE   0x00000002

#define KHUI_DEF_TIMEOUT_WARN 900
#define KHUI_DEF_TIMEOUT_CRIT 300
#define KHUI_DEF_TIMEOUT_RENEW 60

/* the max absolute difference between two timers (in seconds) that
   can exist where we consider both timers to be in the same
   timeslot. */
#define KHUI_TIMEEQ_ERROR 20

/* the small error. */
#define KHUI_TIMEEQ_ERROR_SMALL 1

void
khm_timer_refresh(HWND hwnd);

void
khm_timer_fire(HWND hwnd);

void
khm_timer_init(void);

void
khm_timer_exit(void);

#endif
