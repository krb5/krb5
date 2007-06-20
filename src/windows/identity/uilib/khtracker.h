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

#ifndef __KHIMAIRA_TRACKERWND_H
#define __KHIMAIRA_TRACKERWND_H

#include<time.h>

/*! \addtogroup khui 

@{ */

/*!\defgroup khui_trk Duration sliders

The duration sliders in the UI are pseudo-log-scaled.  This is based
on the assumption that people don't really need 1 minute accuracy when
setting a duration that's several hours long.  As a result, it is
easier to hone in on the duration that you want without having
wizardly mouse maneuvering skillz.

Following are the duration ranges and the granularity that is offered
in each range:

<table>
<tr><td> Range     </td><td> Increment</td></tr>
<tr><td> 0..5m     </td><td> 1 min    </td></tr>
<tr><td> 5m..1hr   </td><td> 5 min    </td></tr>
<tr><td> 1hr..4hr  </td><td> 15 min   </td></tr>
<tr><td> 4hr..10hr </td><td> 30 min   </td></tr>
<tr><td> 10hr..24hr</td><td> 1 hr     </td></tr>
<tr><td> 24hr..4d  </td><td> 6 hr     </td></tr>
<tr><td> 4d..      </td><td> 1 day    </td></tr>
</table>

We don't really adjust for durations over 4 days.  The ranges we are
concerned with don't get much larger.

For the purpose of writing this piece of code, I have chosen the term
"tick" to refer to a period of granularity.  The number of periods of
granularity (inclusive) within a certain duration interval is referred
to as the number of ticks in the interval.  For example, there are 4
ticks between the interval of 3 minutes to 10 minutes.  Each occuring
at the start of 3min, 4, 5 and 10mins.  And thusly the slider control
will display 4 ticks if it is displaying the interval 3-10mins.

@{*/

/*! \brief Tracker data */
typedef struct tag_khui_tracker {
    WNDPROC fn_edit;
    WNDPROC fn_tracker;
    HWND hw_slider;
    HWND hw_edit;
    int lbl_y;
    int lbl_lx;
    int lbl_rx;
    DWORD act_time;

    time_t current;             /*!< Current selection */
    time_t min;                 /*!< Minimum (inclusive)  */
    time_t max;                 /*!< Maximum (inclusive) */
} khui_tracker;

/*! \brief Install a tracker into an edit control

    Once installed, the edit control becomes a duration editor.  The
    tracker data structure that is supplied should remain as is for
    the lifetime of the edit control.

    The tracker strucutre should have been initialized with a call to
    khui_tracker_initialize() and should have valid values in the \a
    min, \a max and \a current fields.
 */
KHMEXP void KHMAPI
khui_tracker_install(HWND hwnd_edit, khui_tracker * tc);

KHMEXP void KHMAPI
khui_tracker_reposition(khui_tracker * tc);

KHMEXP void KHMAPI
khui_tracker_initialize(khui_tracker * tc);

KHMEXP void KHMAPI
khui_tracker_refresh(khui_tracker * tc);

KHMEXP void KHMAPI
khui_tracker_kill_controls(khui_tracker * tc);
/*!@}*/
/*!@}*/

#endif
