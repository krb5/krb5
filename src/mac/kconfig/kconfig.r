/*
 * Copyright 1991-1994 by The University of Texas at Austin
 * All rights reserved.
 *
 * For infomation contact:
 * Rick Watson
 * University of Texas
 * Computation Center, COM 1
 * Austin, TX 78712
 * r.watson@utexas.edu
 * 512-471-3241
 */

#include "Types.r"		/* To get system types */
#include "SysTypes.r"	/* get more system types */
#include "kconfig.vers"

include "kconfig.rsrc" not 'ckid';
include "ldef.rsrc";

type KCONFIG_CREATOR {
	pstring;
};

resource KCONFIG_CREATOR (0,purgeable) {
	"CNS Config"
};

resource 'vers' (1, purgeable) {
    VERSION,             /* version */
    VERSION2,			 /* 2nd part of version */
    0x60,                /* beta */
    BETAPART,            /* beta part */
    verUS,
    SHORTVERS,
	LONGVERS
    };

resource 'vers' (2, purgeable) {
    VERSION,             /* version */
    VERSION2,			 /* 2nd part of version */
    0x60,                /* beta */
    BETAPART,            /* beta part */
    verUS,
    SHORTVERS,
    "Program"
    };


resource 'SIZE' (-1) {
	dontSaveScreen,
	acceptSuspendResumeEvents,
	enableOptionSwitch,
	canBackground,
	doesActivateOnFGSwitch,
	backgroundAndForeground,
	dontGetFrontClicks,
	ignoreAppDiedEvents,
	not32BitCompatible,
	notHighLevelEventAware,
	onlyLocalHLEvents,
	notStationeryAware,
	dontUseTextEditServices,
	reserved,
	reserved,
	reserved,
	524288,
	524288
};

resource 'SIZE' (0) {
	dontSaveScreen,
	acceptSuspendResumeEvents,
	enableOptionSwitch,
	canBackground,
	doesActivateOnFGSwitch,
	backgroundAndForeground,
	dontGetFrontClicks,
	ignoreAppDiedEvents,
	not32BitCompatible,
	notHighLevelEventAware,
	onlyLocalHLEvents,
	notStationeryAware,
	dontUseTextEditServices,
	reserved,
	reserved,
	reserved,
	524288,
	524288
};

