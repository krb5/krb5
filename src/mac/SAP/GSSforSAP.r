#ifdef mw_rez
#include <SysTypes.r>
#include <Types.r>
#else
#include "SysTypes.r"
#include "Types.r"
#endif

resource 'vers' (1) {
	0x01, 0x00, final, 0x00,
	verUS,
	"1.0",
	"1.0(SAP), Copyright 1996 Massachusetts Institute of Technology"
};

resource 'DITL' (135, nonpurgeable) {
	{	/* array DITLarray: 2 elements */
		/* [1] */
		{96, 292, 116, 360},
		Button {
			enabled,
			"OK"
		},
		/* [2] */
		{16, 64, 84, 360},
		StaticText {
			disabled,
			"This version of the SAP client has expir"
			"ed. Please consult: http://web.mit.edu/r"
			"eeng/www/saphelp/ for instructions on ob"
			"taining a new version."
		}
	}
};

resource 'DITL' (136, nonpurgeable) {
	{	/* array DITLarray: 2 elements */
		/* [1] */
		{116, 300, 136, 368},
		Button {
			enabled,
			"OK"
		},
		/* [2] */
		{16, 64, 100, 360},
		StaticText {
			disabled,
			"This version of the SAP client will expi"
			"re on June 1, 1997. Please consult: "
			"http://web.mit.edu/reeng/www/saphelp/ fo"
			"r instructions on obtaining a new versio"
			"n when it is available."
		}
	}
};

data 'DLGX' (135) {
	$"0743 6869 6361 676F 0000 0000 0000 0000"            /* .Chicago........ */
	$"0000 0000 0000 0000 0000 0000 0000 0000"            /* ................ */
	$"0000 0000 0000 0000 0000 0000 0000 0000"            /* ................ */
	$"0000 0000 0000 0000 0000 0000 0000 0000"            /* ................ */
	$"000C 0000 0000 0001 0004 0004 0000 0000"            /* ................ */
	$"0002 0000 0000 0000 0000 0000 0000 0006"            /* ................ */
	$"0000 0000 0000 0000 0000"                           /* .......... */
};

data 'DLGX' (136) {
	$"0743 6869 6361 676F 0000 0000 0000 0000"            /* .Chicago........ */
	$"0000 0000 0000 0000 0000 0000 0000 0000"            /* ................ */
	$"0000 0000 0000 0000 0000 0000 0000 0000"            /* ................ */
	$"0000 0000 0000 0000 0000 0000 0000 0000"            /* ................ */
	$"000C 0000 0000 0001 0004 0004 0000 0000"            /* ................ */
	$"0002 0000 0000 0000 0000 0000 0000 0006"            /* ................ */
	$"0000 0000 0000 0000 0000"                           /* .......... */
};

data 'ictb' (136) {
	$"0000 0000 0000 0000"                                /* ........ */
};

resource 'ALRT' (135, nonpurgeable) {
	{383, 390, 511, 770},
	135,
	{	/* array: 4 elements */
		/* [1] */
		OK, visible, sound1,
		/* [2] */
		OK, visible, sound1,
		/* [3] */
		OK, visible, sound1,
		/* [4] */
		OK, visible, sound1
	}
	/****** Extra bytes follow... ******/
	/* $"0000"                                               /* .. */
};

resource 'ALRT' (136, nonpurgeable) {
	{383, 390, 531, 774},
	136,
	{	/* array: 4 elements */
		/* [1] */
		OK, visible, sound1,
		/* [2] */
		OK, visible, sound1,
		/* [3] */
		OK, visible, sound1,
		/* [4] */
		OK, visible, sound1
	}
	/****** Extra bytes follow... ******/
	/* $"0000"                                               /* .. */
};

resource 'actb' (136) {
	{	/* array ColorSpec: 5 elements */
		/* [1] */
		wContentColor, 65535, 65535, 65535,
		/* [2] */
		wFrameColor, 0, 0, 0,
		/* [3] */
		wTextColor, 0, 0, 0,
		/* [4] */
		wHiliteColor, 0, 0, 0,
		/* [5] */
		wTitleBarColor, 65535, 65535, 65535
	}
};

