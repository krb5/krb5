#ifdef mw_rez
#include <SysTypes.r>
#include <Types.r>
#else
#include "SysTypes.r"
#include "Types.r"
#endif

resource 'vers' (1) {
	0x01, 0x05, beta, 0x05,
	verUS,
	"1.0.5b5",
	"1.0.5b5, Copyright 1996-1998 Massachusetts Institute of Technology"
};

resource 'vers' (2) {
	0x01, 0x05, final, 0x01,
	verUS,
	"",
	"Kerberos v5 1.0.5, Copyright 1996-1998 MIT"
};
