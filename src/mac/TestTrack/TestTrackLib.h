/*
 *   Copyright (C) 1992 by the Massachusetts Institute of Technology
 *   All rights reserved.
 *
 *   For copying and distribution information, please see the file
 *   COPYRIGHT.
 */
/*
 * Function prototypes for testtrack routines - shared library version
 */

#ifdef __cplusplus
extern "C" {
#endif

#if GENERATINGCFM

#define InitializeMacAthenaLib()
#define TerminateMacAthenaLib()

	#if defined(__CFM68K__)
		#pragma import on

		extern int test_track(char *appl_name, char *appl_vers, Boolean edit_flag,
			       Boolean do_logging, int check_probability);
		extern short GetBSDMacOSError( void );

		#pragma import reset
	#else

		int test_track(char *appl_name, char *appl_vers, Boolean edit_flag,
			       Boolean do_logging, int check_probability);
		short GetBSDMacOSError( void );

	#endif			/* endif __CFM68K__ */

#else			/* else GENERATINGCFM */

	typedef int (*test_trackProcPtr) (char *appl_name, char *appl_vers, Boolean edit_flag,
		       Boolean do_logging, int check_probability);
	typedef short (*GetBSDMacOSErrorProcPtr) (void);

	extern test_trackProcPtr		gtest_trackGlue;
	extern GetBSDMacOSErrorProcPtr	gGetBSDMacOSErrorGlue;

	#define test_track(appl_name, appl_vers, edit_flag, do_logging, check_probability)\
			((gtest_trackGlue)(appl_name, appl_vers, edit_flag, do_logging, check_probability))
	#define GetBSDMacOSError()\
			((gGetBSDMacOSErrorGlue)())
	 
	OSErr InializeMacAthenaLib (void);
	OSErr TerminateMacAthenaLib (void);

#endif			/* endif GENERATINGCFM */


#ifdef __cplusplus
}
#endif
