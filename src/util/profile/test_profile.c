/*
 * test_profile.c --- testing program for the profile routine
 */

#include <stdio.h>
#include <stdlib.h>

#include "profile.h"
#ifndef _MSDOS
#include "com_err.h"
#else

/* Stubs for the error handling routines */
#include "prof_int.h"
void initialize_prof_error_table() {}
void com_err (char *fmt, long err, char *msg) {
    printf (fmt, err, msg);
}
#endif

int main(argc, argv)
    int		argc;
    char	**argv;
{
    profile_t	profile;
    long	retval;
    const char	*filenames[2];
    char	**values, **cpp;
    const char	**names;
    
    filenames[0] = argv[1];
    filenames[1] = 0;

    if (argc < 2) {
	    fprintf(stderr, "Usage: %s filename argset\n", argv[0]);
	    exit(1);
    }

    initialize_prof_error_table();
    
    retval = profile_init(filenames, &profile);
    if (retval) {
	com_err(argv[0], retval, "while initializing profile");
	exit(1);
    }
    names = (const char **) argv+2;
    retval = profile_get_values(profile, names, &values);
    if (retval) {
	com_err(argv[0], retval, "while getting values");
	exit(1);
    }
    for (cpp = values; *cpp; cpp++) {
	printf("%s\n", *cpp);
	free(*cpp);
    }
    free(values);
    profile_release(profile);

	return 0;

}
    
    
