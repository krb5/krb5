/*
 * test_profile.c --- testing program for the profile routine
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include "profile.h"
#include "com_err.h"

int main(argc, argv)
    int		argc;
    char	**argv;
{
    profile_t	profile;
    long	retval;
    const char	*filenames[2];
    char	**values, **cpp;
    
    filenames[0] = argv[1];
    filenames[1] = 0;

    initialize_prof_error_table();
    
    retval = profile_init(filenames, &profile);
    if (retval) {
	com_err(argv[0], retval, "while initializing profile");
	exit(1);
    }
    retval = profile_get_values(profile, argv+2, &values);
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
    exit(0);
}
    
    
