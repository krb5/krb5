/*
 * test_profile.c --- testing program for the profile routine
 */

#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#include "prof_int.h"
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

const char *program_name = "test_profile";

int main(argc, argv)
    int		argc;
    char	**argv;
{
    profile_t	profile;
    long	retval;
    char	**values, **cpp;
    const char	*value;
    const char	**names;
    char	*cmd;
    int		print_value = 0;
    
    if (argc < 3) {
	    fprintf(stderr, "Usage: %s filename cmd argset\n", program_name);
	    exit(1);
    }

    initialize_prof_error_table();
    
    retval = profile_init_path(argv[1], &profile);
    if (retval) {
	com_err(program_name, retval, "while initializing profile");
	exit(1);
    }
    cmd = *(argv+2);
    names = (const char **) argv+3;
    if (!strcmp(cmd, "query")) {
	    retval = profile_get_values(profile, names, &values);
    } else if (!strcmp(cmd, "query1")) {
	    retval = profile_get_value(profile, names, &value);
	    print_value++;
    } else if (!strcmp(cmd, "list_sections")) {
	    retval = profile_get_subsection_names(profile, names, &values);
    } else if (!strcmp(cmd, "list_relations")) {
	    retval = profile_get_relation_names(profile, names, &values);
    } else {
	    fprintf(stderr, "Invalid command.\n");
	    exit(1);
    }
    if (retval) {
	    com_err(argv[0], retval, "while getting values");
	    exit(1);
    }
    if (print_value) {
	    printf("%s\n", value);
    } else {
	    for (cpp = values; *cpp; cpp++)
		    printf("%s\n", *cpp);
	    profile_free_list(values);
    }
    profile_release(profile);

    return 0;
}
    
    
