/*
 * wconfig.c
 *
 * Copyright 1995,1996 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 *
 * Program to take the place of the configure shell script under DOS.
 * The makefile.in files are constructed in such a way that all this
 * program needs to do is uncomment lines beginning ##DOS by removing the
 * first 5 characters of the line.  This will allow lines like:
 * ##DOS!include windows.in to become: !include windows.in
 *
 * We also turn any line beginning with '@' into a blank line.
 *
 * If a config directory is specified, then the output will be start with
 * config\pre.in, then the filtered stdin text, and will end with
 * config\post.in.
 *
 * Syntax: wconfig [config_directory] <input_file >output_file
 *
 */
#include <stdio.h>
#include <string.h>

static int copy_file (char *path, char *fname);
void add_ignore_list(char *str);

int mit_specific = 0;

int main(int argc, char *argv[])
{
	char *ignore_str = "--ignore=";
	int ignore_len;
	
	ignore_len = strlen(ignore_str);
	argc--; argv++;
	while ((argc > 1) && *argv[0] == '-') {
		if (!strcmp(*argv, "--mit")) {
			mit_specific = 1;
			argc--; argv++;
			continue;
		}
		if (!strcmp(*argv, "--nomit")) {
			mit_specific = 0;
			argc--; argv++;
			continue;
		}
		if (!strncmp(*argv, ignore_str, ignore_len)) {
			add_ignore_list((*argv)+ignore_len);
			argc--; argv++;
		}
	}

	if (mit_specific)
		add_ignore_list("MIT##");
		
	if (argc > 0)                              /* Config directory given */
		copy_file (*argv, "\\windows.in");        /* Send out prefix */

	copy_file("", "-");
    
	if (argc > 0)                          /* Config directory given */
		copy_file (*argv, "\\win-post.in");    /* Send out postfix */
	return 0;
}

char *ignore_list[32] = {
	"DOS##",
	"DOS",
#ifdef _MSDOS
	"WIN16##",
#endif
#ifdef _WIN32
	"WIN32##",
#endif
	};

/*
 * Add a new item to the ignore list
 */
void add_ignore_list(char *str)
{
	char **cpp;

	for (cpp = ignore_list; *cpp; cpp++)
		;
	*cpp = str;
}

		
/*
 * 
 * Copy_file
 * 
 * Copies file 'path\fname' to stdout.
 * 
 */
static int
copy_file (char *path, char *fname)
{
    FILE *fin;
    char buf[1024];
    char **cpp, *ptr;
    int len;

    if (strcmp(fname, "-") == 0) {
	    fin = stdin;
    } else {
	    strcpy (buf, path);              /* Build up name to open */
	    strcat (buf, fname);
	    fin = fopen (buf, "r");                     /* File to read */
	    if (fin == NULL)
		    return 1;
    }
    

    while (fgets (buf, sizeof(buf), fin) != NULL) { /* Copy file over */
	    if (buf[0] == '@') {
		    fputs("\n", stdout);
		    continue;
	    }
	    if (buf[0] != '#' || buf[1] != '#') {
		    fputs(buf, stdout);
		    continue;
	    }
	    ptr = buf;
	    for (cpp = ignore_list; *cpp; cpp++) {
		    len = strlen(*cpp);
		    if (memcmp (*cpp, buf+2, len) == 0) {
			    ptr += 2+len;
			    break;
		    }
	    }
	    fputs(ptr, stdout);
    }

    fclose (fin);

    return 0;
}
