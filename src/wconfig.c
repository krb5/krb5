/*
 * wconfig.c
 *
 * Copyright 1995 by the Massachusetts Institute of Technology.
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

static char buf [1024];							/* Holds line from a file */
static int copy_file (char *path, char *fname);

int main(int argc, char *argv[]) {
    char *ptr;									/* For parsing the input */

    if (argc == 2)                              /* Config directory given */
        copy_file (argv[1], "\\windows.in");        /* Send out prefix */

    while ((ptr = gets(buf)) != NULL) {         /* Filter stdin */
        if (memcmp ("##DOS", buf, 5) == 0)
            ptr += 5;
		else if (*ptr == '@')					/* Lines starting w/ '@'... */
			*ptr = '\0';						/* ...turn into blank lines */

        puts (ptr);
    }

    if (argc == 2)                              /* Config directory given */
        copy_file (argv[1], "\\post.in");       /* Send out postfix */

    return 0;
}
/*
 * 
 * Copy_file
 * 
 * Copies file 'path\fname' to stdout.
 * 
 */
static int
copy_file (char *path, char *fname) {
    FILE *fin;

    strcpy (buf, path);                         /* Build up name to open */
    strcat (buf, fname);

    fin = fopen (buf, "r");                     /* File to read */
    if (fin == NULL)
        return 1;

    while (fgets (buf, sizeof(buf), fin) != NULL) { /* Copy file over */
        fputs (buf, stdout);
    }

    fclose (fin);

    return 0;
}
