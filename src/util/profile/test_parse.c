#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>

#include "prof_int.h"

#if !defined(_MSDOS) && !defined(_MACINTOSH)
#include "com_err.h"
#else

#define initialize_prof_error_table()
char *error_message (long err) {
	static char buf[50];

	sprintf (buf, " 0x%lX (%ld)", err, err);
	return buf;
}
#endif

void dump_profile PROTOTYPE((struct profile_node *root, int level));

int main(argc, argv)
	int	argc;
	char	**argv;
{
	struct profile_node *root;
	unsigned long retval;
	FILE *f;

	initialize_prof_error_table();
	if (argc != 2) {
		fprintf(stderr, "%s: Usage <filename>\n", argv[0]);
		exit(1);
	}

	f = fopen(argv[1], "r");
	if (!f) {
		perror(argv[1]);
		exit(1);
	}

	retval = profile_parse_file(f, &root);
	if (retval) {
		printf("profile_parse_file error %s\n", error_message(retval));
		return 0;
	}
	fclose(f);
	
	printf("\n\nDebugging dump.\n");
	dump_profile(root, 0);

	profile_free_node(root);
	return 0;
}
