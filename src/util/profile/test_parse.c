#include <stdio.h>
#include <string.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <errno.h>
#include <ctype.h>

#include "prof_int.h"

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
		exit(1);
	}
	fclose(f);
	
	printf("\n\nDebugging dump.\n");
#if 0
	dump_profile(root, 0);
#else
	dump_profile_to_file(root, 0, stdout);
#endif

	retval = profile_verify_node(root);
	if (retval) {
		printf("profile_verify_node reported an error: %s\n",
		       error_message(retval));
		exit(1);
	}

	profile_free_node(root);

	return 0;
}
