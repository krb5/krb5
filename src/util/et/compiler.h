/*
 * definitions common to the source files of the error table compiler
 */

enum lang {
    lang_C,			/* ANSI C (default) */
    lang_KRC,			/* C: ANSI + K&R */
    lang_CPP			/* C++ */
};

int debug;			/* dump debugging info? */
char *filename;			/* error table source */
enum lang language;
const char *whoami;
