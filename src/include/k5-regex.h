/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* vi: set softtabstop=4 shiftwidth=4 tabstop=4 expandtab ai: */
/* include/k5-regex.h - Compatibility glue for std::regex on Windows */

/*
 * On POSIX platforms we can use the standardized regcomp()/regexec()
 * function calls.  However, Windows does not provide a C interface to
 * these calls.  It does provide a C++ interface (std::regex) that has
 * the same functionality.
 *
 * On POSIX platforms just include regex.h and be done with it.  On
 * Windows redefine all of the regular expression functions in terms of
 * k5_reg*() and implement the appropriate glue code in libkrb5support.
 *
 */

#ifndef _K5_REGEX_H_
#define _K5_REGEX_H_

#ifndef _WIN32
#include <regex.h>
#else /* _WIN32 */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Emulate the regex C interface
 */

typedef struct {
    size_t re_nsub;         /* Number of subexpressions */
    void *regex;            /* Pointer to std::basic_regex */
    char regerrmsg[128];    /* Regular expression error message */
    size_t regerrlen;       /* Error message length */
} regex_t;

typedef off_t regoff_t;

typedef struct {
    regoff_t rm_so;
    regoff_t rm_eo;
} regmatch_t;

/*
 * Flags to k5_regcomp()
 */

#define REG_BASIC       0000    /* Basic regular expressions */
#define REG_EXTENDED    0001    /* Extended regular expressions */
#define REG_ICASE       0002    /* Case-insensitive match */
#define REG_NOSUB       0004    /* Do not do submatching */

/*
 * Flags to k5_regexec()
 */

#define REG_NOTBOL      0001    /* First character not at beginning of line */
#define REG_NOTEOL      0002    /* Last character not at end of line */

/*
 * Error return codes for k5_regcomp()/k5_regexec()
 *
 * We only define REG_NOMATCH and REG_BADPAT, since no Kerberos code looks
 * for anything other than success and REG_NOMATCH.  Any exceptions from
 * these functions are caught and the error message is stored in regex_t
 * and can be extracted by k5_regerror().
 */

#define REG_NOMATCH     1
#define REG_BADPAT      2

/*
 * Note that we don't follow the POSIX API exactly because k5_regexec()
 * doesn't declare regex_t as const; that's so we can store an error
 * string.
 */
int k5_regcomp(regex_t *preg, const char *pattern, int flags);
int k5_regexec(regex_t *preg, const char *string, size_t,
               regmatch_t pmatch[], int flags);
size_t k5_regerror(int code, const regex_t *preg, char *errmsg,
                   size_t errmsg_size);
void k5_regfree(regex_t *preg);

#define regcomp k5_regcomp
#define regexec k5_regexec
#define regerror k5_regerror
#define regfree k5_regfree

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* _WIN32 */
#endif /* _K5_REGEX_H_ */
