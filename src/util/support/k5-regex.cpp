/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* vi: set softtabstop=4 shiftwidth=4 tabstop=4 expandtab ai: */
/* k5-regex.cpp - Glue routines to std::regex functions */

/*
 * These functions provide a mostly-complete POSIX regex(3)
 * implementation that uses the C++ std::regex classes.  Deficiencies
 * are noted below.
 */

#include <k5-platform.h>
#include <string.h>
#include "k5-regex.h"

#include <regex>

/*
 * Our implementation of regcomp() which calls into std::regex.  We
 * implement the standard flags but none of the non-portable extensions
 * on some platforms
 */

extern "C" int
k5_regcomp(regex_t *preg, const char *pattern, int cflags)
{
    std::regex *r;
    std::regex_constants::syntax_option_type flags;
    int retcode = 0;

    if (cflags & REG_EXTENDED)
        flags = std::regex::extended;
    else
        flags = std::regex::basic;

    if (cflags & REG_ICASE)
        flags |= std::regex::icase;

    /*
     * If std::regex::nosubs is set then we won't get any submatches,
     * but we don't need to do anything here, regexec() will handle it
     * just fine.
     */

    if (cflags & REG_NOSUB)
        flags |= std::regex::nosubs;

    /*
     * If regex_t is allocated on the stack we can't guarantee that
     * the regex pointer is initialized to NULL so calling regfree()
     * on that might fail.  Set the regex pointer to NULL in case
     * the regular expression compilation fails.
     */

    preg->regex = NULL;
    preg->re_nsub = 0;
    preg->regerrmsg[0] = '\0';
    preg->regerrlen = 0;

    try {
        r = new std::regex(pattern, flags);
        preg->regex = r;
        preg->re_nsub = r->mark_count();
    } catch (std::regex_error& e) {
        /*
         * Save the error message in regerrmsg.  We don't actually use
         * the error code for anything; return REG_BADPAT for everything.
         */
        preg->regerrlen = strlen(e.what());
        strncpy(preg->regerrmsg, e.what(), sizeof(preg->regerrmsg));
        preg->regerrmsg[sizeof(preg->regerrmsg) - 1] = '\0';
        retcode = REG_BADPAT;
    }

    return retcode;
}

extern "C" int
k5_regexec(regex_t *preg, const char *string, size_t nmatch,
           regmatch_t pmatch[], int eflags)
{
    int retcode = 0;
    unsigned int i;
    std::cmatch cm;
    std::regex_constants::match_flag_type flags =
                                        std::regex_constants::match_default;
    std::regex *r = static_cast<std::regex *>(preg->regex);

    if (eflags & REG_NOTBOL)
        flags |= std::regex_constants::match_not_bol;

    if (eflags & REG_NOTEOL)
        flags |= std::regex_constants::match_not_eol;

    try {
        if (! std::regex_search(string, cm, *r, flags))
            return REG_NOMATCH;

        /*
         * If given, fill in pmatch with the full match string and any
         * sub-matches.  If we set nosub previously we shouldn't have
         * any submatches (but should still have the first element
         * which refers to the whole match string).
         */

        for (i = 0; i < nmatch; i++) {
            /*
             * If we're past the end of the match list (cm.size()) or
             * this sub-match didn't match (!cm[i].matched()) then
             * return -1 for those array members.
             */
            if (i >= cm.size() || !cm[i].matched) {
                pmatch[i].rm_so = pmatch[i].rm_eo = -1;
            } else {
                pmatch[i].rm_so = cm.position(i);
                pmatch[i].rm_eo = cm.position(i) + cm.length(i);
            }
        }
    } catch (std::regex_error& e) {
        /* See above */
        preg->regerrlen = strlen(e.what());
        strncpy(preg->regerrmsg, e.what(), sizeof(preg->regerrmsg));
        preg->regerrmsg[sizeof(preg->regerrmsg) - 1] = '\0';
        retcode = REG_BADPAT;
    }

    return retcode;
}

/*
 * Report back an error string.  We don't use the errcode for anything, just
 * the error string stored in regex_t.  If we don't have an error string
 * return an "unknown error" message.
 */

extern "C" size_t
k5_regerror(int errcode, const regex_t *preg, char *errbuf, size_t errbuf_size)
{
    const char *err;
    size_t errlen;

    if (preg->regerrlen > 0) {
        err = preg->regerrmsg;
        errlen = preg->regerrlen;
    } else {
        err = "Unknown regular expression error";
        errlen = strlen(err);
    }

    if (errbuf && errbuf_size > 0) {
        strncpy(errbuf, err, errbuf_size);
        errbuf[errbuf_size - 1] = '\0';
    }

    return errlen;
}

extern "C" void
k5_regfree(regex_t *preg)
{
    if (preg->regex) {
        delete static_cast<std::regex *>(preg->regex);
        preg->regex = NULL;
        preg->regerrlen = 0;
    }
}
