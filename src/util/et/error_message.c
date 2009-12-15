/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 1997,2000,2001,2004,2008 by Massachusetts Institute of Technology
 *
 * Copyright 1987, 1988 by MIT Student Information Processing Board
 *
 * Permission to use, copy, modify, and distribute this software
 * and its documentation for any purpose and without fee is
 * hereby granted, provided that the above copyright notice
 * appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation,
 * and that the names of M.I.T. and the M.I.T. S.I.P.B. not be
 * used in advertising or publicity pertaining to distribution
 * of the software without specific, written prior permission.
 * Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. and the M.I.T. S.I.P.B. make no representations about
 * the suitability of this software for any purpose.  It is
 * provided "as is" without express or implied warranty.
 */

#include "autoconf.h"
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>
#include "com_err.h"
#include "error_table.h"
#include "k5-platform.h"

#if !defined(HAVE_STRERROR) && !defined(SYS_ERRLIST_DECLARED)
extern char const * const sys_errlist[];
extern const int sys_nerr;
#endif

/*@null@*/ static struct et_list * _et_list = (struct et_list *) NULL;
/*@null@*//*@only@*/static struct dynamic_et_list * et_list_dynamic;
static k5_mutex_t et_list_lock = K5_MUTEX_PARTIAL_INITIALIZER;
static int terminated = 0;      /* for debugging shlib fini sequence errors */

MAKE_INIT_FUNCTION(com_err_initialize);
MAKE_FINI_FUNCTION(com_err_terminate);

int com_err_initialize(void)
{
    int err;
#ifdef SHOW_INITFINI_FUNCS
    printf("com_err_initialize\n");
#endif
    terminated = 0;
    err = k5_mutex_finish_init(&et_list_lock);
    if (err)
        return err;
    err = k5_mutex_finish_init(&com_err_hook_lock);
    if (err)
        return err;
    err = k5_key_register(K5_KEY_COM_ERR, free);
    if (err)
        return err;
    return 0;
}

void com_err_terminate(void)
{
    struct dynamic_et_list *e, *enext;
    if (! INITIALIZER_RAN(com_err_initialize) || PROGRAM_EXITING()) {
#ifdef SHOW_INITFINI_FUNCS
        printf("com_err_terminate: skipping\n");
#endif
        return;
    }
#ifdef SHOW_INITFINI_FUNCS
    printf("com_err_terminate\n");
#endif
    k5_key_delete(K5_KEY_COM_ERR);
    k5_mutex_destroy(&com_err_hook_lock);
    if (k5_mutex_lock(&et_list_lock) != 0)
        return;
    for (e = et_list_dynamic; e; e = enext) {
        enext = e->next;
        free(e);
    }
    k5_mutex_unlock(&et_list_lock);
    k5_mutex_destroy(&et_list_lock);
    terminated = 1;
}

#ifndef DEBUG_TABLE_LIST
#define dprintf(X)
#else
#define dprintf(X) printf X
#endif

static char *
get_thread_buffer ()
{
    char *cp;
    cp = k5_getspecific(K5_KEY_COM_ERR);
    if (cp == NULL) {
        cp = malloc(ET_EBUFSIZ);
        if (cp == NULL) {
            return NULL;
        }
        if (k5_setspecific(K5_KEY_COM_ERR, cp) != 0) {
            free(cp);
            return NULL;
        }
    }
    return cp;
}

const char * KRB5_CALLCONV
error_message(long code)
/*@modifies internalState@*/
{
    unsigned long offset;
    unsigned long l_offset;
    struct et_list *et;
    struct dynamic_et_list *det;
    unsigned long table_num;
    int started = 0;
    unsigned int divisor = 100;
    char *cp, *cp1;
    const struct error_table *table;
    int merr;

    l_offset = (unsigned long)code & ((1<<ERRCODE_RANGE)-1);
    offset = l_offset;
    table_num = ((unsigned long)code - l_offset) & ERRCODE_MAX;
    if (table_num == 0
#ifdef __sgi
        /* Irix 6.5 uses a much bigger table than other UNIX
           systems I've looked at, but the table is sparse.  The
           sparse entries start around 500, but sys_nerr is only
           152.  */
        || (code > 0 && code <= 1600)
#endif
    ) {
        if (code == 0)
            goto oops;

        /* This could trip if int is 16 bits.  */
        if ((unsigned long)(int)code != (unsigned long)code)
            abort ();
#ifdef HAVE_STRERROR_R
        cp = get_thread_buffer();
        if (cp && strerror_r((int) code, cp, ET_EBUFSIZ) == 0)
            return cp;
#endif
#ifdef HAVE_STRERROR
        cp = strerror((int) code);
        if (cp)
            return cp;
#elif defined HAVE_SYS_ERRLIST
        if (offset < sys_nerr)
            return(sys_errlist[offset]);
#endif
        goto oops;
    }

    if (CALL_INIT_FUNCTION(com_err_initialize))
        return 0;
    merr = k5_mutex_lock(&et_list_lock);
    if (merr)
        goto oops;
    dprintf (("scanning static list for %x\n", table_num));
    for (et = _et_list; et != NULL; et = et->next) {
        if (et->table == NULL)
            continue;
        dprintf (("\t%x = %s\n", et->table->base & ERRCODE_MAX,
                  et->table->msgs[0]));
        if ((et->table->base & ERRCODE_MAX) == table_num) {
            table = et->table;
            goto found;
        }
    }
    dprintf (("scanning dynamic list for %x\n", table_num));
    for (det = et_list_dynamic; det != NULL; det = det->next) {
        dprintf (("\t%x = %s\n", det->table->base & ERRCODE_MAX,
                  det->table->msgs[0]));
        if ((det->table->base & ERRCODE_MAX) == table_num) {
            table = det->table;
            goto found;
        }
    }
    goto no_table_found;

found:
    k5_mutex_unlock(&et_list_lock);
    dprintf (("found it!\n"));
    /* This is the right table */

    /* This could trip if int is 16 bits.  */
    if ((unsigned long)(unsigned int)offset != offset)
        goto no_table_found;

    if (table->n_msgs <= (unsigned int) offset)
        goto no_table_found;

    return table->msgs[offset];

no_table_found:
    k5_mutex_unlock(&et_list_lock);
#if defined(_WIN32)
    /*
     * WinSock errors exist in the 10000 and 11000 ranges
     * but might not appear if WinSock is not initialized
     */
    if (code >= WSABASEERR && code < WSABASEERR + 1100) {
        table_num = 0;
        offset = code;
        divisor = WSABASEERR;
    }
#endif
#ifdef _WIN32
    {
        LPVOID msgbuf;

        if (! FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                             NULL /* lpSource */,
                             (DWORD) code,
                             MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                             (LPTSTR) &msgbuf,
                             (DWORD) 0 /*sizeof(buffer)*/,
                             NULL /* va_list */ )) {
            /*
             * WinSock errors exist in the 10000 and 11000 ranges
             * but might not appear if WinSock is not initialized
             */
            if (code >= WSABASEERR && code < WSABASEERR + 1100) {
                table_num = 0;
                offset = code;
                divisor = 10000;
            }

            goto oops;
        } else {
            char *buffer;
            cp = get_thread_buffer();
            if (cp == NULL)
                return "Unknown error code";
            buffer = cp;
            strncpy(buffer, msgbuf, ET_EBUFSIZ);
            buffer[ET_EBUFSIZ-1] = '\0';
            cp = buffer + strlen(buffer) - 1;
            if (*cp == '\n') *cp-- = '\0';
            if (*cp == '\r') *cp-- = '\0';
            if (*cp == '.') *cp-- = '\0';

            LocalFree(msgbuf);
            return buffer;
        }
    }
#endif

oops:

    cp = get_thread_buffer();
    if (cp == NULL)
        return "Unknown error code";
    cp1 = cp;
    strlcpy(cp, "Unknown code ", ET_EBUFSIZ);
    cp += sizeof("Unknown code ") - 1;
    if (table_num != 0L) {
        (void) error_table_name_r(table_num, cp);
        while (*cp != '\0')
            cp++;
        *cp++ = ' ';
    }
    while (divisor > 1) {
        if (started != 0 || offset >= divisor) {
            *cp++ = '0' + offset / divisor;
            offset %= divisor;
            started++;
        }
        divisor /= 10;
    }
    *cp++ = '0' + offset;
    *cp = '\0';
    return(cp1);
}

/*@-incondefs@*/ /* _et_list is global on unix but not in header annotations */
errcode_t KRB5_CALLCONV
add_error_table(/*@dependent@*/ const struct error_table * et)
/*@modifies _et_list,et_list_dynamic@*/
/*@=incondefs@*/
{
    struct dynamic_et_list *del;
    int merr;

    if (CALL_INIT_FUNCTION(com_err_initialize))
        return 0;

    del = (struct dynamic_et_list *)malloc(sizeof(struct dynamic_et_list));
    if (del == NULL)
        return ENOMEM;

    del->table = et;

    merr = k5_mutex_lock(&et_list_lock);
    if (merr) {
        free(del);
        return merr;
    }
    del->next = et_list_dynamic;
    et_list_dynamic = del;
    return k5_mutex_unlock(&et_list_lock);
}

/*@-incondefs@*/ /* _et_list is global on unix but not in header annotations */
errcode_t KRB5_CALLCONV
remove_error_table(const struct error_table * et)
/*@modifies _et_list,et_list_dynamic@*/
/*@=incondefs@*/
{
    struct dynamic_et_list **del;
    struct et_list **el;
    int merr;

    if (CALL_INIT_FUNCTION(com_err_initialize))
        return 0;
    merr = k5_mutex_lock(&et_list_lock);
    if (merr)
        return merr;

    /* Remove the entry that matches the error table instance.  Prefer dynamic
       entries, but if there are none, check for a static one too.  */
    for (del = &et_list_dynamic; *del; del = &(*del)->next)
        if ((*del)->table == et) {
            /*@only@*/ struct dynamic_et_list *old = *del;
            *del = old->next;
            free (old);
            return k5_mutex_unlock(&et_list_lock);
        }
    for (el = &_et_list; *el; el = &(*el)->next)
        if ((*el)->table == et) {
            struct et_list *old = *el;
            *el = old->next;
            old->next = NULL;
            old->table = NULL;
            return k5_mutex_unlock(&et_list_lock);
        }
    k5_mutex_unlock(&et_list_lock);
    return ENOENT;
}

int com_err_finish_init()
{
    return CALL_INIT_FUNCTION(com_err_initialize);
}
