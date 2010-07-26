/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved
 * 
 * Copyright (C) 2010 by the Massachusetts Institute of Technology.
 * All rights reserved.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 *
 * Sample password quality plugin which checks for dictionary word combos
 */


#include <krb5.h>
#include <krb5/pwqual_plugin.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

typedef struct combo_moddata_st {
    char **word_list;        /* list of word pointers */
    char *word_block;        /* actual word data */
    size_t word_count; /* number of words */
} *combo_moddata;

static int
word_compare(const void *s1, const void *s2)
{
    return (strcasecmp(*(const char **)s1, *(const char **)s2));
}

static krb5_error_code
init_dict(combo_moddata dict, const char *dict_file)
{
    int fd;
    size_t len, i;
    char *p, *t;
    struct stat sb;

    if (dict_file == NULL)
        return 0;
    if ((fd = open(dict_file, O_RDONLY)) == -1)
        return (errno == ENOENT) ? 0 : errno;
    if (fstat(fd, &sb) == -1) {
        close(fd);
        return errno;
    }
    if ((dict->word_block = malloc(sb.st_size + 1)) == NULL)
        return ENOMEM;
    if (read(fd, dict->word_block, sb.st_size) != sb.st_size)
        return errno;
    (void) close(fd);
    dict->word_block[sb.st_size] = '\0';

    p = dict->word_block;
    len = sb.st_size;
    while(len > 0 && (t = memchr(p, '\n', len)) != NULL) {
        *t = '\0';
        len -= t - p + 1;
        p = t + 1;
        dict->word_count++;
    }
    if ((dict->word_list = malloc(dict->word_count * sizeof(char *))) == NULL)
        return ENOMEM;
    p = dict->word_block;
    for (i = 0; i < dict->word_count; i++) {
        dict->word_list[i] = p;
        p += strlen(p) + 1;
    }
    qsort(dict->word_list, dict->word_count, sizeof(char *), word_compare);
    return 0;
}

static void
destroy_dict(combo_moddata dict)
{
    if (dict == NULL)
        return;
    free(dict->word_list);
    free(dict->word_block);
    free(dict);
    return;
}

static krb5_error_code
combo_open(krb5_context context, const char *dict_file,
           krb5_pwqual_moddata *data)
{
    krb5_error_code ret;
    combo_moddata dict;

    *data = NULL;

    /* Allocate and initialize a dictionary structure. */
    dict = malloc(sizeof(*dict));
    if (dict == NULL)
        return ENOMEM;
    dict->word_list = NULL;
    dict->word_block = NULL;
    dict->word_count = 0;

    /* Fill in the dictionary structure with data from dict_file. */
    ret = init_dict(dict, dict_file);
    if (ret != 0) {
        destroy_dict(dict);
        return ret;
    }

    *data = (krb5_pwqual_moddata)dict;
    return 0;
}

static krb5_error_code
combo_check(krb5_context context, krb5_pwqual_moddata data,
            const char *password, kadm5_policy_ent_t policy,
            krb5_principal princ)
{
    combo_moddata dict = (combo_moddata)data;
    size_t i, j, len, pwlen;
    const char *remainder;

    if (dict->word_list == NULL)
        return 0;

    pwlen = strlen(password);
    for (i = 0; i < dict->word_count; i++) {
        len = strlen(dict->word_list[i]);
        if (len >= pwlen)
            continue;
        if (strncasecmp(password, dict->word_list[i], len) != 0)
            continue;
        remainder = password + len;
        for (i = 0; i < dict->word_count; i++) {
            if (strcasecmp(remainder, dict->word_list[i]) == 0)
                return KADM5_PASS_Q_DICT;
        }
    }

    return 0;
}

static void
combo_close(krb5_context context, krb5_pwqual_moddata data)
{
    destroy_dict((combo_moddata)data);
}

krb5_error_code
pwqual_combo_initvt(krb5_context context, int maj_ver, int min_ver,
                    krb5_plugin_vtable vtable)
{
    krb5_pwqual_vtable vt;

    if (maj_ver != 1)
        return EINVAL; /* XXX create error code */
    vt = (krb5_pwqual_vtable)vtable;
    vt->open = combo_open;
    vt->check = combo_check;
    vt->close = combo_close;
    return 0;
}
