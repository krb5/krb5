/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/krb/response_set.c - Response set implementation */
/*
 * Copyright 2012 Red Hat, Inc.
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
 * the name of Red Hat not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original Red Hat software.
 * Red Hat makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#include "k5-int.h"
#include "int-proto.h"

struct item {
    struct item *next;
    char *name;
    void *item;
    void (*free_item)(void *);
};

struct krb5_response_set_st {
    struct item *head;
};

static struct item *
get(struct item *i, const char *name)
{
    for (; i != NULL; i = i->next) {
        if (strcmp(name, i->name) == 0)
            return i;
    }
    return NULL;
}

krb5_error_code
k5_response_set_new(krb5_response_set **rset_out)
{
    *rset_out = calloc(1, sizeof(**rset_out));
    return (*rset_out == NULL) ? ENOMEM : 0;
}

void
k5_response_set_free(krb5_response_set *rset)
{
    k5_response_set_reset(rset);
    free(rset);
}

void
k5_response_set_reset(krb5_response_set *rset)
{
    struct item *i, *next;

    if (rset == NULL)
        return;
    for (i = rset->head; i != NULL; i = next) {
        next = i->next;
        i->free_item(i->item);
        free(i->name);
        free(i);
    }
    rset->head = NULL;
}

void *
k5_response_set_get_item(krb5_response_set *rsp, const char *name)
{
    struct item *i;

    i = get(rsp->head, name);
    return (i == NULL) ? NULL : i->item;
}

krb5_error_code
k5_response_set_set_item(krb5_response_set *rset, const char *name, void *item,
                         void (*free_item)(void *item))
{
    struct item *i;

    if (rset == NULL || name == NULL || item == NULL || free_item == NULL)
      return EINVAL;

    i = get(rset->head, name);
    if (i == NULL) {
        i = malloc(sizeof(struct item));
        if (i == NULL)
            return ENOMEM;
        i->name = strdup(name);
        if (i->name == NULL) {
            free(i);
            return ENOMEM;
        }
        i->next = rset->head;
        rset->head = i;
    } else {
        i->free_item(i->item);
    }

    i->item = item;
    i->free_item = free_item;
    return 0;
}
