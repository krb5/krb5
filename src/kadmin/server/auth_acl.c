/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* kadmin/server/auth_acl.c */
/*
 * Copyright 1995-2004, 2007, 2008, 2017 by the Massachusetts Institute of
 * Technology.  All Rights Reserved.
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
 */

#include "k5-int.h"
#include <syslog.h>
#include <kadm5/admin.h>
#include "adm_proto.h"
#include "auth_acl.h"
#include <ctype.h>

struct acl_op_table {
    char op;
    uint32_t mask;
};

struct acl_entry {
    struct acl_entry *next;
    krb5_principal client;
    uint32_t op_allowed;
    krb5_principal target;
    struct kadm5_auth_restrictions *rs;
};

static const struct acl_op_table acl_op_table[] = {
    { 'a', ACL_ADD },
    { 'd', ACL_DELETE },
    { 'm', ACL_MODIFY },
    { 'c', ACL_CHANGEPW },
    { 'i', ACL_INQUIRE },
    { 'l', ACL_LIST },
    { 'p', ACL_IPROP },
    { 's', ACL_SETKEY },
    { 'x', ACL_ALL_MASK },
    { '*', ACL_ALL_MASK },
    { 'e', ACL_EXTRACT },
    { '\0', 0 }
};

struct wildstate {
    int nwild;
    const krb5_data *backref[9];
};

struct acl_state {
    struct acl_entry *list;
};

static struct acl_state aclstate;

/*
 * Get a line from the ACL file.  Lines ending with \ are continued on the next
 * line.  The caller should set *lineno to 1 and *incr to 0 before the first
 * call.  On successful return, *lineno will be the line number of the line
 * read.  Return a pointer to the line on success, or NULL on end of file or
 * read failure.
 */
static char *
get_line(FILE *fp, const char *fname, int *lineno, int *incr)
{
    const int chunksize = 128;
    struct k5buf buf;
    size_t old_len;
    char *p;

    /* Increment *lineno by the number of newlines from the last line. */
    *lineno += *incr;
    *incr = 0;

    k5_buf_init_dynamic(&buf);
    for (;;) {
        /* Read at least part of a line into the buffer. */
        old_len = buf.len;
        p = k5_buf_get_space(&buf, chunksize);
        if (p == NULL)
            return NULL;

        if (fgets(p, chunksize, fp) == NULL) {
            /* We reached the end.  Return a final unterminated line, if there
             * is one and it's not a comment. */
            k5_buf_truncate(&buf, old_len);
            if (buf.len > 0 && *(char *)buf.data != '#')
                return buf.data;
            k5_buf_free(&buf);
            return NULL;
        }

        /* Set the buffer length based on the actual amount read. */
        k5_buf_truncate(&buf, old_len + strlen(p));

        p = buf.data;
        if (buf.len > 0 && p[buf.len - 1] == '\n') {
            /* We have a complete raw line in the buffer. */
            (*incr)++;
            k5_buf_truncate(&buf, buf.len - 1);
            if (buf.len > 0 && p[buf.len - 1] == '\\') {
                /* This line has a continuation marker; keep reading. */
                k5_buf_truncate(&buf, buf.len - 1);
            } else if (buf.len == 0 || *p == '#') {
                /* This line is empty or a comment.  Start over. */
                *lineno += *incr;
                *incr = 0;
                k5_buf_truncate(&buf, 0);
            } else {
                return buf.data;
            }
        }
    }
}

/*
 * Parse a restrictions field.  Return NULL on failure.
 *
 * Allowed restrictions are:
 *      [+-]flagname            (recognized by krb5_flagspec_to_mask)
 *                              flag is forced to indicated value
 *      -clearpolicy            policy is forced clear
 *      -policy pol             policy is forced to be "pol"
 *      -{expire,pwexpire,maxlife,maxrenewlife} deltat
 *                              associated value will be forced to
 *                              MIN(deltat, requested value)
 */
static struct kadm5_auth_restrictions *
parse_restrictions(const char *str, const char *fname)
{
    char *copy = NULL, *token, *arg, *save;
    const char *delims = "\t\n\f\v\r ,";
    krb5_deltat delta;
    struct kadm5_auth_restrictions *rs;

    copy = strdup(str);
    if (copy == NULL)
        return NULL;

    rs = calloc(1, sizeof(*rs));
    if (rs == NULL) {
        free(copy);
        return NULL;
    }

    rs->forbid_attrs = ~(krb5_flags)0;
    for (token = strtok_r(copy, delims, &save); token != NULL;
         token = strtok_r(NULL, delims, &save)) {

        if (krb5_flagspec_to_mask(token, &rs->require_attrs,
                                  &rs->forbid_attrs) == 0) {
            rs->mask |= KADM5_ATTRIBUTES;
            continue;
        }

        if (strcmp(token, "-clearpolicy") == 0) {
            rs->mask |= KADM5_POLICY_CLR;
            continue;
        }

        /* Everything else needs an argument. */
        arg = strtok_r(NULL, delims, &save);
        if (arg == NULL)
            goto error;

        if (strcmp(token, "-policy") == 0) {
            if (rs->policy != NULL)
                goto error;
            rs->policy = strdup(arg);
            if (rs->policy == NULL)
                goto error;
            rs->mask |= KADM5_POLICY;
            continue;
        }

        /* All other arguments must be a deltat. */
        if (krb5_string_to_deltat(arg, &delta) != 0)
            goto error;

        if (strcmp(token, "-expire") == 0) {
            rs->princ_lifetime = delta;
            rs->mask |= KADM5_PRINC_EXPIRE_TIME;
        } else if (strcmp(token, "-pwexpire") == 0) {
            rs->pw_lifetime = delta;
            rs->mask |= KADM5_PW_EXPIRATION;
        } else if (strcmp(token, "-maxlife") == 0) {
            rs->max_life = delta;
            rs->mask |= KADM5_MAX_LIFE;
        } else if (strcmp(token, "-maxrenewlife") == 0) {
            rs->max_renewable_life = delta;
            rs->mask |= KADM5_MAX_RLIFE;
        } else {
            goto error;
        }
    }

    free(copy);
    return rs;

error:
    krb5_klog_syslog(LOG_ERR, _("%s: invalid restrictions: %s"), fname, str);
    free(copy);
    free(rs->policy);
    free(rs);
    return NULL;
}

static void
free_acl_entry(struct acl_entry *entry)
{
    krb5_free_principal(NULL, entry->client);
    krb5_free_principal(NULL, entry->target);
    if (entry->rs != NULL) {
        free(entry->rs->policy);
        free(entry->rs);
    }
    free(entry);
}

/* Parse the four fields of an ACL entry and return a structure representing
 * it.  Log a message and return NULL on error. */
static struct acl_entry *
parse_entry(krb5_context context, const char *client, const char *ops,
            const char *target, const char *rs, const char *line,
            const char *fname)
{
    struct acl_entry *entry;
    const char *op;
    char rop;
    int t;

    entry = calloc(1, sizeof(*entry));
    if (entry == NULL)
        return NULL;

    for (op = ops; *op; op++) {
        rop = isupper((unsigned char)*op) ? tolower((unsigned char)*op) : *op;
        for (t = 0; acl_op_table[t].op; t++) {
            if (rop == acl_op_table[t].op) {
                if (rop == *op)
                    entry->op_allowed |= acl_op_table[t].mask;
                else
                    entry->op_allowed &= ~acl_op_table[t].mask;
                break;
            }
        }
        if (!acl_op_table[t].op) {
            krb5_klog_syslog(LOG_ERR,
                             _("Unrecognized ACL operation '%c' in %s"),
                             *op, line);
            goto error;
        }
    }

    if (strcmp(client, "*") != 0) {
        if (krb5_parse_name(context, client, &entry->client) != 0) {
            krb5_klog_syslog(LOG_ERR, _("Cannot parse client principal '%s'"),
                             client);
            goto error;
        }
    }

    if (target != NULL && strcmp(target, "*") != 0) {
        if (krb5_parse_name(context, target, &entry->target) != 0) {
            krb5_klog_syslog(LOG_ERR, _("Cannot parse target principal '%s'"),
                             target);
            goto error;
        }
    }

    if (rs != NULL) {
        entry->rs = parse_restrictions(rs, fname);
        if (entry->rs == NULL)
            goto error;
    }

    return entry;

error:
    free_acl_entry(entry);
    return NULL;
}

/* Parse the contents of an ACL line. */
static struct acl_entry *
parse_line(krb5_context context, const char *line, const char *fname)
{
    struct acl_entry *entry = NULL;
    char *copy;
    char *client, *client_end, *ops, *ops_end, *target, *target_end, *rs, *end;
    const char *ws = "\t\n\f\v\r ,";

    /*
     * Format:
     *  entry ::= [<whitespace>] <principal> <whitespace> <opstring>
     *            [<whitespace> <target> [<whitespace> <restrictions>
     *                                    [<whitespace>]]]
     */

    /* Make a copy and remove any trailing whitespace. */
    copy = strdup(line);
    if (copy == NULL)
        return NULL;
    end = copy + strlen(copy);
    while (end > copy && isspace(end[-1]))
        *--end = '\0';

    /* Find the beginning and end of each field.  The end of restrictions is
     * the end of copy. */
    client = copy + strspn(copy, ws);
    client_end = client + strcspn(client, ws);
    ops = client_end + strspn(client_end, ws);
    ops_end = ops + strcspn(ops, ws);
    target = ops_end + strspn(ops_end, ws);
    target_end = target + strcspn(target, ws);
    rs = target_end + strspn(target_end, ws);

    /* Terminate the first three fields. */
    *client_end = *ops_end = *target_end = '\0';

    /* The last two fields are optional; represent them as NULL if not present.
     * The first two fields are required. */
    if (*target == '\0')
        target = NULL;
    if (*rs == '\0')
        rs = NULL;
    if (*client != '\0' && *ops != '\0')
        entry = parse_entry(context, client, ops, target, rs, line, fname);
    free(copy);
    return entry;
}

/* Impose restrictions, modifying *rec and *mask. */
krb5_error_code
acl_impose_restrictions(krb5_context context, kadm5_principal_ent_rec *rec,
                        long *mask, struct kadm5_auth_restrictions *rs)
{
    krb5_error_code ret;
    krb5_timestamp now;

    if (rs == NULL)
        return 0;
    if (rs->mask & (KADM5_PRINC_EXPIRE_TIME | KADM5_PW_EXPIRATION)) {
        ret = krb5_timeofday(context, &now);
        if (ret)
            return ret;
    }

    if (rs->mask & KADM5_ATTRIBUTES) {
        rec->attributes |= rs->require_attrs;
        rec->attributes &= rs->forbid_attrs;
        *mask |= KADM5_ATTRIBUTES;
    }
    if (rs->mask & KADM5_POLICY_CLR) {
        *mask &= ~KADM5_POLICY;
        *mask |= KADM5_POLICY_CLR;
    } else if (rs->mask & KADM5_POLICY) {
        if (rec->policy != NULL && strcmp(rec->policy, rs->policy) != 0) {
            free(rec->policy);
            rec->policy = NULL;
        }
        if (rec->policy == NULL) {
            rec->policy = strdup(rs->policy);  /* XDR will free it */
            if (!rec->policy)
                return ENOMEM;
        }
        *mask |= KADM5_POLICY;
    }
    if (rs->mask & KADM5_PRINC_EXPIRE_TIME) {
        if (!(*mask & KADM5_PRINC_EXPIRE_TIME) ||
            ts_after(rec->princ_expire_time, ts_incr(now, rs->princ_lifetime)))
            rec->princ_expire_time = now + rs->princ_lifetime;
        *mask |= KADM5_PRINC_EXPIRE_TIME;
    }
    if (rs->mask & KADM5_PW_EXPIRATION) {
        if (!(*mask & KADM5_PW_EXPIRATION) ||
            ts_after(rec->pw_expiration, ts_incr(now, rs->pw_lifetime)))
            rec->pw_expiration = now + rs->pw_lifetime;
        *mask |= KADM5_PW_EXPIRATION;
    }
    if (rs->mask & KADM5_MAX_LIFE) {
        if (!(*mask & KADM5_MAX_LIFE) || rec->max_life > rs->max_life)
            rec->max_life = rs->max_life;
        *mask |= KADM5_MAX_LIFE;
    }
    if (rs->mask & KADM5_MAX_RLIFE) {
        if (!(*mask & KADM5_MAX_RLIFE) ||
            rec->max_renewable_life > rs->max_renewable_life)
            rec->max_renewable_life = rs->max_renewable_life;
        *mask |= KADM5_MAX_RLIFE;
    }
    return 0;
}

/* Free all ACL entries. */
static void
free_acl_entries(struct acl_state *state)
{
    struct acl_entry *entry, *next;

    for (entry = state->list; entry != NULL; entry = next) {
        next = entry->next;
        free_acl_entry(entry);
    }
    state->list = NULL;
}

/* Open and parse the ACL file. */
static void
load_acl_file(krb5_context context, const char *fname, struct acl_state *state)
{
    FILE *fp;
    char *line;
    struct acl_entry **entry_slot;
    int lineno, incr;

    state->list = NULL;

    /* Open the ACL file for reading. */
    fp = fopen(fname, "r");
    if (fp == NULL) {
        krb5_klog_syslog(LOG_ERR, _("%s while opening ACL file %s"),
                         error_message(errno), fname);
        return;
    }

    set_cloexec_file(fp);
    lineno = 1;
    incr = 0;
    entry_slot = &state->list;

    /* Get a non-comment line. */
    while ((line = get_line(fp, fname, &lineno, &incr)) != NULL) {
        /* Parse it.  Fail out on syntax error. */
        *entry_slot = parse_line(context, line, fname);
        if (*entry_slot == NULL) {
            krb5_klog_syslog(LOG_ERR,
                             _("%s: syntax error at line %d <%.10s...>"),
                             fname, lineno, line);
            free_acl_entries(state);
            free(line);
            fclose(fp);
            return;
        }
        entry_slot = &(*entry_slot)->next;
        free(line);
    }

    fclose(fp);
}

/*
 * See if two data entries match.  If e1 is a wildcard (matching a whole
 * component only) and targetflag is false, save an alias to e2 into
 * ws->backref.  If e1 is a back-reference and targetflag is true, compare the
 * appropriate entry in ws->backref to e2.  If ws is NULL, do not store or
 * match back-references.
 */
static krb5_boolean
match_data(const krb5_data *e1, const krb5_data *e2, krb5_boolean targetflag,
           struct wildstate *ws)
{
    int n;

    if (data_eq_string(*e1, "*")) {
        if (ws != NULL && !targetflag) {
            if (ws->nwild < 9)
                ws->backref[ws->nwild++] = e2;
        }
        return TRUE;
    }

    if (ws != NULL && targetflag && e1->length == 2 && e1->data[0] == '*' &&
        e1->data[1] >= '1' && e1->data[1] <= '9') {
        n = e1->data[1] - '1';
        if (n >= ws->nwild)
            return FALSE;
        return data_eq(*e2, *ws->backref[n]);
    } else {
        return data_eq(*e2, *e1);
    }
}

/* Return true if p1 matches p2.  p1 may contain wildcards if targetflag is
 * false, or backreferences if it is true. */
static krb5_boolean
match_princ(krb5_const_principal p1, krb5_const_principal p2,
            krb5_boolean targetflag, struct wildstate *ws)
{
    int i;

    /* The principals must be of the same length. */
    if (p1->length != p2->length)
        return FALSE;

    /* The realm must match, and does not interact with wildcard state. */
    if (!match_data(&p1->realm, &p2->realm, targetflag, NULL))
        return FALSE;

    /* All components of the principals must match. */
    for (i = 0; i < p1->length; i++) {
        if (!match_data(&p1->data[i], &p2->data[i], targetflag, ws))
            return FALSE;
    }

    return TRUE;
}

/* Find an ACL entry matching principal and target_principal.  Return NULL if
 * none is found. */
static struct acl_entry *
find_entry(struct acl_state *state, krb5_const_principal client,
           krb5_const_principal target)
{
    struct acl_entry *entry;
    struct wildstate ws;

    for (entry = state->list; entry != NULL; entry = entry->next) {
        memset(&ws, 0, sizeof(ws));
        if (entry->client != NULL) {
            if (!match_princ(entry->client, client, FALSE, &ws))
                continue;
        }

        if (entry->target != NULL) {
            if (target == NULL)
                continue;
            if (!match_princ(entry->target, target, TRUE, &ws))
                continue;
        }

        return entry;
    }

    return NULL;
}

/* Initialize the ACL context. */
krb5_error_code
acl_init(krb5_context context, const char *acl_file)
{
    load_acl_file(context, acl_file, &aclstate);
    return 0;
}

/* Terminate the ACL context. */
void
acl_finish(krb5_context context)
{
    free_acl_entries(&aclstate);
}

/* Return true if op is permitted for this principal.  Set *rs_out (if not
 * NULL) according to any restrictions in the ACL entry. */
krb5_boolean
acl_check(krb5_context context, krb5_const_principal client, uint32_t op,
          krb5_const_principal target, struct kadm5_auth_restrictions **rs_out)
{
    struct acl_entry *entry;

    if (rs_out != NULL)
        *rs_out = NULL;

    entry = find_entry(&aclstate, client, target);
    if (entry == NULL)
        return FALSE;
    if (!(entry->op_allowed & op))
        return FALSE;

    if (rs_out != NULL && entry->rs != NULL && entry->rs->mask)
        *rs_out = entry->rs;

    return TRUE;
}
