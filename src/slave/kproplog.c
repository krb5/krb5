/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* #pragma ident        "@(#)kproplog.c 1.4     04/03/19 SMI" */

/*
 * This module will parse the update logs on the master or slave servers.
 */

#include <stdio.h>
#include <sys/types.h>
#include <time.h>
#include <limits.h>
#include <locale.h>
#include <syslog.h>
#include "k5-int.h"
#include <kdb_log.h>
#include <kadm5/admin.h>

#ifndef gettext
#define textdomain(X) 0
#endif

static char     *progname;

static void
usage()
{
    (void) fprintf(stderr, _("\nUsage: %s [-h] [-v] [-v] [-e num]\n\n"),
                   progname);
    exit(1);
}

/*
 * Print the attribute flags of principal in human readable form.
 */
static void
print_flags(unsigned int flags)
{
    unsigned int i;
    static char *prflags[] = {
        "DISALLOW_POSTDATED",     /* 0x00000001 */
        "DISALLOW_FORWARDABLE",   /* 0x00000002 */
        "DISALLOW_TGT_BASED",     /* 0x00000004 */
        "DISALLOW_RENEWABLE",     /* 0x00000008 */
        "DISALLOW_PROXIABLE",     /* 0x00000010 */
        "DISALLOW_DUP_SKEY",      /* 0x00000020 */
        "DISALLOW_ALL_TIX",       /* 0x00000040 */
        "REQUIRES_PRE_AUTH",      /* 0x00000080 */
        "REQUIRES_HW_AUTH",       /* 0x00000100 */
        "REQUIRES_PWCHANGE",      /* 0x00000200 */
        "UNKNOWN_0x00000400",     /* 0x00000400 */
        "UNKNOWN_0x00000800",     /* 0x00000800 */
        "DISALLOW_SVR",           /* 0x00001000 */
        "PWCHANGE_SERVICE",       /* 0x00002000 */
        "SUPPORT_DESMD5",         /* 0x00004000 */
        "NEW_PRINC",              /* 0x00008000 */
        "UNKNOWN_0x00010000",     /* 0x00010000 */
        "UNKNOWN_0x00020000",     /* 0x00020000 */
        "UNKNOWN_0x00040000",     /* 0x00040000 */
        "UNKNOWN_0x00080000",     /* 0x00080000 */
        "OK_AS_DELEGATE",         /* 0x00100000 */
        "OK_TO_AUTH_AS_DELEGATE", /* 0x00200000 */
        "NO_AUTH_DATA_REQUIRED",  /* 0x00400000 */

    };

    for (i = 0; i < sizeof (prflags) / sizeof (char *); i++) {
        if (flags & (krb5_flags) 1 << i)
            printf("\t\t\t%s\n", prflags[i]);
    }
}

/* ctime() for uint32_t* */
static char *
ctime_uint32(uint32_t *time32)
{
    time_t tmp;
    tmp = *time32;
    return ctime(&tmp);
}

/*
 * Display time information.
 */
static void
print_time(uint32_t *timep)
{
    if (*timep == 0L)
        printf("\t\t\tNone\n");
    else {
        printf("\t\t\t%s", ctime_uint32(timep));
    }
}

static void
print_deltat(uint32_t *deltat)
{
    krb5_error_code ret;
    static char buf[30];
    ret = krb5_deltat_to_string(*deltat, buf, sizeof(buf));
    if (ret)
        printf("\t\t\t(error)\n");
    else
        printf("\t\t\t%s\n", buf);
}

/*
 * Display string in hex primitive.
 */
static void
print_hex(const char *tag, utf8str_t *str)
{
    unsigned int i;
    unsigned int len;

    len = str->utf8str_t_len;

    (void) printf("\t\t\t%s(%d): 0x", tag, len);
    for (i = 0; i < len; i++) {
        printf("%02x", (krb5_octet) str->utf8str_t_val[i]);
    }
    (void) printf("\n");
}

/*
 * Display string primitive.
 */
static void
print_str(const char *tag, utf8str_t *str)
{
    char *dis;
    unsigned int len;

    /* + 1 for null byte */
    len = str->utf8str_t_len + 1;
    dis = (char *) malloc(len);

    if (!dis) {
        (void) fprintf(stderr, _("\nCouldn't allocate memory"));
        exit(1);
    }

    (void) snprintf(dis, len, "%s", str->utf8str_t_val);

    (void) printf("\t\t\t%s(%d): %s\n", tag, len - 1, dis);

    free(dis);
}

/*
 * Display data components.
 */
static void
print_data(const char *tag, kdbe_data_t *data)
{

    (void) printf("\t\t\tmagic: 0x%x\n", data->k_magic);

    (void) print_str(tag, &data->k_data);
}

/*
 * Display the principal components.
 */
static void
print_princ(kdbe_princ_t *princ)
{
    int i, len;
    kdbe_data_t *data;

    print_str("realm", &princ->k_realm);

    len = princ->k_components.k_components_len;
    data = princ->k_components.k_components_val;

    for (i = 0; i < len; i++, data++) {

        print_data("princ", data);
    }
}

/*
 * Display individual key.
 */
static void
print_key(kdbe_key_t *k)
{
    unsigned int i;
    utf8str_t *str;

    printf("\t\t\tver: %d\n", k->k_ver);

    printf("\t\t\tkvno: %d\n", k->k_kvno);

    for (i = 0; i < k->k_enctype.k_enctype_len; i++) {
        printf("\t\t\tenc type: 0x%x\n",
               k->k_enctype.k_enctype_val[i]);
    }

    str = k->k_contents.k_contents_val;
    for (i = 0; i < k->k_contents.k_contents_len; i++, str++) {
        print_hex("key", str);
    }
}

/*
 * Display all key data.
 */
static void
print_keydata(kdbe_key_t *keys, unsigned int len)
{
    unsigned int i;

    for (i = 0; i < len; i++, keys++) {
        print_key(keys);
    }
}

/*
 * Display TL item.
 */
static void
print_tl(kdbe_tl_t *tl)
{
    int i, len;

    printf("\t\t\ttype: 0x%x\n", tl->tl_type);

    len = tl->tl_data.tl_data_len;

    printf("\t\t\tvalue(%d): 0x", len);
    for (i = 0; i < len; i++) {
        printf("%02x", (krb5_octet) tl->tl_data.tl_data_val[i]);
    }
    printf("\n");
}

/*
 * Display TL data items.
 */
static void
print_tldata(kdbe_tl_t *tldata, int len)
{
    int i;

    printf("\t\t\titems: %d\n", len);

    for (i = 0; i < len; i++, tldata++) {
        print_tl(tldata);
    }
}

/*
 * Print the individual types if verbose mode was specified.
 * If verbose-verbose then print types along with respective values.
 */
static void
print_attr(kdbe_val_t *val, int vverbose)
{
    switch (val->av_type) {
    case AT_ATTRFLAGS:
        (void) printf(_("\t\tAttribute flags\n"));
        if (vverbose) {
            print_flags(val->kdbe_val_t_u.av_attrflags);
        }
        break;
    case AT_MAX_LIFE:
        (void) printf(_("\t\tMaximum ticket life\n"));
        if (vverbose) {
            print_deltat(&val->kdbe_val_t_u.av_max_life);
        }
        break;
    case AT_MAX_RENEW_LIFE:
        (void) printf(_("\t\tMaximum renewable life\n"));
        if (vverbose) {
            print_deltat(&val->kdbe_val_t_u.av_max_renew_life);
        }
        break;
    case AT_EXP:
        (void) printf(_("\t\tPrincipal expiration\n"));
        if (vverbose) {
            print_time(&val->kdbe_val_t_u.av_exp);
        }
        break;
    case AT_PW_EXP:
        (void) printf(_("\t\tPassword expiration\n"));
        if (vverbose) {
            print_time(&val->kdbe_val_t_u.av_pw_exp);
        }
        break;
    case AT_LAST_SUCCESS:
        (void) printf(_("\t\tLast successful auth\n"));
        if (vverbose) {
            print_time(&val->kdbe_val_t_u.av_last_success);
        }
        break;
    case AT_LAST_FAILED:
        (void) printf(_("\t\tLast failed auth\n"));
        if (vverbose) {
            print_time(&val->kdbe_val_t_u.av_last_failed);
        }
        break;
    case AT_FAIL_AUTH_COUNT:
        (void) printf(_("\t\tFailed passwd attempt\n"));
        if (vverbose) {
            (void) printf("\t\t\t%d\n",
                          val->kdbe_val_t_u.av_fail_auth_count);
        }
        break;
    case AT_PRINC:
        (void) printf(_("\t\tPrincipal\n"));
        if (vverbose) {
            print_princ(&val->kdbe_val_t_u.av_princ);
        }
        break;
    case AT_KEYDATA:
        (void) printf(_("\t\tKey data\n"));
        if (vverbose) {
            print_keydata(
                val->kdbe_val_t_u.av_keydata.av_keydata_val,
                val->kdbe_val_t_u.av_keydata.av_keydata_len);
        }
        break;
    case AT_TL_DATA:
        (void) printf(_("\t\tTL data\n"));
        if (vverbose) {
            print_tldata(
                val->kdbe_val_t_u.av_tldata.av_tldata_val,
                val->kdbe_val_t_u.av_tldata.av_tldata_len);
        }
        break;
    case AT_LEN:
        (void) printf(_("\t\tLength\n"));
        if (vverbose) {
            (void) printf("\t\t\t%d\n",
                          val->kdbe_val_t_u.av_len);
        }
        break;
    case AT_PW_LAST_CHANGE:
        (void) printf(_("\t\tPassword last changed\n"));
        if (vverbose) {
            print_time(&val->kdbe_val_t_u.av_pw_last_change);
        }
        break;
    case AT_MOD_PRINC:
        (void) printf(_("\t\tModifying principal\n"));
        if (vverbose) {
            print_princ(&val->kdbe_val_t_u.av_mod_princ);
        }
        break;
    case AT_MOD_TIME:
        (void) printf(_("\t\tModification time\n"));
        if (vverbose) {
            print_time(&val->kdbe_val_t_u.av_mod_time);
        }
        break;
    case AT_MOD_WHERE:
        (void) printf(_("\t\tModified where\n"));
        if (vverbose) {
            print_str("where",
                      &val->kdbe_val_t_u.av_mod_where);
        }
        break;
    case AT_PW_POLICY:
        (void) printf(_("\t\tPassword policy\n"));
        if (vverbose) {
            print_str("policy",
                      &val->kdbe_val_t_u.av_pw_policy);
        }
        break;
    case AT_PW_POLICY_SWITCH:
        (void) printf(_("\t\tPassword policy switch\n"));
        if (vverbose) {
            (void) printf("\t\t\t%d\n",
                          val->kdbe_val_t_u.av_pw_policy_switch);
        }
        break;
    case AT_PW_HIST_KVNO:
        (void) printf(_("\t\tPassword history KVNO\n"));
        if (vverbose) {
            (void) printf("\t\t\t%d\n",
                          val->kdbe_val_t_u.av_pw_hist_kvno);
        }
        break;
    case AT_PW_HIST:
        (void) printf(_("\t\tPassword history\n"));
        if (vverbose) {
            (void) printf("\t\t\tPW history elided\n");
        }
        break;
    } /* switch */

}
/*
 * Print the update entry information
 */
static void
print_update(kdb_hlog_t *ulog, uint32_t entry, unsigned int verbose)
{
    XDR                 xdrs;
    uint32_t            start_sno, i, j, indx;
    char                *dbprinc;
    kdb_ent_header_t    *indx_log;
    kdb_incr_update_t   upd;

    if (entry && (entry < ulog->kdb_num))
        start_sno = ulog->kdb_last_sno - entry;
    else
        start_sno = ulog->kdb_first_sno - 1;

    for (i = start_sno; i < ulog->kdb_last_sno; i++) {
        indx = i % ulog->kdb_num;

        indx_log = (kdb_ent_header_t *)INDEX(ulog, indx);

        /*
         * Check for corrupt update entry
         */
        if (indx_log->kdb_umagic != KDB_ULOG_MAGIC) {
            (void) fprintf(stderr,
                           _("Corrupt update entry\n\n"));
            exit(1);
        }

        (void) memset(&upd, 0, sizeof (kdb_incr_update_t));
        xdrmem_create(&xdrs, (char *)indx_log->entry_data,
                      indx_log->kdb_entry_size, XDR_DECODE);
        if (!xdr_kdb_incr_update_t(&xdrs, &upd)) {
            (void) printf(_("Entry data decode failure\n\n"));
            exit(1);
        }

        (void) printf("---\n");
        (void) printf(_("Update Entry\n"));

        (void) printf(_("\tUpdate serial # : %u\n"),
                      indx_log->kdb_entry_sno);

        (void) printf(_("\tUpdate operation : "));
        if (upd.kdb_deleted)
            (void) printf(_("Delete\n"));
        else
            (void) printf(_("Add\n"));

        dbprinc = malloc(upd.kdb_princ_name.utf8str_t_len + 1);
        if (dbprinc == NULL) {
            (void) printf(_("Could not allocate "
                            "principal name\n\n"));
            exit(1);
        }
        (void) strncpy(dbprinc, upd.kdb_princ_name.utf8str_t_val,
                       upd.kdb_princ_name.utf8str_t_len);
        dbprinc[upd.kdb_princ_name.utf8str_t_len] = 0;
        (void) printf(_("\tUpdate principal : %s\n"), dbprinc);

        (void) printf(_("\tUpdate size : %u\n"),
                      indx_log->kdb_entry_size);

        (void) printf(_("\tUpdate committed : %s\n"),
                      indx_log->kdb_commit ? "True" : "False");

        if (indx_log->kdb_time.seconds == 0L)
            (void) printf(_("\tUpdate time stamp : None\n"));
        else
            (void) printf(_("\tUpdate time stamp : %s"),
                          ctime_uint32(&indx_log->kdb_time.seconds));

        (void) printf(_("\tAttributes changed : %d\n"),
                      upd.kdb_update.kdbe_t_len);

        if (verbose)
            for (j = 0; j < upd.kdb_update.kdbe_t_len; j++)
                print_attr(&upd.kdb_update.kdbe_t_val[j],
                           verbose > 1 ? 1 : 0);

        xdr_free(xdr_kdb_incr_update_t, (char *)&upd);
        free(dbprinc);
    } /* for */
}

int
main(int argc, char **argv)
{
    int                 c;
    unsigned int        verbose = 0;
    bool_t              headeronly = FALSE;
    uint32_t            entry = 0;
    krb5_context        context;
    kadm5_config_params params;
    kdb_log_context     *log_ctx;
    kdb_hlog_t          *ulog = NULL;
    char                **db_args = NULL; /* XXX */

    (void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define TEXT_DOMAIN "SYS_TEST"
#endif /* TEXT_DOMAIN */

    (void) textdomain(TEXT_DOMAIN);

    progname = argv[0];

    while ((c = getopt(argc, argv, "vhe:")) != -1) {
        switch (c) {
        case 'h':
            headeronly = TRUE;
            break;
        case 'e':
            entry = atoi(optarg);
            break;
        case 'v':
            verbose++;
            break;
        default:
            usage();
        }
    }

    if (krb5_init_context(&context)) {
        (void) fprintf(stderr,
                       _("Unable to initialize Kerberos\n\n"));
        exit(1);
    }

    (void) memset(&params, 0, sizeof (params));

    if (kadm5_get_config_params(context, 1, &params, &params)) {
        (void) fprintf(stderr,
                       _("Couldn't read database_name\n\n"));
        exit(1);
    }

    (void) printf(_("\nKerberos update log (%s)\n"),
                  params.iprop_logfile);

    if (ulog_map(context, params.iprop_logfile, 0, FKPROPLOG, db_args)) {
        (void) fprintf(stderr, _("Unable to map log file %s\n\n"),
                       params.iprop_logfile);
        exit(1);
    }

    log_ctx = context->kdblog_context;
    if (log_ctx)
        ulog = log_ctx->ulog;
    else {
        (void) fprintf(stderr, _("Unable to map log file %s\n\n"),
                       params.iprop_logfile);
        exit(1);
    }

    if (ulog->kdb_hmagic != KDB_ULOG_HDR_MAGIC) {
        (void) fprintf(stderr,
                       _("Corrupt header log, exiting\n\n"));
        exit(1);
    }

    (void) printf(_("Update log dump :\n"));
    (void) printf(_("\tLog version # : %u\n"), ulog->db_version_num);
    (void) printf(_("\tLog state : "));
    switch (ulog->kdb_state) {
    case KDB_STABLE:
        (void) printf(_("Stable\n"));
        break;
    case KDB_UNSTABLE:
        (void) printf(_("Unstable\n"));
        break;
    case KDB_CORRUPT:
        (void) printf(_("Corrupt\n"));
        break;
    default:
        (void) printf(_("Unknown state: %d\n"),
                      ulog->kdb_state);
        break;
    }
    (void) printf(_("\tEntry block size : %u\n"), ulog->kdb_block);
    (void) printf(_("\tNumber of entries : %u\n"), ulog->kdb_num);

    if (ulog->kdb_last_sno == 0)
        (void) printf(_("\tLast serial # : None\n"));
    else {
        if (ulog->kdb_first_sno == 0)
            (void) printf(_("\tFirst serial # : None\n"));
        else {
            (void) printf(_("\tFirst serial # : "));
            (void) printf("%u\n", ulog->kdb_first_sno);
        }

        (void) printf(_("\tLast serial # : "));
        (void) printf("%u\n", ulog->kdb_last_sno);
    }

    if (ulog->kdb_last_time.seconds == 0L) {
        (void) printf(_("\tLast time stamp : None\n"));
    } else {
        if (ulog->kdb_first_time.seconds == 0L)
            (void) printf(_("\tFirst time stamp : None\n"));
        else {
            (void) printf(_("\tFirst time stamp : %s"),
                          ctime_uint32(&ulog->kdb_first_time.seconds));
        }

        (void) printf(_("\tLast time stamp : %s\n"),
                      ctime_uint32(&ulog->kdb_last_time.seconds));
    }

    if ((!headeronly) && ulog->kdb_num) {
        print_update(ulog, entry, verbose);
    }

    (void) printf("\n");

    return (0);
}
