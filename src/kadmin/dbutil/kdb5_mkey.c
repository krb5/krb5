/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <time.h>
#include <k5-int.h>
#include <kdb.h>
#include <kadm5/server_internal.h>
#include <kadm5/admin.h>
#include <adm_proto.h>
#include "kdb5_util.h"

extern krb5_keyblock master_keyblock; /* current mkey */
extern krb5_principal master_princ;
extern krb5_keylist_node *master_keylist;
extern krb5_data master_salt;
extern char *mkey_password;
extern char *progname;
extern int exit_status;
extern kadm5_config_params global_params;
extern krb5_context util_context;
extern time_t get_date(char *);

static char *strdate(krb5_timestamp when)
{
    struct tm *tm;
    static char out[40];

    time_t lcltim = when;
    tm = localtime(&lcltim);
    strftime(out, sizeof(out), "%a %b %d %H:%M:%S %Z %Y", tm);
    return out;
}

void
kdb5_add_mkey(int argc, char *argv[])
{
    int optchar;
    krb5_error_code retval;
    char *mkey_fullname;
    char *pw_str = 0;
    unsigned int pw_size = 0;
    int do_stash = 0, nentries = 0;
    int old_key_data_count, i, j;
    krb5_boolean more = 0;
    krb5_data pwd;
    krb5_kvno old_kvno, new_mkey_kvno;
    krb5_keyblock new_master_keyblock;
    krb5_keyblock  plainkey;
    krb5_key_data tmp_key_data, *old_key_data, *key_data;
    krb5_enctype new_master_enctype = DEFAULT_KDC_ENCTYPE;
    char *new_mkey_password;
    krb5_db_entry master_entry;
    krb5_timestamp now;
    krb5_mkey_aux_node  *mkey_aux_data_head, **mkey_aux_data,
                        *cur_mkey_aux_data, *next_mkey_aux_data;

    /*
     * The command table entry for this command causes open_db_and_mkey() to be
     * called first to open the KDB and get the current mkey.
     */

    while ((optchar = getopt(argc, argv, "k:s")) != -1) {
        switch(optchar) {
        case 'k':
            if (krb5_string_to_enctype(optarg, &new_master_enctype)) {
                com_err(progname, EINVAL, ": %s is an invalid enctype", optarg);
                exit_status++;
                return;
            }
            break;
        case 's':
            do_stash++;
            break;
        case '?':
        default:
            usage();
            return;
        }
    }

    /* assemble & parse the master key name */
    if ((retval = krb5_db_setup_mkey_name(util_context,
                                          global_params.mkey_name,
                                          global_params.realm,  
                                          &mkey_fullname, &master_princ))) {
        com_err(progname, retval, "while setting up master key name");
        exit_status++;
        return;
    }

    retval = krb5_db_get_principal(util_context, master_princ, &master_entry,
                                   &nentries,
                                   &more);
    if (retval != 0) {
        com_err(progname, retval, "while setting up master key name");
        exit_status++;
        return;
    }

    printf("Creating new master key for master key principal '%s'\n",
        mkey_fullname);

    printf("You will be prompted for a new database Master Password.\n");
    printf("It is important that you NOT FORGET this password.\n");
    fflush(stdout);

    pw_size = 1024;
    pw_str = malloc(pw_size);
    if (pw_str == NULL) {
        com_err(progname, ENOMEM, "while creating new master key");
        exit_status++;
        return;
    }

    retval = krb5_read_password(util_context, KRB5_KDC_MKEY_1, KRB5_KDC_MKEY_2,
        pw_str, &pw_size);
    if (retval) {
        com_err(progname, retval, "while reading new master key from keyboard");
        exit_status++;
        return;
    }
    new_mkey_password = pw_str;

    pwd.data = new_mkey_password;
    pwd.length = strlen(new_mkey_password);
    retval = krb5_principal2salt(util_context, master_princ, &master_salt);
    if (retval) {
        com_err(progname, retval, "while calculating master key salt");
        exit_status++;
        return;
    }

    retval = krb5_c_string_to_key(util_context, new_master_enctype, 
        &pwd, &master_salt, &new_master_keyblock);
    if (retval) {
        com_err(progname, retval, "while transforming master key from password");
        exit_status++;
        return;
    }

    /* First save the old keydata */
    old_kvno = get_key_data_kvno(util_context, master_entry.n_key_data,
        master_entry.key_data);
    old_key_data_count = master_entry.n_key_data;
    old_key_data = master_entry.key_data;

    /* alloc enough space to hold new and existing key_data */
    /*
     * The encrypted key is malloc'ed by krb5_dbekd_encrypt_key_data and
     * krb5_key_data key_data_contents is a pointer to this key.  Using some
     * logic from master_key_convert().
     */
    master_entry.key_data = (krb5_key_data *) malloc(sizeof(krb5_key_data) *
                                                     (old_key_data_count + 1));
    if (master_entry.key_data == NULL) {
        com_err(progname, ENOMEM, "while adding new master key");
        exit_status++;
        return;
    }
    memset((char *) master_entry.key_data, 0, sizeof(krb5_key_data) * (old_key_data_count + 1));
    master_entry.n_key_data = old_key_data_count + 1;

    new_mkey_kvno = old_kvno + 1;
    /* deal with wrapping? */
    if (new_mkey_kvno == 0)
        new_mkey_kvno = 1; /* knvo must not be 0 as this is special value (IGNORE_VNO) */

    /* Note, mkey does not have salt */
    /* add new mkey encrypted with itself to mkey princ entry */
    if ((retval = krb5_dbekd_encrypt_key_data(util_context, &new_master_keyblock,
                                              &new_master_keyblock, NULL, 
                                              (int) new_mkey_kvno,
                                              master_entry.key_data))) {
        com_err(progname, retval, "while creating new master key");
        exit_status++;
        return;
    }

    /*
     * Need to decrypt old keys with the current mkey which is in the global
     * master_keyblock and encrypt those keys with the latest mkey.
     *
     * The new mkey is followed by existing keys.
     *
     * First, set up for creating a krb5_mkey_aux_node list which will be used
     * to update the mkey aux data for the mkey princ entry.
     */
    mkey_aux_data_head = (krb5_mkey_aux_node *) malloc(sizeof(krb5_mkey_aux_node));
    if (mkey_aux_data_head == NULL) {
        com_err(progname, ENOMEM, "while creating mkey_aux_data");
        exit_status++;
        return;
    }
    memset(mkey_aux_data_head, 0, sizeof(krb5_mkey_aux_node));
    mkey_aux_data = &mkey_aux_data_head;

    for (i = 0; i < old_key_data_count; i++) {
        key_data = &old_key_data[i];

        retval = krb5_dbekd_decrypt_key_data(util_context, &master_keyblock,
                                             key_data, &plainkey, NULL);
        if (retval) {
            com_err(progname, retval, "while decrypting master keys");
            exit_status++;
            return;
        }

        /*
         * Create a list of krb5_mkey_aux_node nodes.  One node contains the new
         * mkey encrypted by an old mkey and the old mkey's kvno (one node per
         * old mkey).
         */

        if (*mkey_aux_data == NULL) {
            /* *mkey_aux_data points to next field of previous node */
            *mkey_aux_data = (krb5_mkey_aux_node *) malloc(sizeof(krb5_mkey_aux_node));
            if (mkey_aux_data == NULL) {
                com_err(progname, ENOMEM, "while creating mkey_aux_data");
                exit_status++;
                return;
            }
            memset(*mkey_aux_data, 0, sizeof(krb5_mkey_aux_node));
        }

        /* encrypt the new mkey with the older mkey */
        retval = krb5_dbekd_encrypt_key_data(util_context, &plainkey,
            &new_master_keyblock,
            NULL, /* no keysalt */
            (int) key_data->key_data_kvno,
            &tmp_key_data);
        if (retval) {
            com_err(progname, retval, "while encrypting master keys");
            exit_status++;
            return;
        }

        (*mkey_aux_data)->latest_mkey = tmp_key_data;
        (*mkey_aux_data)->mkey_kvno = key_data->key_data_kvno;

        mkey_aux_data = &((*mkey_aux_data)->next);

        /* Store old key in master_entry keydata, + 1 to skip the first key_data entry */
        retval = krb5_dbekd_encrypt_key_data(util_context, &new_master_keyblock,
                                             &plainkey,
                                             NULL, /* no keysalt */
                                             (int) key_data->key_data_kvno,
                                             &master_entry.key_data[i+1]);
        if (retval) {
            com_err(progname, retval, "while encrypting master keys");
            exit_status++;
            return;
        }

        /* free plain text key and old key data entry */
        krb5_free_keyblock_contents(util_context, &plainkey);
        for (j = 0; j < key_data->key_data_ver; j++) {
            if (key_data->key_data_length[j]) {
                /* the key_data contents are encrypted so no clearing first */
                free(key_data->key_data_contents[j]);
            }
        }
    }

    if ((retval = krb5_dbe_update_mkey_aux(util_context, &master_entry,
                                           mkey_aux_data_head))) {
        com_err(progname, retval, "while updating mkey aux data");
        exit_status++;
        return;
    }

    if ((retval = krb5_timeofday(util_context, &now))) {
        com_err(progname, retval, "while getting current time");
        exit_status++;
        return;
    }

    if ((retval = krb5_dbe_update_mod_princ_data(util_context, &master_entry,
                now, master_princ))) {
        com_err(progname, retval, "while updating the master key principal modification time");
        exit_status++;
        return;
    }

    if ((retval = krb5_db_put_principal(util_context, &master_entry, &nentries))) {
        (void) krb5_db_fini(util_context);
        com_err(progname, retval, "while adding master key entry to the database");
        exit_status++;
        return;
    }

    if (do_stash) {
        retval = krb5_db_store_master_key(util_context,
            global_params.stash_file,
            master_princ,
            new_mkey_kvno,
            &new_master_keyblock,
            mkey_password);
        if (retval) {
            com_err(progname, errno, "while storing key");
            printf("Warning: couldn't stash master key.\n");
        }
    }
    /* clean up */
    (void) krb5_db_fini(util_context);
    memset((char *)master_keyblock.contents, 0, master_keyblock.length);
    free(master_keyblock.contents);
    memset((char *)new_master_keyblock.contents, 0, new_master_keyblock.length);
    free(new_master_keyblock.contents);
    if (pw_str) {
        memset(pw_str, 0, pw_size);
        free(pw_str);
    }
    free(master_salt.data);
    free(mkey_fullname);
    for (cur_mkey_aux_data = mkey_aux_data_head; cur_mkey_aux_data != NULL;
        cur_mkey_aux_data = next_mkey_aux_data) {

        next_mkey_aux_data = cur_mkey_aux_data->next;
        krb5_free_key_data_contents(util_context, &(cur_mkey_aux_data->latest_mkey));
        free(cur_mkey_aux_data);
    }
    return;
}

void
kdb5_use_mkey(int argc, char *argv[])
{
    krb5_error_code retval;
    char  *mkey_fullname;
    krb5_kvno  use_kvno;
    krb5_timestamp now, start_time;
    krb5_actkvno_node *actkvno_list, *new_actkvno_list_head, *new_actkvno,
                      *prev_actkvno, *cur_actkvno;
    krb5_db_entry master_entry;
    int   nentries = 0;
    krb5_boolean more = 0;

    if (argc < 1 || argc > 2) {
        /* usage calls exit */
        usage();
    }

    use_kvno = (int) strtol(argv[0], (char **)NULL, 10);
    if (use_kvno == 0) {
        com_err(progname, EINVAL, ": 0 is an invalid KVNO value.");
        exit_status++;
        return;
    }

    if ((retval = krb5_timeofday(util_context, &now))) {
        com_err(progname, retval, "while getting current time.");
        exit_status++;
        return;
    }

    if (argc == 2) {
        start_time = (krb5_timestamp) get_date(argv[0]);
    } else {
        start_time = now;
    }

    /*
     * Need to:
     *
     * 1. get mkey princ
     * 2. verify that mprinc actually has a mkey with the new actkvno
     * 2. get krb5_actkvno_node list
     * 3. add use_kvno to actkvno list (sorted in right spot)
     * 4. update mkey princ's tl data
     * 5. put mkey princ.
     */

    /* assemble & parse the master key name */
    if ((retval = krb5_db_setup_mkey_name(util_context,
                                          global_params.mkey_name,
                                          global_params.realm,  
                                          &mkey_fullname, &master_princ))) {
        com_err(progname, retval, "while setting up master key name");
        exit_status++;
        return;
    }

    retval = krb5_db_get_principal(util_context, master_princ, &master_entry, &nentries,
        &more);
    if (retval != 0) {
        com_err(progname, retval, "while setting up master key name");
        exit_status++;
        return;
    }

    /* XXX WAF: verify that the provided kvno is valid */

    retval = krb5_dbe_lookup_actkvno(util_context, &master_entry, &actkvno_list);
    if (retval != 0) {
        com_err(progname, retval, "while setting up master key name");
        exit_status++;
        return;
    }

    /*
     * determine which nodes to delete and where to insert new act kvno node
     */

    /* alloc enough space to hold new and existing key_data */
    new_actkvno = (krb5_actkvno_node *) malloc(sizeof(krb5_actkvno_node));
    if (new_actkvno == NULL) {
        com_err(progname, ENOMEM, "while adding new master key");
        exit_status++;
        return;
    }

    new_actkvno->act_kvno = use_kvno;
    new_actkvno->act_time = start_time;

    if (actkvno_list == NULL || new_actkvno->act_time < actkvno_list->act_time) {
        /* insert new actkvno at head of list and link rest following */
        new_actkvno->next = actkvno_list;
        new_actkvno_list_head = new_actkvno;
    } else {
        for (new_actkvno_list_head = prev_actkvno = cur_actkvno = actkvno_list;
             cur_actkvno != NULL;
             prev_actkvno = cur_actkvno, cur_actkvno = cur_actkvno->next) {

            if (cur_actkvno->act_time <= now) {
                if (new_actkvno->act_time < cur_actkvno->act_time) {
                    /*
                     * This is a problem as the new actkvno would be skipped and
                     * not added to the entries for the mkey princ.
                     */
                    com_err(progname, EINVAL,
                        "Activation time %s is less than a existing currently "
                        "active kvno %d (activation time %s)",
                        strdate(new_actkvno->act_time), cur_actkvno->act_kvno,
                                strdate(cur_actkvno->act_time));
                    exit_status++;
                    return;
                }
                /*
                 * New list head should point to the most current valid node in
                 * order to trim out of date entries.
                 */
                new_actkvno_list_head = cur_actkvno;
            }

            if (new_actkvno->act_time < cur_actkvno->act_time) {
                if (new_actkvno_list_head == cur_actkvno) {
                    /*
                     * XXX WAF: trying to minimize race condition issue here,
                     * maybe there is a better way to do this?
                     */
                    com_err(progname, EINVAL,
                        "Activation time %s is less than an existing currently "
                        "active kvno %d (activation time %s)",
                        strdate(new_actkvno->act_time), cur_actkvno->act_kvno,
                                strdate(cur_actkvno->act_time));
                    exit_status++;
                    return;
                }
                prev_actkvno->next = new_actkvno;
                new_actkvno->next = cur_actkvno;
                break;
            } else if (cur_actkvno->next == NULL) {
                /* end of line, just add new node to end of list */
                cur_actkvno->next = new_actkvno;
                break;
            }
        } /* end for (new_actkvno_list_head = prev_actkvno = ... */
    }

    if ((retval = krb5_dbe_update_actkvno(util_context, &master_entry,
                                          new_actkvno_list_head))) {
        com_err(progname, retval, "while updating actkvno data for master principal entry.");
        exit_status++;
        return;
    }

    if ((retval = krb5_dbe_update_mod_princ_data(util_context, &master_entry,
                now, master_princ))) {
        com_err(progname, retval, "while updating the master key principal modification time");
        exit_status++;
        return;
    }

    if ((retval = krb5_db_put_principal(util_context, &master_entry, &nentries))) {
        (void) krb5_db_fini(util_context);
        com_err(progname, retval, "while adding master key entry to the database");
        exit_status++;
        return;
    }

    /* clean up */
    (void) krb5_db_fini(util_context);
    free(mkey_fullname);
    for (cur_actkvno = actkvno_list; cur_actkvno != NULL;) {

        prev_actkvno = cur_actkvno;
        cur_actkvno = cur_actkvno->next;
        free(prev_actkvno);
    }
    return;
}

void
kdb5_list_mkeys(int argc, char *argv[])
{
    krb5_error_code retval;
    char  *mkey_fullname, *output_str = NULL, enctype[BUFSIZ];
    krb5_kvno  act_kvno;
    krb5_timestamp act_time;
    krb5_actkvno_node *actkvno_list = NULL, *cur_actkvno, *prev_actkvno;
    krb5_db_entry master_entry;
    int   nentries = 0;
    krb5_boolean more = 0;
    krb5_keylist_node  *cur_kb_node;
    krb5_keyblock *act_mkey;

    /* assemble & parse the master key name */
    if ((retval = krb5_db_setup_mkey_name(util_context,
                global_params.mkey_name,
                global_params.realm,  
                &mkey_fullname, &master_princ))) {
        com_err(progname, retval, "while setting up master key name");
        exit_status++;
        return;
    }

    retval = krb5_db_get_principal(util_context, master_princ, &master_entry, &nentries,
        &more);
    if (retval != 0) {
        com_err(progname, retval, "while getting master key principal %s", mkey_fullname);
        exit_status++;
        return;
    }

    retval = krb5_dbe_lookup_actkvno(util_context, &master_entry, &actkvno_list);
    if (retval != 0) {
        com_err(progname, retval, "while looking up active kvno list");
        exit_status++;
        return;
    }
    /* XXX WAF: debug code, remove before commit */
    if (master_keylist == NULL) {
        com_err(progname, retval, "master_keylist == NULL this is a problem");
        exit_status++;
        return;
    }

    if (actkvno_list == NULL) {
        act_kvno = master_entry.key_data[0].key_data_kvno;
    } else {
        retval = krb5_dbe_find_act_mkey(util_context, master_keylist,
                                        actkvno_list, &act_kvno, &act_mkey);
        if (retval != 0) {
            com_err(progname, retval, "while setting up master key name");
            exit_status++;
            return;
        }
    }

    printf("Master keys for Principal: %s\n", mkey_fullname);

    for (cur_kb_node = master_keylist; cur_kb_node != NULL;
         cur_kb_node = cur_kb_node->next) {

        if (krb5_enctype_to_string(cur_kb_node->keyblock.enctype,
                                   enctype, sizeof(enctype))) {
            com_err(progname, retval, "while getting enctype description");
            exit_status++;
            return;
        }

        if (actkvno_list != NULL) {
            for (cur_actkvno = actkvno_list; cur_actkvno != NULL;
                 cur_actkvno = cur_actkvno->next) {
                if (cur_actkvno->act_kvno == cur_kb_node->kvno) {
                    act_time = cur_actkvno->act_time;
                    break;
                }
            }
        } else {
            /*
             * mkey princ doesn't have an active knvo list so assume the current
             * key is active now
             */
            if ((retval = krb5_timeofday(util_context, &act_time))) {
                com_err(progname, retval, "while getting current time");
                exit_status++;
                return;
            }
        }

        if (cur_kb_node->kvno == act_kvno) {
            asprintf(&output_str, "KNVO: %d, Enctype: %s, Active on: %s *\n",
                     cur_kb_node->kvno, enctype, strdate(act_time));
        } else {
            asprintf(&output_str, "KNVO: %d, Enctype: %s, Active on: %s\n",
                     cur_kb_node->kvno, enctype, strdate(act_time));
        }
    }

    /* clean up */
    (void) krb5_db_fini(util_context);
    free(mkey_fullname);
    free(output_str);
    for (cur_actkvno = actkvno_list; cur_actkvno != NULL;) {
        prev_actkvno = cur_actkvno;
        cur_actkvno = cur_actkvno->next;
        free(prev_actkvno);
    }
    return;
}
