/*
 * kadmin/server/adm_adm_func.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * Sandia National Laboratories also makes no representations about the 
 * suitability of the modifications, or additions to this software for 
 * any purpose.  It is provided "as is" without express or implied warranty.
 * 
 * Modify the Kerberos Database
 */


#include <sys/types.h>
#include <syslog.h>
#include "com_err.h"

#include <sys/socket.h>
#include <netinet/in.h>
#ifndef hpux
#include <arpa/inet.h>
#endif

#include "k5-int.h"
#include "adm_extern.h"

#ifdef SANDIA
extern int classification;
#endif

krb5_error_code
adm_build_key (context, auth_context, new_passwd, oper_type, entry)
    krb5_context context;
    krb5_auth_context auth_context;
    char *new_passwd;
    int oper_type;
    krb5_db_entry entry;
{
    krb5_replay_data replaydata;
    krb5_data outbuf;
    int retval;
    krb5_key_data *key_data;
#if defined(MACH_PASS) || defined(SANDIA)
    char *tmp_phrase;
    char *tmp_passwd;
    int pwd_length, phrase_length;
#endif

#if defined(MACH_PASS) || defined(SANDIA)
    
    if ((tmp_passwd = (char *) calloc (1, 120)) == (char *) 0) {
	com_err("adm_build_key", ENOMEM, "for tmp_passwd");
	return(3);		/* No Memory */
    }
    
    if ((tmp_phrase = (char *) calloc (1, 120)) == (char *) 0) {
	free(tmp_passwd);
	com_err("adm_build_key", ENOMEM, "for tmp_phrase");
	return(3);		/* No Memory */
    }
    
    if (retval = get_pwd_and_phrase("adm_build_key", &tmp_passwd, 
				    &tmp_phrase)) {
	free(tmp_passwd);
	free(tmp_phrase);
	return(4);		/* Unable to get Password */
    }
    
    if ((outbuf.data = (char *) calloc (1, strlen(tmp_passwd) + 1)) == 
	(char *) 0) {
	com_err("adm_build_key", ENOMEM, "for outbuf.data");
	free(tmp_passwd);
	free(tmp_phrase);
	return(3);		/* No Memory */
    }
    
    outbuf.length = strlen(tmp_passwd);
    (void) memcpy(outbuf.data, tmp_passwd, strlen(tmp_passwd));
    
#else 
    
    if ((outbuf.data = (char *) calloc (1, 3)) == 
	(char *) 0) {
	com_err("adm_build_key", ENOMEM, "for outbuf.data");
	return(3);		/* No Memory */
    }

    outbuf.data[0] = KADMIN;
    outbuf.data[1] = oper_type;
    outbuf.data[2] = KADMGOOD;
    outbuf.length = 3;
    
    if (oper_type == CHGOPER || oper_type == CH4OPER) {
	key_data = (krb5_key_data *) NULL;
	if (krb5_dbe_find_enctype(context,
				  &entry,
				  ENCTYPE_DES_CBC_MD5,
				  ((oper_type == CHGOPER) ? 
				   KRB5_KDB_SALTTYPE_NORMAL : 
				   KRB5_KDB_SALTTYPE_V4),
				  -1,
				  &key_data)) {
	    com_err("adm_build_key", ENOENT, "finding key data");
	    return(4);	/* Unable to get password */
	}
	outbuf.data[3] = key_data->key_data_type[1];
	outbuf.length = 4;
    }
    
#endif

    /* Encrypt Password and Phrase */
    if (retval = krb5_mk_priv(context, auth_context, &outbuf,
			      &msg_data, &replaydata)) {
	com_err("adm_build_key", retval, "during mk_priv");
#if defined(MACH_PASS) || defined(SANDIA)
	free(tmp_passwd);
	free(tmp_phrase);
#endif
	free(outbuf.data);
	return(5);		/* Protocol Failure */
    }
    
#if defined(MACH_PASS) || defined(SANDIA)
    (void) memcpy(new_passwd, tmp_passwd, strlen(tmp_passwd));
    new_passwd[strlen(tmp_passwd)] = '\0';
    
    free(tmp_phrase);
    free(tmp_passwd);
#endif
    free(outbuf.data);
    
    /* Send private message to Client */
    if (krb5_write_message(context, &client_server_info.client_socket, 
			   &msg_data)){
	free(msg_data.data);
	com_err("adm_build_key", 0, "Error Performing Password Write");
	return(5);		/* Protocol Failure */
    }
    
    free(msg_data.data);
    
    /* Read Client Response */
    if (krb5_read_message(context, &client_server_info.client_socket, &inbuf)){
	syslog(LOG_ERR | LOG_INFO, "Error Performing Password Read");
	return(5);		/* Protocol Failure */
    }
    
    /* Decrypt Client Response */
    if (retval = krb5_rd_priv(context, auth_context, &inbuf,
			      &msg_data, &replaydata)) {
	syslog(LOG_ERR | LOG_INFO, "adm_build_key krb5_rd_priv error");
	free(inbuf.data);
	return(5);		/* Protocol Failure */
    }
    free(inbuf.data);
    
#if !defined(MACH_PASS) && !defined(SANDIA)
    memcpy(new_passwd, msg_data.data, msg_data.length);
#endif
    
    free(msg_data.data);
    return(0);
}

/*	kadmin change password request	*/
krb5_error_code
adm_change_pwd(context, auth_context, prog, customer_name, salttype)
    krb5_context context;
    krb5_auth_context auth_context;
    char *prog;
    char *customer_name;
    int salttype;
{
    krb5_db_entry entry;
    int nprincs = 1;
    
    krb5_error_code retval;
    krb5_principal newprinc;
    char *composite_name;
    char *new_passwd;
    int oper_type;
    
    syslog(LOG_AUTH | LOG_INFO, 
	   "Remote Administrative Password Change Request for %s by %s", 
	   customer_name, client_server_info.name_of_client);
    
    if (retval = krb5_parse_name(context, customer_name, &newprinc)) {
	syslog(LOG_ERR | LOG_INFO, "parse failure while parsing '%s'", 
	       customer_name);
	return(5);		/* Protocol Failure */
    }
    
    if (!(adm_princ_exists(context, "adm_change_pwd", newprinc,
			   &entry, &nprincs))) {
	com_err("adm_change_pwd", 0, "Principal does not exist!");
	krb5_free_principal(context, newprinc);
	krb5_db_free_principal(context, &entry, nprincs);
	return(1);              /* Principal Unknown */
    }
    
    if ((new_passwd = (char *) calloc (1, ADM_MAX_PW_LENGTH+1)) == (char *) 0) {
	com_err("adm_change_pwd", ENOMEM, "while allocating new_passwd!");
	krb5_free_principal(context, newprinc);
	krb5_db_free_principal(context, &entry, nprincs);
	return(3);		/* No Memory */
    }
    
    oper_type = (salttype == KRB5_KDB_SALTTYPE_NORMAL) ? CHGOPER : CH4OPER;

    if (retval = adm_build_key(context, auth_context, new_passwd, 
			       oper_type, entry)) {
	krb5_free_principal(context, newprinc);
	krb5_db_free_principal(context, &entry, nprincs);
	free(new_passwd);
	return(retval);
    }
    
    retval = krb5_unparse_name(context, newprinc, &composite_name);

    if (retval = adm_enter_pwd_key(context, "adm_change_pwd",              
				   composite_name,
				   newprinc,
				   newprinc,
				   1,		/* chg_entry */
				   salttype,
				   new_passwd,
				   &entry)) retval = 8;
    krb5_free_principal(context, newprinc);
    krb5_db_free_principal(context, &entry, nprincs);
    free(composite_name);
    
    (void) memset(new_passwd, 0, strlen(new_passwd));
    free(new_passwd);
    return(0);
}

/* kadmin add new random key function */
krb5_error_code
adm_change_pwd_rnd(context, cmdname, customer_name)
    krb5_context context;
    char *cmdname;
    char *customer_name;
{
    krb5_db_entry entry;
    int nprincs = 1;
    krb5_error_code retval;
    krb5_principal newprinc;

    
    syslog(LOG_AUTH | LOG_INFO, 
	   "Remote Administrative Random Password Change Request for %s by %s", 
	   customer_name, client_server_info.name_of_client);
    
    if (retval = krb5_parse_name(context, customer_name, &newprinc)) {
	com_err("adm_change_pwd_rnd", retval, "while parsing '%s'", customer_name);
	return(5);		/* Protocol Failure */
    }
#ifdef SANDIA       
    if (!(newprinc[2])) {
	if (retval = check_security(newprinc, classification)) {
	    krb5_free_principal(context, newprinc);
	    syslog(LOG_ERR, "Principal (%s) - Incorrect Classification level",
		   customer_name);
	    return(6);
	}
    }
#endif
    if (!(adm_princ_exists(context, "adm_change_pwd_rnd", newprinc,
			   &entry, &nprincs))) {
	com_err("adm_change_pwd_rnd", 0, "Principal does not exist!");
	krb5_free_principal(context, newprinc);
	krb5_db_free_principal(context, &entry, nprincs);
	return(1);              /* Principal Unknown */
    }
    
    if (retval = adm_enter_rnd_pwd_key(context, "adm_change_pwd_rnd",
				       newprinc,
				       1, /* change existing entry */
				       &entry))
      retval = 8;
	
    krb5_free_principal(context, newprinc);
    krb5_db_free_principal(context, &entry, nprincs);
    return(retval);
}

/* kadmin add new key function */
krb5_error_code
adm_add_new_key(context, auth_context, cmdname, customer_name, salttype)
    krb5_context context;
    krb5_auth_context auth_context;
    char *cmdname;
    char *customer_name;
    int salttype;
{
    krb5_db_entry entry;
    int nprincs = 1;
    
    krb5_error_code retval;
    krb5_principal newprinc;
    char *new_passwd;
    
    syslog(LOG_AUTH | LOG_INFO, 
	   "Remote Administrative Addition Request for %s by %s", 
	   customer_name, client_server_info.name_of_client);
    
    if (retval = krb5_parse_name(context, customer_name, &newprinc)) {
	com_err("adm_add_new_key", retval, "while parsing '%s'", customer_name);
	return(5);		/* Protocol Failure */
    }
#ifdef SANDIA       
    if (!(newprinc[2])) {
	if (retval = check_security(newprinc, classification)) {
	    krb5_free_principal(context, newprinc);
	    syslog(LOG_ERR, "Principal (%s) - Incorrect Classification level",
		   customer_name);
	    return(6);
	}
    }
#endif
    if (adm_princ_exists(context, "adm_add_new_key",newprinc,&entry,&nprincs)) {
	com_err("adm_add_new_key", 0, 
		"principal '%s' already exists", customer_name);
	krb5_free_principal(context, newprinc);
	krb5_db_free_principal(context, &entry, nprincs);
	return(2);		/* Principal Already Exists */
    }
    
    if ((new_passwd = (char *) calloc (1, 255)) == (char *) 0) {
	com_err("adm_add_new_key", ENOMEM, "for new_passwd");
	krb5_free_principal(context, newprinc);
	krb5_db_free_principal(context, &entry, nprincs);
	return(3);		/* No Memory */
    }
    
    if (retval = adm_build_key(context, auth_context, new_passwd, 
			       ADDOPER, entry)) {
	krb5_free_principal(context, newprinc);
	krb5_db_free_principal(context, &entry, nprincs);
	free(new_passwd);
	return(retval);
    }
    
    if (retval = adm_enter_pwd_key(context, "adm_add_new_key", 
				   customer_name,
				   newprinc, 
				   newprinc,
				   0, 		/* new_entry */
				   salttype,
				   new_passwd,
				   &entry)) 
      retval = 8;
    (void) memset(new_passwd, 0, strlen(new_passwd));
    free(new_passwd);
    krb5_free_principal(context, newprinc);
    krb5_db_free_principal(context, &entry, nprincs);
    return(retval);
}

/* kadmin add new random key function */
krb5_error_code
adm_add_new_key_rnd(context, cmdname, customer_name)
    krb5_context context;
    char *cmdname;
    char *customer_name;
{
    krb5_db_entry entry;
    int nprincs = 1;
    krb5_error_code retval;
    krb5_principal newprinc;

    
    syslog(LOG_AUTH | LOG_INFO, 
	   "Remote Administrative Addition Request for %s by %s", 
	   customer_name, client_server_info.name_of_client);
    
    if (retval = krb5_parse_name(context, customer_name, &newprinc)) {
	com_err("adm_add_new_key_rnd", retval, "while parsing '%s'", customer_name);
	return(5);		/* Protocol Failure */
    }
#ifdef SANDIA       
    if (!(newprinc[2])) {
	if (retval = check_security(newprinc, classification)) {
	    krb5_free_principal(context, newprinc);
	    syslog(LOG_ERR, "Principal (%s) - Incorrect Classification level",
		   customer_name);
	    return(6);
	}
    }
#endif
    if (adm_princ_exists(context, "adm_add_new_key_rnd", newprinc, 
			 &entry, &nprincs)) {
	com_err("adm_add_new_key_rnd", 0, 
		"principal '%s' already exists", customer_name);
	krb5_free_principal(context, newprinc);
	krb5_db_free_principal(context, &entry, nprincs);
	return(2);		/* Principal Already Exists */
    }
    
    if (retval = adm_enter_rnd_pwd_key(context, "adm_add_new_key_rnd",
				       newprinc,
				       0, /* new entry */
				       &entry))
      retval = 8;
	
    krb5_free_principal(context, newprinc);
    krb5_db_free_principal(context, &entry, nprincs);
    return(retval);
}

/* kadmin delete old key function */
krb5_error_code
adm_del_old_key(context, cmdname, customer_name)
    krb5_context context;
    char *cmdname;
    char *customer_name;
{
    krb5_db_entry entry;
    int nprincs = 1;
    
    krb5_error_code retval;
    krb5_principal newprinc;
    int one = 1;
    
    syslog(LOG_AUTH | LOG_INFO, 
	   "Remote Administrative Deletion Request for %s by %s", 
	   customer_name, client_server_info.name_of_client);
    
    if (retval = krb5_parse_name(context, customer_name, &newprinc)) {
	com_err("adm_del_old_key", retval, "while parsing '%s'", customer_name);
	return(5);		/* Protocol Failure */
    }
    
    if (!adm_princ_exists(context, "adm_del_old_key", newprinc,
			  &entry, &nprincs)) {
	com_err("adm_del_old_key", 0, "principal '%s' is not in the database", 
		customer_name);
	krb5_free_principal(context, newprinc);
	krb5_db_free_principal(context, &entry, nprincs);
	return(1);
    }
    
    if (retval = krb5_db_delete_principal(context, newprinc, &one)) {
	com_err("adm_del_old_key", retval, 
		"while deleting '%s'", customer_name);
	krb5_free_principal(context, newprinc);
	krb5_db_free_principal(context, &entry, nprincs);
	return(8);
    } else if (one != 1) {
	com_err("adm_del_old_key", 0, 
		"no principal deleted - unknown error");
	krb5_free_principal(context, newprinc);
	krb5_db_free_principal(context, &entry, nprincs);
	return(8);
    }
    
    krb5_free_principal(context, newprinc);
    krb5_db_free_principal(context, &entry, nprincs);
    return(0);
}

/* kadmin modify existing Principal function */
krb5_error_code
adm_mod_old_key(context, auth_context, cmdname, customer_name)
    krb5_context context;
    krb5_auth_context auth_context;
    char *cmdname;
    char *customer_name;
{
    krb5_replay_data replaydata;
    krb5_db_entry entry;
    int nprincs = 1;
    extern int errno;
    
    krb5_error_code retval;
    krb5_principal newprinc;
    
    krb5_data outbuf;
    char tempstr[20];
    
    int one = 1;
    
    syslog(LOG_AUTH | LOG_INFO, 
	   "Remote Administrative Modification Request for %s by %s", 
	   customer_name, client_server_info.name_of_client);
    
    if (retval = krb5_parse_name(context, customer_name, &newprinc)) {
	com_err("adm_mod_old_key", retval, "while parsing '%s'", customer_name);
	return(5);		/* Protocol Failure */
    }
    
    for ( ; ; ) {
	
	if (!adm_princ_exists(context, "adm_mod_old_key", newprinc,
			      &entry, &nprincs)) {
	    krb5_db_free_principal(context, &entry, nprincs);
	    com_err("adm_mod_old_key", 0, 
		    "principal '%s' is not in the database", 
		    customer_name);
	    krb5_free_principal(context, newprinc);
	    return(1);
	}
	
	/* Send Acknowledgement */
	if ((outbuf.data = (char *) calloc (1, 255)) == (char *) 0) {
	    krb5_free_principal(context, newprinc);
	    krb5_db_free_principal(context, &entry, nprincs);
	    com_err("adm_mod_old_key", ENOMEM, "for outbuf.data");
	    return(3);		/* No Memory */
	}
	
	outbuf.length = 3;
	outbuf.data[0] = KADMIND;
	outbuf.data[1] = MODOPER;
	outbuf.data[2] = SENDDATA3;
	
	if (retval = krb5_mk_priv(context, auth_context, &outbuf,
				  &msg_data, &replaydata)) {
	    krb5_free_principal(context, newprinc);
	    krb5_db_free_principal(context, &entry, nprincs);
	    com_err("adm_mod_old_key", retval, "during mk_priv");
	    free(outbuf.data);
	    return(5);		/* Protocol Failure */
	}
	free(outbuf.data);
	
	if (krb5_write_message(context, &client_server_info.client_socket, 
			       &msg_data)){
	    free(msg_data.data);
	    krb5_free_principal(context, newprinc);
	    krb5_db_free_principal(context, &entry, nprincs);
	    com_err("adm_mod_old_key", 0, 
		    "Error Performing Modification Write");
	    return(5);		/* Protocol Failure */
	}
	free(msg_data.data);
	
	/* Read Client Response */
	if (krb5_read_message(context, &client_server_info.client_socket, &inbuf)){
	    krb5_free_principal(context, newprinc);
	    krb5_db_free_principal(context, &entry, nprincs);
	    com_err("adm_mod_old_key", errno, 
		    "Error Performing Modification Read");
            return(5);		/* Protocol Failure */
	}
	
	/* Decrypt Client Response */
	if (retval = krb5_rd_priv(context, auth_context, &inbuf,
				  &msg_data, &replaydata)) {
	    com_err("adm_mod_old_key", retval, "krb5_rd_priv error %s",
		    error_message(retval));
	    free(inbuf.data);
	    krb5_free_principal(context, newprinc);
	    krb5_db_free_principal(context, &entry, nprincs);
	    return(5);		/* Protocol Failure */
	}
	
	free(inbuf.data);
	
	if (msg_data.data[1] == KADMGOOD) break;
	
	/* Decode Message - Modify Database */
	if (msg_data.data[2] != SENDDATA3) {
	    free(msg_data.data);
	    krb5_free_principal(context, newprinc);
	    krb5_db_free_principal(context, &entry, nprincs);
	    return(5);		/* Protocol Failure */
	}
#ifdef SANDIA
	if (msg_data.data[3] == KMODFCNT) {
	    (void) memcpy(tempstr, (char *) msg_data.data + 4,
			  msg_data.length - 4);
	    entry.fail_auth_count = atoi(tempstr);
	}
#endif

	if (msg_data.data[3] == KMODVNO) {
	    krb5_key_data	*kdata;

	    (void) memcpy(tempstr, (char *) msg_data.data + 4,
			  msg_data.length - 4);
	    /*
	     * We could loop through all the supported key/salt types, but
	     * we don't have that technology yet.
	     */
	    if (!krb5_dbe_find_enctype(context,
				       &entry,
				       ENCTYPE_DES_CBC_MD5,
				       KRB5_KDB_SALTTYPE_NORMAL,
				       -1,
				       &kdata))
		kdata->key_data_kvno = atoi(tempstr);
	    if (!krb5_dbe_find_enctype(context,
				       &entry,
				       ENCTYPE_DES_CBC_CRC,
				       KRB5_KDB_SALTTYPE_V4,
				       -1,
				       &kdata))
		kdata->key_data_kvno = atoi(tempstr);
	    if (!krb5_dbe_find_enctype(context,
				       &entry,
				       ENCTYPE_DES_CBC_MD5,
				       KRB5_KDB_SALTTYPE_NOREALM,
				       -1,
				       &kdata))
		kdata->key_data_kvno = atoi(tempstr);
	    if (!krb5_dbe_find_enctype(context,
				       &entry,
				       ENCTYPE_DES_CBC_MD5,
				       KRB5_KDB_SALTTYPE_ONLYREALM,
				       -1,
				       &kdata))
		kdata->key_data_kvno = atoi(tempstr);
	    if (!krb5_dbe_find_enctype(context,
				       &entry,
				       ENCTYPE_DES_CBC_MD5,
				       KRB5_KDB_SALTTYPE_AFS3,
				       -1,
				       &kdata))
		kdata->key_data_kvno = atoi(tempstr);
	}
	
	if (msg_data.data[3] == KMODATTR) {
	    if (msg_data.data[4] == ATTRPOST)
	      entry.attributes &= ~KRB5_KDB_DISALLOW_POSTDATED;
	    if (msg_data.data[4] == ATTRNOPOST)
	      entry.attributes |= KRB5_KDB_DISALLOW_POSTDATED;
	    if (msg_data.data[4] == ATTRFOR) 
	      entry.attributes &= ~KRB5_KDB_DISALLOW_FORWARDABLE;
	    if (msg_data.data[4] == ATTRNOFOR) 
	      entry.attributes |= KRB5_KDB_DISALLOW_FORWARDABLE;
	    if (msg_data.data[4] == ATTRTGT) 
	      entry.attributes &= ~KRB5_KDB_DISALLOW_TGT_BASED;
	    if (msg_data.data[4] == ATTRNOTGT) 
	      entry.attributes |= KRB5_KDB_DISALLOW_TGT_BASED;
	    if (msg_data.data[4] == ATTRREN) 
	      entry.attributes &= ~KRB5_KDB_DISALLOW_RENEWABLE;
	    if (msg_data.data[4] == ATTRNOREN) 
	      entry.attributes |= KRB5_KDB_DISALLOW_RENEWABLE;
	    if (msg_data.data[4] == ATTRPROXY) 
	      entry.attributes &= ~KRB5_KDB_DISALLOW_PROXIABLE;
	    if (msg_data.data[4] == ATTRNOPROXY) 
	      entry.attributes |= KRB5_KDB_DISALLOW_PROXIABLE;
	    if (msg_data.data[4] == ATTRDSKEY) 
	      entry.attributes &= ~KRB5_KDB_DISALLOW_DUP_SKEY;
	    if (msg_data.data[4] == ATTRNODSKEY) 
	      entry.attributes |= KRB5_KDB_DISALLOW_DUP_SKEY;
	    if (msg_data.data[4] == ATTRLOCK) 
	      entry.attributes |= KRB5_KDB_DISALLOW_ALL_TIX;
	    if (msg_data.data[4] == ATTRUNLOCK) 
	      entry.attributes &= ~KRB5_KDB_DISALLOW_ALL_TIX;
	    if (msg_data.data[4] == ATTRNOSVR) 
	      entry.attributes |= KRB5_KDB_DISALLOW_SVR;
	    if (msg_data.data[4] == ATTRSVR) 
	      entry.attributes &= ~KRB5_KDB_DISALLOW_SVR;
#ifdef SANDIA
	    if (msg_data.data[4] == ATTRPRE) 
	      entry.attributes &= ~KRB5_KDB_REQUIRES_PRE_AUTH;
	    if (msg_data.data[4] == ATTRNOPRE) 
	      entry.attributes |= KRB5_KDB_REQUIRES_PRE_AUTH;
	    if (msg_data.data[4] == ATTRPWOK) 
	      entry.attributes &= ~KRB5_KDB_REQUIRES_PWCHANGE;
	    if (msg_data.data[4] == ATTRPWCHG) 
	      entry.attributes |= KRB5_KDB_REQUIRES_PWCHANGE;
	    if (msg_data.data[4] == ATTRSID) 
	      entry.attributes &= ~KRB5_KDB_REQUIRES_SECUREID;
	    if (msg_data.data[4] == ATTRNOSID) 
	      entry.attributes |= KRB5_KDB_REQUIRES_SECUREID;
#endif
        }
	
	free(msg_data.data);
	if (adm_update_tl_attrs(context,
				&entry,
				client_server_info.client,
				0)) {
	    com_err("adm_mod_old_key", retval,
		    "while updating modification attributes");
	    krb5_free_principal(context, newprinc);
	    krb5_db_free_principal(context, &entry, nprincs);
	    return(5);		/* Protocol Failure */
	}
	
	retval = krb5_db_put_principal(context, &entry, &one);
	if (retval) {
	    com_err("adm_mod_old_key", retval, "while storing principal");
	    krb5_free_principal(context, newprinc);
	    krb5_db_free_principal(context, &entry, nprincs);
	    return(8);		/* Update failed */
	}
	one = 1;
    }	/* for */
    
    krb5_db_free_principal(context, &entry, nprincs);
    krb5_free_principal(context, newprinc);
    
    /* Read Client Response */
    if (krb5_read_message(context, &client_server_info.client_socket, &inbuf)){
	com_err("adm_mod_old_key", errno, "Error Performing Read");
	return(5);		/* Protocol Failure */
    }
    
    /* Decrypt Client Response */
    if (retval = krb5_rd_priv(context, auth_context, &inbuf,
			      &msg_data, &replaydata)) {
	com_err("adm_mod_old_key", retval, "krb5_rd_priv error %s",
		error_message(retval));
	free(inbuf.data);
	return(5);		/* Protocol Failure */
    }
    
    free(msg_data.data);
    free(inbuf.data);
    
    return(0);
}

/* kadmin inquire existing Principal function */
krb5_error_code
adm_inq_old_key(context, auth_context, cmdname, customer_name)
    krb5_context context;
    krb5_auth_context auth_context;
    char *cmdname;
    char *customer_name;
{
    krb5_replay_data replaydata;
    krb5_db_entry entry;
    int nprincs = 1;
    
    krb5_data outbuf;
    krb5_error_code retval;
    krb5_principal newprinc;
    char *fullname;
    
    syslog(LOG_AUTH | LOG_INFO, 
	   "Remote Administrative Inquiry Request for %s by %s", 
	   customer_name, client_server_info.name_of_client);
    
    if (retval = krb5_parse_name(context, customer_name, &newprinc)) {
        com_err("adm_inq_old_key", retval, "while parsing '%s'", customer_name);
	return(5);		/* Protocol Failure */
    }
    
    if (retval = krb5_unparse_name(context, newprinc, &fullname)) {
	krb5_free_principal(context, newprinc);
	com_err("adm_inq_old_key", retval, "while unparsing");
        return(5);		/* Protocol Failure */
    }
    
    if (!adm_princ_exists(context, "adm_inq_old_key", newprinc,
			  &entry, &nprincs)) {
	krb5_db_free_principal(context, &entry, nprincs);
	krb5_free_principal(context, newprinc);
	free(fullname);
	com_err("adm_inq_old_key", 0, "principal '%s' is not in the database", 
		customer_name);
	return(1);
    }
    
    if ((outbuf.data = (char *) calloc (1, 2048)) == (char *) 0) {
	krb5_db_free_principal(context, &entry, nprincs);
	krb5_free_principal(context, newprinc);
	free(fullname);
	com_err("adm_inq_old_key", ENOMEM, "for outbuf.data");
	return(3);		/* No Memory */
    }
    
    /* Format Inquiry Data */
    if ((retval = adm_fmt_prt(context, &entry, fullname, outbuf.data))) {
	krb5_db_free_principal(context, &entry, nprincs);
	krb5_free_principal(context, newprinc);
	free(fullname);
	com_err("adm_inq_old_key", 0, "Unable to Format Inquiry Data");
	return(5);		/* XXX protocol failure --- not right, but.. */
    }
    outbuf.length = strlen(outbuf.data);
    krb5_db_free_principal(context, &entry, nprincs);
    krb5_free_principal(context, newprinc);
    free(fullname);
    
    /* Encrypt Inquiry Data */
    if (retval = krb5_mk_priv(context, auth_context, &outbuf,
			      &msg_data, &replaydata)) {
	com_err("adm_inq_old_key", retval, "during mk_priv");
	free(outbuf.data);
	return(5);		/* Protocol Failure */
    }
    free(outbuf.data);
    
    /* Send Inquiry Information */
    if (krb5_write_message(context, &client_server_info.client_socket, 
			   &msg_data)){
	free(msg_data.data);
	com_err("adm_inq_old_key", 0, "Error Performing Write");
	return(5);		/* Protocol Failure */
    }
    
    free(msg_data.data);
    
    /* Read Client Response */
    if (krb5_read_message(context, &client_server_info.client_socket, &inbuf)){
	com_err("adm_inq_old_key", errno, "Error Performing Read");
	syslog(LOG_ERR, "adm_inq sock %d", client_server_info.client_socket);
	return(5);		/* Protocol Failure */
    }
    
    /* Decrypt Client Response */
    if (retval = krb5_rd_priv(context, auth_context, &inbuf,
			      &msg_data, &replaydata)) {
	com_err("adm_inq_old_key", retval, "krb5_rd_priv error %s",
		error_message(retval));
	free(inbuf.data);
	return(5);		/* Protocol Failure */
    }
    
    /* XXX Decrypt client response.... and we don't use it?!? */
    
    free(msg_data.data);
    free(inbuf.data);
    return(retval);
}

#ifdef SANDIA
krb5_error_code
  check_security(princ, class)
krb5_principal princ;
int class;
{
    char *input_name;
    
    if ((input_name = (char *) calloc (1, 255)) == 0) {
	com_err("check_security", 
		ENOMEM, "while allocating memory for class check");
	return(3);
    }
    
    memcpy((char *) input_name, princ->data[0].data, princ->data[0].length);
    
    if (class) {
	/* Must be Classified Principal */
	if (strlen(input_name) == 8) {
	    if (!(strcmp(&input_name[7], "s") == 0) &&
		!(strcmp(&input_name[7], "c") == 0)) {
		free(input_name);
		return(6);
	    }
	}  else {
	    if (!((strncmp(&input_name[strlen(input_name) - 2], 
			   "_s", 2) == 0) ||
		  (strncmp(&input_name[strlen(input_name) - 2], "_c", 2) == 0))) {
		free(input_name);
		return(6);
	    }
	}
    } else {
	/* Must be Unclassified Principal */
	if ((strlen(input_name) >= 8) ||
	    ((strncmp(&input_name[strlen(input_name) - 2], "_s", 2) == 0) ||
	     (strncmp(&input_name[strlen(input_name) - 2], "_c", 2) == 0))) {
	    free(input_name);
	    return(6);
	}
    }
    
    free(input_name);
    return(0);
}
#endif
