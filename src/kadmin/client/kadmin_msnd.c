/*
 * kadmin/client/kadmin_msnd.c
 *
 * Copyright 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 */

/* 
 * Sandia National Laboratories also makes no representations about the 
 * suitability of the modifications, or additions to this software for 
 * any purpose.  It is provided "as is" without express or implied warranty.
 */


/*
 * kadmin_snd_mod
 * Perform Remote Kerberos Administrative Functions
 */

#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>
#include <string.h>
#include <com_err.h>

#include <sys/param.h>
#include <pwd.h>

#include <krb5/adm_defs.h>

#include <sys/stat.h>

#include <krb5/krb5.h>
#include <krb5/kdb.h>
#include <krb5/kdb_dbm.h>
#include <krb5/ext-proto.h>
#include <krb5/los-proto.h>
#include <krb5/asn1.h>
#include <krb5/config.h>
#include <krb5/base-defs.h>
#include <krb5/asn.1/encode.h>
#include <krb5/adm_err.h>
#include <krb5/errors.h>
#include <krb5/kdb5_err.h>
#include <krb5/krb5_err.h>

#ifndef MAXPATHLEN
#define MAXPATHLEN 1024
#endif

krb5_error_code
kadm_snd_mod(context, my_creds, rep_ret, local_addr, foreign_addr, 
	     local_socket, seqno)
    krb5_context context;
    krb5_creds *my_creds;
    krb5_ap_rep_enc_part *rep_ret;
    krb5_address *local_addr, *foreign_addr;
    int *local_socket;
    krb5_int32 *seqno;
{
    krb5_error_code retval;     /* return code */
    krb5_data msg_data, inbuf;
    char mod_type[10];
    char attrib[20];
    char version[10];
    int value;
    int valid_command;
    int i;

    for ( ; ; ) {
	valid_command = 0;
repeat1:
#ifdef SANDIA
	fprintf(stdout, "\nParameter Type to be Modified (fcnt, vno, attr, or q): ");
#else
	fprintf(stdout, "\nParameter Type to be Modified (vno, attr, or q): ");
#endif
                         
	(void) fgets(mod_type, 10, stdin);
	mod_type[strlen(mod_type) - 1] = '\0';

	if ((inbuf.data = (char *) calloc(1, 80)) == (char *) 0) {
            fprintf(stderr, "No memory for command!\n");
            exit(1);
	}

	if (!strcmp(mod_type, "q")) {
	    free(inbuf.data);
	    goto alldone;
	}
#ifdef SANDIA
	if (!strcmp(mod_type, "fcnt")) {
	    valid_command = 1;
repeat_cnt:
	    fprintf(stdout, "\nFailure Count: ");
	    (void) fgets(version, sizeof(version), stdin);
	    /* Make sure version is null terminated */
	    version[sizeof(version) -1] = '\0';
	    /* Strip linefeed */
	    if (version[strlen(version) - 1] == '\n')
	        version[strlen(version) - 1] = '\0';
	    if (!strcmp(version, "q")) {
            	free(inbuf.data);
            	goto alldone;
            }
	    value = -1;
	    sscanf(version,"%d",&value);
	    if (value < 0 || value > 10 ) {
	        fprintf(stderr, "Value must be between 0 and 10!\n");
	        goto repeat_cnt;
	    }
            inbuf.data[3] = KMODFCNT;
	    (void) memcpy(inbuf.data + 4, version, strlen(version));
	    inbuf.length = strlen(version) + 4;
        }
#endif
	if (!strcmp(mod_type, "vno")) {
	    valid_command = 1;
repeat2:
	    fprintf(stdout, "\nVersion Number: ");
            (void) fgets(version, sizeof(version), stdin);
            /* Make sure version is null terminated */
            version[sizeof(version) -1] = '\0';
            /* Strip linefeed */
            if (version[strlen(version) - 1] == '\n')
                version[strlen(version) - 1] = '\0';
            if (!strcmp(version, "q")) {
                free(inbuf.data);
                goto alldone;
            }
            value = -1;
            sscanf(version,"%d",&value);
	    if (value < 0 || value > 255 ) {
	        fprintf(stderr, "Value must be between 0 and 255!\n");
	        goto repeat2;
	    }
            inbuf.data[3] = KMODVNO;
	    (void) memcpy(inbuf.data + 4, version, strlen(version));
	    inbuf.length = strlen(version) + 4;
        }

	if (!strcmp(mod_type, "attr")) {
	     valid_command = 1;
repeat3:
	    fprintf(stdout, "\nAttribute: ");
	    fgets(attrib, 20, stdin);
	    attrib[strlen(attrib) - 1] = '\0';
	    for (i = 0; attrib[i] != '\0'; i++)
		if (isupper(attrib[i]))
		    attrib[i] = tolower(attrib[i]);

            inbuf.data[3] = KMODATTR;
	    inbuf.data[4] = BADATTR;
            inbuf.length = 5;
	    if (!strcmp(attrib, "post")) inbuf.data[4] = ATTRPOST;
	    if (!strcmp(attrib, "nopost")) inbuf.data[4] = ATTRNOPOST;
	    if (!strcmp(attrib, "forward")) inbuf.data[4] = ATTRFOR;
	    if (!strcmp(attrib, "noforward")) inbuf.data[4] = ATTRNOFOR;
	    if (!strcmp(attrib, "tgt")) inbuf.data[4] = ATTRTGT;
	    if (!strcmp(attrib, "notgt")) inbuf.data[4] = ATTRNOTGT;
	    if (!strcmp(attrib, "ren")) inbuf.data[4] = ATTRREN;
	    if (!strcmp(attrib, "noren")) inbuf.data[4] = ATTRNOREN;
	    if (!strcmp(attrib, "proxy")) inbuf.data[4] = ATTRPROXY;
	    if (!strcmp(attrib, "noproxy")) inbuf.data[4] = ATTRNOPROXY;
	    if (!strcmp(attrib, "dskey")) inbuf.data[4] = ATTRDSKEY;
	    if (!strcmp(attrib, "nodskey")) inbuf.data[4] = ATTRNODSKEY;
	    if (!strcmp(attrib, "lock")) inbuf.data[4] = ATTRLOCK;
	    if (!strcmp(attrib, "unlock")) inbuf.data[4] = ATTRUNLOCK;
	    if (!strcmp(attrib, "svr")) inbuf.data[4] = ATTRSVR;
	    if (!strcmp(attrib, "nosvr")) inbuf.data[4] = ATTRNOSVR;

#ifdef SANDIA
	    if (!strcmp(attrib, "preauth")) inbuf.data[4] = ATTRPRE;
	    if (!strcmp(attrib, "nopreauth")) inbuf.data[4] = ATTRNOPRE;
	    if (!strcmp(attrib, "pwok")) inbuf.data[4] = ATTRPWOK;
	    if (!strcmp(attrib, "pwchange")) inbuf.data[4] = ATTRPWCHG;
	    if (!strcmp(attrib, "sid")) inbuf.data[4] = ATTRSID;
	    if (!strcmp(attrib, "nosid")) inbuf.data[4] = ATTRNOSID;
#endif
	    if (!strcmp(attrib, "q")){
            	free(inbuf.data);
            	goto alldone;
            }
	    if (inbuf.data[4] == BADATTR) {
	        fprintf(stderr, "Valid Responses are:\n");
	        fprintf(stderr, "post/nopost - Allow/Disallow postdating\n");
	        fprintf(stderr, "forward/noforward - Allow/Disallow forwarding\n");
	        fprintf(stderr, "tgt/notgt - Allow/Disallow initial tickets\n");
	        fprintf(stderr, "ren/noren - Allow/Disallow renewable tickets\n");
	        fprintf(stderr, 
		    "proxy/noproxy - Allow/Disallow proxiable tickets\n");
	            fprintf(stderr, 
		    "dskey/nodskey - Allow/Disallow Duplicate Session Keys\n");
	        fprintf(stderr, "lock/unlock - Lock/Unlock client\n");
		fprintf(stderr, 
		    "svr/nosvr - Allow/Disallow Use of Principal as Server\n");
#ifdef SANDIA
	        fprintf(stderr, 
		    "preauth/nopreauth - Require/Do Not Require preauthentication\n");
		fprintf(stderr, 
		   "pwok/pwchange - Password is OK/Needs to be changed\n");
	        fprintf(stderr, 
		    "sid/nosid - Require/Do Not Require Hardware Authentication\n");
#endif
		fprintf(stderr, "q - Quit from setting attributes.\n");
	        goto repeat3;
	    }
	}

	if (!valid_command) {
	    free(inbuf.data);
	    fprintf(stderr, "Invalid command - Try Again\n");
	    goto repeat1;
	}

	inbuf.data[0] = KADMIN;
	inbuf.data[1] = MODOPER;
	inbuf.data[2] = SENDDATA3;

	if ((retval = krb5_mk_priv(context, &inbuf,
			ETYPE_DES_CBC_CRC,
			&my_creds->keyblock, 
			local_addr, 
			foreign_addr,
			*seqno,
			KRB5_PRIV_DOSEQUENCE|KRB5_PRIV_NOTIME,
			0,
			0,
			&msg_data))) {
            fprintf(stderr, "Error during Second Message Encoding: %s!\n",
			error_message(retval));
	    free(inbuf.data);
            return(1);
	}
	free(inbuf.data);

    /* write private message to server */
	if (krb5_write_message(context, local_socket, &msg_data)) {
            fprintf(stderr, "Write Error During Second Message Transmission!\n");
            return(1);
	} 
	free(msg_data.data);

    /* Ok Now let's get the private message */
	if (retval = krb5_read_message(context, local_socket, &inbuf)){
            fprintf(stderr, "Read Error During Second Reply: %s!\n",
                        error_message(retval));
            return(1);
	}

	if ((retval = krb5_rd_priv(context, &inbuf,
			&my_creds->keyblock,
                        foreign_addr,
                        local_addr,
                        rep_ret->seq_number,
                        KRB5_PRIV_DOSEQUENCE|KRB5_PRIV_NOTIME,
                        0,
                        0,
                        &msg_data))) {
            fprintf(stderr, "Error during Second Read Decoding :%s!\n",
                        error_message(retval));
            free(inbuf.data);
            return(1);     
	}
	free(inbuf.data);
    }	/* for */

alldone:
    if ((inbuf.data = (char *) calloc(1, 80)) == (char *) 0) {
	fprintf(stderr, "No memory for command!\n");
	exit(1);
    }

    inbuf.data[0] = KADMIN;
    inbuf.data[1] = KADMGOOD;
    inbuf.data[2] = SENDDATA3;
    inbuf.length = 3;

    if ((retval = krb5_mk_priv(context, &inbuf,
			ETYPE_DES_CBC_CRC,
			&my_creds->keyblock, 
			local_addr, 
			foreign_addr,
			*seqno,
			KRB5_PRIV_DOSEQUENCE|KRB5_PRIV_NOTIME,
			0,
			0,
			&msg_data))) {
	fprintf(stderr, "Error during Second Message Encoding: %s!\n",
			error_message(retval));
	free(inbuf.data);
	return(1);
    }
    free(inbuf.data);

    /* write private message to server */
    if (krb5_write_message(context, local_socket, &msg_data)) {
	fprintf(stderr, "Write Error During Second Message Transmission!\n");
	return(1);
    } 
    free(msg_data.data);

    return(0);
}
