/*
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
 * Note: The internal interfaces to this routine are subject to change
 * and/or cleanup.  You should only expect the interfaces to
 * krb5_obtain_padata and krb5_verify_padata to have some chance of
 * staying stable.  [tytso:19920903.1544EDT]
 */

/*
 * This file contains routines for establishing, verifying, and any other
 * necessary functions, for utilizing the pre-authentication field of the 
 * kerberos kdc request, with various hardware/software verification devices.
 *
 * Note: At some point these functions may very well be split apart
 * into different files.... [tytso:19920903.1618EDT]
 */

#include "k5-int.h"
#include <stdio.h>
#include <time.h>
#include <syslog.h>
#ifdef _MSDOS
#define getpid _getpid
#include <process.h>
#endif

static krb5_preauth_ops preauth_systems[] = {
    {
	0,
        KRB5_PADATA_ENC_UNIX_TIME,
        KRB5_PREAUTH_FLAGS_ENCRYPT,
        get_unixtime_padata,
        verify_unixtime_padata,
    },
    {
	0,
	KRB5_PADATA_ENC_SANDIA_SECURID,
	KRB5_PREAUTH_FLAGS_ENCRYPT | KRB5_PREAUTH_FLAGS_HARDWARE,
	get_securid_padata,
	verify_securid_padata,
    },
    { -1,}
};

static krb5_error_code find_preauthenticator
    PROTOTYPE((int type, krb5_preauth_ops **Preauth_proc));

/*
 *   krb5_obtain_padata  is a glue routine which when passed in
 *   a preauthentication type, client principal, and src_addr, returns
 *   preauthentication data contained in data to be passed onto the KDC.
 *   
 *   If problems occur then a non zero value is returned...
 *
 *   Note: This is a first crack at what any preauthentication will need...
 */
krb5_error_code
krb5_obtain_padata(context, type, client, src_addr, encrypt_key, ret_data)
    krb5_context context;
    int type;			 	/*IN:  Preauth type */
    krb5_principal client;		/*IN:  requestor */
    krb5_address **src_addr;            /*IN:  array of ptrs to addresses */
    krb5_keyblock *encrypt_key;		/*IN:  encryption key */
    krb5_pa_data **ret_data;			/*OUT: Returned padata */
{
    krb5_error_code	retval;
    krb5_preauth_ops	*p_system;
    krb5_encrypt_block	eblock;
    krb5_data		scratch;
    krb5_pa_data	*data;

    if (!ret_data)
	return EINVAL;
    *ret_data = 0;
    
    if (type == KRB5_PADATA_NONE ) 
	return(0);

    data = (krb5_pa_data *) malloc(sizeof(krb5_pa_data));
    if (!data)
	return ENOMEM;
    
    data->length = 0;
    data->contents = 0;
    data->pa_type = type;

    /* Find appropriate preauthenticator */
    retval = find_preauthenticator(type, &p_system);
    if (retval)
	goto error_out;

    retval = (*p_system->obtain)(context, client, src_addr, data );
    if (retval)
	goto error_out;

    /* Check to see if we need to encrypt padata */
    if (p_system->flags & KRB5_PREAUTH_FLAGS_ENCRYPT) {
	/* If we dont have a encryption key we are out of luck */
	if (!encrypt_key) {
	    retval = KRB5_PREAUTH_NO_KEY;
	    goto error_out;
	}
        krb5_use_enctype(context, &eblock, encrypt_key->enctype);

	/* do any necessay key pre-processing */
	retval = krb5_process_key(context, &eblock, encrypt_key);
	if (retval)
	    goto error_out;
	
	/*
	 * Set up scratch data and length for encryption 
	 * Must allocate more space for checksum and confounder
	 * We also leave space for an uncrypted size field.
	 */
	scratch.length = krb5_encrypt_size(data->length,
					   eblock.crypto_entry) + 4;
	
	if(!(scratch.data = malloc(scratch.length))){
	    (void) krb5_finish_key(context, &eblock);
	    retval = ENOMEM;
	    goto error_out;
	}
	
	scratch.data[0] = data->length >> 24;
	scratch.data[1] = data->length >> 16;
	scratch.data[2] = data->length >> 8;
	scratch.data[3] = data->length;

	/* Encrypt preauth data in encryption key */
	if ((retval = krb5_encrypt(context, (krb5_pointer) data->contents,
				   (char *) scratch.data + 4,
				   data->length, &eblock, 0))) {
	    (void) krb5_finish_key(context, &eblock);
	    free(scratch.data);
	    goto error_out;
	}
	(void) krb5_finish_key(context, &eblock);
	    
	free(data->contents);
	data->length = scratch.length;
	data->contents = (unsigned char *) scratch.data;
    }

    *ret_data = data;
    return 0;
    
error_out:
    free(data);
    return retval;
}

/*
 *   krb5_verify_padata  is a glue routine which when passed in
 *   the client, src_addr and padata verifies it with the appropriate 
 *   verify function.
 *  
 *   If problems occur then a non zero value is returned...
 *   else returns zero if padata verifies, and returns a "unique" id.
 *
 *   Note: This is a first crack at what any preauthentication will need...
 */

krb5_error_code
krb5_verify_padata(context, data,client,src_addr, decrypt_key, req_id, flags)
    krb5_context context;
    krb5_pa_data *data;                 /*IN: padata */
    krb5_principal client;              /*IN: requestor */
    krb5_address **src_addr;            /*IN: array of ptrs to addresses */
    krb5_keyblock *decrypt_key;		/*IN: decryption key */
    int * req_id;			/*OUT: identifier */
    int * flags;			/*OUT: flags  */
{
    krb5_preauth_ops	*p_system;
    krb5_encrypt_block 	eblock;
    krb5_data		scratch;
    int 		free_scratch = 0;
    krb5_checksum	cksum;
    krb5_error_code	retval;

    if (!data)
	return(EINVAL);

    /* Find appropriate preauthenticator */
    retval = find_preauthenticator((int) data->pa_type, &p_system);
    if (retval)
	return retval;

    /* Check to see if we need to decrypt padata */
    if (p_system->flags & KRB5_PREAUTH_FLAGS_ENCRYPT) {

	/* If we dont have a decryption key we are out of luck */
	if (!decrypt_key)
	    return(EINVAL);

        krb5_use_enctype(context, &eblock, decrypt_key->enctype);

        scratch.length = data->length;
        if (!(scratch.data = (char *)malloc(scratch.length))) {
           return(ENOMEM);
        }

	/* do any necessay key pre-processing */
	retval = krb5_process_key(context, &eblock,decrypt_key);
	if (retval) {
           free(scratch.data);
           return(retval);
        }

	/* Decrypt data */
	retval = krb5_decrypt(context, (char *) data->contents + 4,
			      (krb5_pointer) scratch.data,
			      scratch.length - 4, &eblock, 0);
	if (retval) {
           (void) krb5_finish_key(context, &eblock);
           free(scratch.data);
           return(retval);
	}

	scratch.length  = (((int) ((unsigned char *)data->contents)[0] << 24)
			   + ((int) ((unsigned char *)data->contents)[1] << 16)
			   + ((int) ((unsigned char *)data->contents)[2] << 8)
			   + (int) ((unsigned char *)data->contents)[3]);
	free_scratch++;
    } else {
	scratch.data = (char *) data->contents;
	scratch.length = data->length;
    }

    retval = (*p_system->verify)(context, client, src_addr, &scratch);
    if (free_scratch)
	free(scratch.data);
    if (retval)
	return retval;
    if (flags)
	*flags = p_system->flags;

    /* Generate a request id by crc32ing the (encrypted) preauth data. */
    /* Note: The idea behind req_id is that it is dependant upon
             the information in data. This could then be used for
             replay detection. */
    /* MUST malloc cksum.contents */
    cksum.contents = (krb5_octet *)calloc(1,
				krb5_checksum_size(context, CKSUMTYPE_CRC32));
    if (!cksum.contents) return(1);

    if (krb5_calculate_checksum(context, CKSUMTYPE_CRC32,
			data->contents,
			data->length,
                        0, /* seed is ignored */
                        0, /* seed length is ignored */
                        &cksum )) {
        *req_id = 0;
    } else {
        /* Checksum length should be 32 bits, so truncation should never
           take place */
        if ( cksum.length > sizeof(*req_id)) cksum.length = sizeof(*req_id);

        /* Offset req_id for 64 bit systems */
        memcpy((char *)req_id + (sizeof(*req_id) - cksum.length),
                cksum.contents,cksum.length);
    } 
    free(cksum.contents);
    return(0);
}

static krb5_error_code
find_preauthenticator(type, preauth)
    int			type;
    krb5_preauth_ops	**preauth;
{
    krb5_preauth_ops *ap = preauth_systems;
    
    while ((ap->type != -1) && (ap->type != type))
	ap++;
    if (ap->type == -1)
	return(KRB5_PREAUTH_BAD_TYPE);
    *preauth = ap;
    return 0;
} 

/*
 * Format is:   8 bytes of random confounder,
 *              1 byte version number (currently 0),
 *              4 bytes: number of seconds since Jan 1, 1970, in MSB order.
 */
int seeded = 0 ; /* Used by srand below */

krb5_error_code
get_unixtime_padata(context, client, src_addr, pa_data)
    krb5_context context;
    krb5_principal client;
    krb5_address **src_addr;
    krb5_pa_data *pa_data;
{
    unsigned char *tmp;
    krb5_error_code     retval;
    krb5_timestamp kdc_time;
    int         i;

    pa_data->length = 13;
    tmp = pa_data->contents = (unsigned char *) malloc(pa_data->length);
    if (!tmp) 
        return(ENOMEM);

    retval = krb5_timeofday(context, &kdc_time);
    if (retval)
        return retval;
    if ( !seeded) {
	seeded = (int) kdc_time + getpid();
	srand(seeded);
    }

    for (i=0; i < 8; i++)
        *tmp++ = rand() & 255;

    *tmp++ = (unsigned char) 0;
    *tmp++ = (unsigned char) ((kdc_time >> 24) & 255);
    *tmp++ = (unsigned char) ((kdc_time >> 16) & 255);
    *tmp++ = (unsigned char) ((kdc_time >> 8) & 255);
    *tmp++ = (unsigned char) (kdc_time & 255);

    return(0);
}

krb5_error_code
verify_unixtime_padata(context, client, src_addr, data)
    krb5_context context;
    krb5_principal client;
    krb5_address **src_addr;
    krb5_data *data;
{
    unsigned char       *tmp;
    krb5_error_code     retval;
    krb5_timestamp      currenttime, patime;
    extern krb5_deltat  krb5_clockskew;
#define in_clock_skew(date) (labs((date)-currenttime) < krb5_clockskew)

    tmp = (unsigned char *) data->data;
    if (tmp[8] != 0)
        return KRB5_PREAUTH_FAILED;
    patime = (int) tmp[9] << 24;
    patime += (int) tmp[10] << 16;
    patime += (int) tmp[11] << 8;
    patime += tmp[12];

    retval = krb5_timeofday(context, &currenttime);
    if (retval)
        return retval;

    if (!in_clock_skew(patime))
        return KRB5_PREAUTH_FAILED;

    return 0;
}

#ifdef KRBCONF_SECUREID
#include "sdcli.h"
#include "sdconf.c"

krb5_error_code
verify_securid_padata(client, src_addr, data)
    krb5_principal client;
    krb5_address **src_addr;
    krb5_data *data;
{
   extern perform_hw;

   if (perform_hw) {
        krb5_error_code	retval;
        char username[255];
        struct SD_CLIENT sd;

	memset((char *)&sd,0, sizeof (sd));
   	memset((char *) username, 0, sizeof(username));
        memcpy((char *) username, krb5_princ_component(context, client,0)->data,
                        	  krb5_princ_component(context, client,0)->length);
        /* If Instance then Append */
 	if (krb5_princ_size(context, client) > 1 ) {
	    if (strncmp(krb5_princ_realm(context, client)->data,
			krb5_princ_component(context, client,1)->data,
			krb5_princ_component(context, client,1)->length) ||
		        krb5_princ_realm(context, client)->length != 
			krb5_princ_component(context, client,1)->length) {
		strncat(username,"/",1);
		strncat(username,krb5_princ_component(context, client,1)->data,
				 krb5_princ_component(context, client,1)->length);
	    }
	}
        if (retval = sd_check(data->data,username,&sd) != ACM_OK) {
		syslog(LOG_INFO, 
		    "%s - Invalid Securid Authentication Data sd_check Code %d",
			username, retval);
		return(KRB5_PREAUTH_FAILED);
	}
	return(0);
    } else {
        char *username = 0;

	krb5_unparse_name(context, client,&username);
	syslog(LOG_INFO, 
	    "%s Provided Securid but this KDC does not support Securid",
		username);
	free(username);
	return(KRB5_PREAUTH_FAILED);
    }
}
#else
krb5_error_code
verify_securid_padata(context, client, src_addr, data)
    krb5_context context;
    krb5_principal client;
    krb5_address **src_addr;
    krb5_data *data;
{
 char *username = 0;
	krb5_unparse_name(context, client,&username);
	syslog(LOG_INFO, 
	    "%s Provided Securid but this KDC does not support Securid",
		username);
	free(username);
	return(KRB5_PREAUTH_FAILED);
}

#endif


/*
static char *krb5_SecureId_prompt = "\nEnter Your SecurId Access Code Prepended with Your PIN\n (or a \'#\'if Your PIN is entered on the card keypad)\n or Type return <CR> if You Do NOT Use a SecurId Card: ";
 */
static char *krb5_SecureId_prompt = "\nEnter Your SecurId Access Code Prepended with Your PIN\n (or a \'#\'if Your PIN is entered on the card keypad): ";

krb5_error_code
get_securid_padata(context, client,src_addr,pa_data)
    krb5_context context;
    krb5_principal client;
    krb5_address **src_addr;
    krb5_pa_data *pa_data;
{

 char temp[MAX_PREAUTH_SIZE];   
 int tempsize;
 int retval = 0;

    tempsize = sizeof(temp) - 1;
    if (krb5_read_password(context, krb5_SecureId_prompt, 0, temp, &tempsize))
        return(KRB5_PARSE_ILLCHAR);
    temp[tempsize] = '\0';

    if (temp[0] == '\0') 
	return(KRB5_PARSE_ILLCHAR);
    pa_data->length = strlen(temp) + 1;
    pa_data->contents = (krb5_octet *) calloc(1,pa_data->length);
    if (pa_data->contents) {
        memcpy(pa_data->contents,temp,pa_data->length);
	retval = 0;
    }
    else retval = ENOMEM;
    memset(temp,0,pa_data->length);
    return(retval);
}
