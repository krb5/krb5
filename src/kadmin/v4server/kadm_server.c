/*
 * kadmin/v4server/kadm_server.c
 *
 * Copyright 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 * Kerberos administration server-side subroutines
 */


#include <mit-copyright.h>

#include "k5-int.h"

#include <stdio.h>
#include <string.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#ifdef TIME_WITH_SYS_TIME
#include <time.h>
#endif
#else
#include <time.h>
#endif
#include <syslog.h>

#ifdef KADM5
#include <com_err.h>
#include <kadm5/admin.h>
#include <kadm5/chpass_util_strings.h>
#include <krb5/kdb.h>
extern void *kadm5_handle;
#endif

#include <kadm.h>
#include <kadm_err.h>
#include "kadm_server.h"

extern krb5_context kadm_context;
int fascist_cpw = 0;		/* Be fascist about insecure passwords? */

char pw_required[] = "The version of kpasswd that you are using is not compatible with the\nOpenV*Secure V4 Administration Server.  Please contact your security\nadministrator.\n\n";

char bad_pw_err[] =
	"\007\007\007ERROR: Insecure password not accepted.  Please choose another.\n\n";

char bad_pw_warn[] =
	"\007\007\007WARNING: You have chosen an insecure password.  You may wish to\nchoose a better password.\n\n";

char check_pw_msg[] =
	"You have entered an insecure password.  You should choose another.\n\n";

char pw_blurb[] =
"A good password is something which is easy for you to remember, but that\npeople who know you won't easily guess; so don't use your name, or your\ndog's name, or a word from the dictionary.  Passwords should be at least\n6 characters long, and may contain UPPER- and lower-case letters,\nnumbers, or punctuation.  A good password can be:\n\n   -- some initials, like \"GykoR-66\" for \"Get your kicks on Rte 66.\"\n   -- an easily pronounced nonsense word, like \"slaRooBey\" or \"krang-its\"\n   -- a mis-spelled phrase, like \"2HotPeetzas\" or \"ItzAGurl\"\n\nPlease Note: It is important that you do not tell ANYONE your password,\nincluding your friends, or even people from Athena or Information\nSystems.  Remember, *YOU* are assumed to be responsible for anything\ndone using your password.\n";

/* from V4 month_sname.c --  was not part of API */
/*
 * Given an integer 1-12, month_sname() returns a string
 * containing the first three letters of the corresponding
 * month.  Returns 0 if the argument is out of range.
 */

static char *month_sname(n)
    int n;
{
    static char *name[] = {
        "Jan","Feb","Mar","Apr","May","Jun",
        "Jul","Aug","Sep","Oct","Nov","Dec"
    };
    return((n < 1 || n > 12) ? 0 : name [n-1]);
}

/* from V4 log.c --  was not part of API */

/*
 * krb_log() is used to add entries to the logfile (see krb_set_logfile()
 * below).  Note that it is probably not portable since it makes
 * assumptions about what the compiler will do when it is called
 * with less than the correct number of arguments which is the
 * way it is usually called.
 *
 * The log entry consists of a timestamp and the given arguments
 * printed according to the given "format".
 *
 * The log file is opened and closed for each log entry.
 *
 * The return value is undefined.
 */

/* static char *log_name = KRBLOG; */
/* KRBLOG is in the V4 klog.h but may not correspond to anything installed. */
static char *log_name = KADM_SYSLOG; 

static void krb_log(format,a1,a2,a3,a4,a5,a6,a7,a8,a9,a0)
    char *format;
    char *a1,*a2,*a3,*a4,*a5,*a6,*a7,*a8,*a9,*a0;
{
    FILE *logfile;
    time_t now;
    struct tm *tm;

    if ((logfile = fopen(log_name,"a")) == NULL)
        return;

    (void) time(&now);
    tm = localtime(&now);

    fprintf(logfile,"%2d-%s-%d %02d:%02d:%02d ",tm->tm_mday,
            month_sname(tm->tm_mon + 1),1900+tm->tm_year,
            tm->tm_hour, tm->tm_min, tm->tm_sec);
    fprintf(logfile,format,a1,a2,a3,a4,a5,a6,a7,a8,a9,a0);
    fprintf(logfile,"\n");
    (void) fclose(logfile);
    return;
}


/* 
kadm_ser_cpw - the server side of the change_password routine
  recieves    : KTEXT, {key}
  returns     : CKSUM, RETCODE
  acl         : caller can change only own password

Replaces the password (i.e. des key) of the caller with that specified in key.
Returns no actual data from the master server, since this is called by a user
*/
int
kadm_ser_cpw(dat, len, ad, datout, outlen)
u_char *dat;
int len;
AUTH_DAT *ad;
u_char **datout;
int *outlen;
{
    krb5_int32 keylow, keyhigh;
    char pword[MAX_KPW_LEN];
    int no_pword = 0;
    des_cblock newkey;
    int status, stvlen = 0;
    int	retval;
    extern int kadm_approve_pw();
#ifdef KADM5
    kadm5_principal_ent_rec princ_ent;
    kadm5_policy_ent_rec pol_ent;
    krb5_principal user_princ;
    char msg_ret[1024], *time_string, *ptr;
    const char *msg_ptr;
    krb5_int32 now;
    time_t until;
    krb5_keyblock newkb;
#endif

    /* take key off the stream, and change the database */

    if ((status = stv_long(dat, &keyhigh, 0, len)) < 0)
	return(KADM_LENGTH_ERROR);
    stvlen += status;
    if ((status = stv_long(dat, &keylow, stvlen, len)) < 0)
	return(KADM_LENGTH_ERROR);
    stvlen += status;
    if ((stvlen = stv_string(dat, pword, stvlen, sizeof(pword), len)) < 0) {
	no_pword++;
	pword[0]='\0';
    }
    stvlen += status;

    keylow = ntohl(keylow);
    keyhigh = ntohl(keyhigh);
    memcpy((char *)(((krb5_int32 *)newkey) + 1), (char *)&keyhigh, 4);
    memcpy((char *)newkey, (char *)&keylow, 4);

    retval = kadm_approve_pw(ad->pname, ad->pinst, ad->prealm,
			     newkey, no_pword ? 0 : pword);
    if (retval) {
	    if (retval == KADM_PW_MISMATCH) {
		    /*
		     * Very strange!!!  This means that the cleartext
		     * password which was sent and the DES cblock
		     * didn't match!
		     */
		    syslog(LOG_ERR, "'%s.%s@%s' sent a password string which didn't match with the DES key?!?",
				   ad->pname, ad->pinst, ad->prealm);
		    return(retval);
	    }
	    if (fascist_cpw) {
		    *outlen = strlen(bad_pw_err)+strlen(pw_blurb)+1;
		    *datout = (u_char *) malloc(*outlen);
		    if (*datout) {
			    strcpy((char *) *datout, bad_pw_err);
			    strcat((char *) *datout, pw_blurb);
		    } else
			    *outlen = 0;
		    syslog(LOG_ERR, "'%s.%s@%s' tried to use an insecure password in changepw",
				   ad->pname, ad->pinst, ad->prealm);
#ifdef notdef
		    /* For debugging only, probably a bad idea */
		    if (!no_pword)
			    (void) krb_log("The password was %s\n", pword);
#endif
		    return(retval);
	    } else {
		    *outlen = strlen(bad_pw_warn) + strlen(pw_blurb)+1;
		    *datout = (u_char *) malloc(*outlen);
		    if (*datout) {
			    strcpy((char *) *datout, bad_pw_warn);
			    strcat((char *) *datout, pw_blurb);
		    } else
			    *outlen = 0;
		    syslog(LOG_ERR, "'%s.%s@%s' used an insecure password in changepw",
				   ad->pname, ad->pinst, ad->prealm);
	    }
    } else {
	    *datout = 0;
	    *outlen = 0;
    }

#ifdef KADM5
    if (no_pword)
	syslog(LOG_WARNING,
	       "Old-style change password request from '%s.%s@%s'!",
	       ad->pname, ad->pinst, ad->prealm);
    else {
	/*
	 * We don't use the client-provided key itself, if there is a
	 * password provided.
	 */
	keylow = keyhigh = 0;
	memset(newkey, 0, sizeof(newkey));
    }

    syslog(LOG_INFO, "'%s.%s@%s' wants to change its password",
	   ad->pname, ad->pinst, ad->prealm);
    if ((krb5_425_conv_principal(kadm_context, ad->pname,
				 *ad->pinst ? ad->pinst : 0,
				 ad->prealm, &user_princ))) {
	/* this should never happen */
	memset(newkey, 0, sizeof(newkey));
	return KADM_NOENTRY;
    }

    *outlen = 0;

    retval = krb5_timeofday(kadm_context, &now);
    if (retval) {
	 msg_ptr = error_message(retval);
	 goto send_response;
    }

    /* Use the default mask for now. */
    retval = kadm5_get_principal(kadm5_handle, user_princ,
				 &princ_ent,
				 KADM5_PRINCIPAL_NORMAL_MASK);
    if (retval != 0) {
	 msg_ptr = error_message(retval);
	 goto send_response;
    }

    /*
     * This daemon necessarily has the modify privilege, so
     * kadm5_chpass_principal will allow it to violate the
     * policy's minimum lifetime.  Since that's A Bad Thing, we need
     * to enforce it ourselves.  Unfortunately, this means we are
     * duplicating code from both ovsec_adm_server and
     * kadm5_chpass_util().
     */
    if (princ_ent.aux_attributes & KADM5_POLICY) {
	 retval = kadm5_get_policy(kadm5_handle,
				   princ_ent.policy,
				   &pol_ent);
	 if (retval != 0) {
	      (void) kadm5_free_principal_ent(kadm5_handle, &princ_ent);
	      msg_ptr = error_message(retval);
	      goto send_response;
	 }

	 /* make "now" a boolean, true == too soon */
	 now = ((now - princ_ent.last_pwd_change) < pol_ent.pw_min_life);

	 (void) kadm5_free_policy_ent(kadm5_handle, &pol_ent);
	 
	 if(now && !(princ_ent.attributes & KRB5_KDB_REQUIRES_PWCHANGE)) {
	      (void) kadm5_free_principal_ent(kadm5_handle, &princ_ent);
	      retval = CHPASS_UTIL_PASSWORD_TOO_SOON;

	      until = princ_ent.last_pwd_change + pol_ent.pw_min_life;
	      time_string = ctime(&until);
				  
	      if (*(ptr = &time_string[strlen(time_string)-1]) == '\n')
		   *ptr = '\0';
	      
	      sprintf(msg_ret, error_message(CHPASS_UTIL_PASSWORD_TOO_SOON), 
		      time_string);
	      msg_ptr = msg_ret;
	      
	      goto send_response;
	 }
    }

    (void) kadm5_free_principal_ent(kadm5_handle, &princ_ent);

    if (no_pword) {
	newkb.magic = KV5M_KEYBLOCK;
	if ((newkb.contents = (krb5_octet *)malloc(8)) == NULL) {
	    retval = KADM_NOMEM;
	    goto send_response;
	}
	newkb.length = 8;
	newkb.enctype = ENCTYPE_DES_CBC_CRC;
	memcpy((char *)newkb.contents, newkey, 8);
	retval = kadm5_setv4key_principal(kadm5_handle, user_princ,
					  &newkb);
	memset(newkb.contents, 0, 8);
	*msg_ret = '\0';
    } else {
	retval = kadm5_chpass_principal_util(kadm5_handle, user_princ,
					     pword, NULL, msg_ret,
					     sizeof(msg_ret));
	msg_ptr = msg_ret;
    }
    (void) krb5_free_principal(kadm_context, user_princ);

send_response:

    memset(newkey, 0, sizeof(newkey));
    retval = convert_kadm5_to_kadm(retval);

    if (retval) {
	 /* don't send message on success because kpasswd.v4 will */
	 /* print "password changed" too */
	 *outlen = strlen(msg_ptr)+2;
	 *datout = (u_char *) malloc(*outlen);
	 if (*datout) {
	      strcpy(*datout, msg_ptr);
	      strcat(*datout, "\n");
	 } else
	      *outlen = 0;
    } else {
         syslog(LOG_INFO,
		"'%s.%s@%s' password changed.", 
		ad->pname, ad->pinst, ad->prealm);
    }
    if (retval == KADM_INSECURE_PW) {
          syslog(LOG_ERR, 
		 "'%s.%s@%s' tried to use an insecure password in changepw",
		 ad->pname, ad->pinst, ad->prealm);
    }
#else /* KADM5 */
    retval = kadm_change(ad->pname, ad->pinst, ad->prealm, newkey);
    keylow = keyhigh = 0;
    memset(newkey, 0, sizeof(newkey));
#endif /* KADM5 */
    
    return retval;
}

/*
kadm_ser_add - the server side of the add_entry routine
  recieves    : KTEXT, {values}
  returns     : CKSUM, RETCODE, {values}
  acl         : su, sms (as alloc)

Adds and entry containing values to the database
returns the values of the entry, so if you leave certain fields blank you will
   be able to determine the default values they are set to
*/
int
kadm_ser_add(dat,len,ad, datout, outlen)
u_char *dat;
int len;
AUTH_DAT *ad;
u_char **datout;
int *outlen;
{
  Kadm_vals values, retvals;
  int status;

  if ((status = stream_to_vals(dat, &values, len)) < 0)
      return(KADM_LENGTH_ERROR);
  if ((status = kadm_add_entry(ad->pname, ad->pinst, ad->prealm,
			      &values, &retvals)) == KADM_DATA) {
      *outlen = vals_to_stream(&retvals,datout);
      retvals.key_low = retvals.key_high = 0;
      return KADM_SUCCESS;
  } else {
      *outlen = 0;
      return status;
  }
}

#ifndef KADM5
/*
kadm_ser_del - the server side of the del_entry routine
  recieves    : KTEXT, {values}
  returns     : CKSUM, RETCODE, {values}
  acl         : su, sms (as alloc)

Deletes an entry containing values to the database
returns the values of the entry, so if you leave certain fields blank you will
   be able to determine the default values they are set to
*/
kadm_ser_del(dat,len,ad, datout, outlen)
u_char *dat;
int len;
AUTH_DAT *ad;
u_char **datout;
int *outlen;
{
  Kadm_vals values, retvals;
  int status;

  if ((status = stream_to_vals(dat, &values, len)) < 0)
      return(KADM_LENGTH_ERROR);
  if ((status = kadm_del_entry(ad->pname, ad->pinst, ad->prealm,
			      &values, &retvals)) == KADM_DATA) {
      *outlen = vals_to_stream(&retvals,datout);
      retvals.key_low = retvals.key_high = 0;
      return KADM_SUCCESS;
  } else {
      *outlen = 0;
      return status;
  }
}

#endif /* !KADM5 */

/*
kadm_ser_mod - the server side of the mod_entry routine
  recieves    : KTEXT, {values, values}
  returns     : CKSUM, RETCODE, {values}
  acl         : su, sms (as register or dealloc)

Modifies all entries corresponding to the first values so they match the
   second values.
returns the values for the changed entries
*/
int
kadm_ser_mod(dat,len,ad, datout, outlen)
u_char *dat;
int len;
AUTH_DAT *ad;
u_char **datout;
int *outlen;
{
  Kadm_vals vals1, vals2, retvals;
  int wh;
  int status;

  if ((wh = stream_to_vals(dat, &vals1, len)) < 0)
      return KADM_LENGTH_ERROR;
  if ((status = stream_to_vals(dat+wh,&vals2, len-wh)) < 0)
      return KADM_LENGTH_ERROR;
  if ((status = kadm_mod_entry(ad->pname, ad->pinst, ad->prealm, &vals1,
			       &vals2, &retvals)) == KADM_DATA) {
      *outlen = vals_to_stream(&retvals,datout);
      retvals.key_low = retvals.key_high = 0;
      return KADM_SUCCESS;
  } else {
      *outlen = 0;
      return status;
  }
}

/*
kadm_ser_get
  recieves   : KTEXT, {values, flags}
  returns    : CKSUM, RETCODE, {count, values, values, values}
  acl        : su

gets the fields requested by flags from all entries matching values
returns this data for each matching recipient, after a count of how many such
  matches there were
*/
int
kadm_ser_get(dat,len,ad, datout, outlen)
u_char *dat;
int len;
AUTH_DAT *ad;
u_char **datout;
int *outlen;
{
  Kadm_vals values, retvals;
  u_char fl[FLDSZ];
  int loop,wh;
  int status;

  if ((wh = stream_to_vals(dat, &values, len)) < 0)
      return KADM_LENGTH_ERROR;
  if (wh + FLDSZ > len)
      return KADM_LENGTH_ERROR;
  for (loop=FLDSZ-1; loop>=0; loop--)
    fl[loop] = dat[wh++];
  if ((status = kadm_get_entry(ad->pname, ad->pinst, ad->prealm,
			      &values, fl, &retvals)) == KADM_DATA) {
      *outlen = vals_to_stream(&retvals,datout);
      retvals.key_low = retvals.key_high = 0;
      return KADM_SUCCESS;
  } else {
      *outlen = 0;
      return status;
  }
}

/* 
kadm_ser_ckpw - the server side of the check_password routine
  recieves    : KTEXT, {key}
  returns     : CKSUM, RETCODE
  acl         : none

Checks to see if the des key passed from the caller is a "secure" password.
*/
int
kadm_ser_ckpw(dat, len, ad, datout, outlen)
u_char *dat;
int len;
AUTH_DAT *ad;
u_char **datout;
int *outlen;
{
    krb5_ui_4 keylow, keyhigh;
    char pword[MAX_KPW_LEN];
    int no_pword = 0;
    des_cblock newkey;
    int stvlen = 0,status;
    int	retval;
    extern int kadm_approve_pw();

    /* take key off the stream, and check it */

    if ((status = stv_long(dat, &keyhigh, 0, len)) < 0)
	return(KADM_LENGTH_ERROR);
    stvlen += status;
    if ((status = stv_long(dat, &keylow, stvlen, len)) < 0)
	return(KADM_LENGTH_ERROR);
    stvlen += status;
    if ((status = stv_string(dat, pword, stvlen, sizeof(pword), len)) < 0) {
	no_pword++;
	pword[0]='\0';
    }
    stvlen += status;

    keylow = ntohl(keylow);
    keyhigh = ntohl(keyhigh);
    memcpy((char *)(((krb5_int32 *)newkey) + 1), (char *)&keyhigh, 4);
    memcpy((char *)newkey, (char *)&keylow, 4);
    keylow = keyhigh = 0;
    retval = kadm_approve_pw(ad->pname, ad->pinst, ad->prealm, newkey,
			no_pword ? 0 : pword);
    memset(newkey, 0, sizeof(newkey));
    if (retval) {
	    *outlen = strlen(check_pw_msg)+strlen(pw_blurb)+1;
	    *datout = (u_char *) malloc(*outlen);
	    if (*datout) {
		    strcpy((char *) *datout, check_pw_msg);
		    strcat((char *) *datout, pw_blurb);
	    } else
		    *outlen = 0;
	    (void) krb_log("'%s.%s@%s' sent an insecure password to be checked",
			   ad->pname, ad->pinst, ad->prealm);
	    return(retval);
    } else {
	    *datout = 0;
	    *outlen = 0;
	    (void) krb_log("'%s.%s@%s' sent a secure password to be checked",
			   ad->pname, ad->pinst, ad->prealm);
    }
    return(0);
}

/*
kadm_ser_stab - the server side of the change_srvtab routine
  recieves    : KTEXT, {values}
  returns     : CKSUM, RETCODE, {values}
  acl         : su, sms (as register or dealloc)

Creates or modifies the specified service principal to have a random
key, which is sent back to the client.  The key version is returned in
the max_life field of the values structure.  It's a hack, but it's a
backwards compatible hack....
*/
int
kadm_ser_stab(dat, len, ad, datout, outlen)
u_char *dat;
int len;
AUTH_DAT *ad;
u_char **datout;
int *outlen;
{
  Kadm_vals values;
  int status;

  if ((status = stream_to_vals(dat, &values, len)) < 0)
	  return KADM_LENGTH_ERROR;
  status = kadm_chg_srvtab(ad->pname, ad->pinst, ad->prealm, &values);
  if (status == KADM_DATA) {
      *outlen = vals_to_stream(&values,datout);
      values.key_low = values.key_high = 0;
      return KADM_SUCCESS;
  } else {
      *outlen = 0;
      return status;
  }
}
