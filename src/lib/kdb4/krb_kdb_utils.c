/*
 * Copyright 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 * Utility routines for Kerberos programs which directly access
 * the database.  This code was duplicated in too many places
 * before I gathered it here.
 *
 * Jon Rochlis, MIT Telecom, March 1988
 */

#include <mit-copyright.h>
#include <des.h>
#include <krb.h>
#include <krb_db.h>
#include <kdc.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/file.h>
#include <fcntl.h>	/* just for O_* for sco */

long kdb_get_master_key_from(prompt, master_key, master_key_sched, verify,
			     kfilename)
     int prompt;
     C_Block master_key;
     Key_schedule master_key_sched;
     int verify;
     char *kfilename;
{
  int kfile;

  if (prompt)  {
#ifdef NOENCRYPTION
      placebo_read_password(master_key,
			    "Kerberos master key: ", verify);
#else
      des_read_password(master_key,
			"Kerberos master key: ", verify);
#endif
      printf ("\n");
  }
  else {
    kfile = open(kfilename?kfilename:MKEYFILE, O_RDONLY, 0600);
    if (kfile < 0) {
      /* oh, for com_err_ */
      return (-1);
    }
    if (read(kfile, (char *) master_key, 8) != 8) {
      return (-1);
    }
    close(kfile);
  }

#ifndef NOENCRYPTION
  key_sched(master_key, master_key_sched);
#endif
  return (0);
}

long kdb_get_master_key(prompt, master_key, master_key_sched, verify)
     int prompt;
     C_Block master_key;
     Key_schedule master_key_sched;
     int verify;
{
  return kdb_get_master_key_from(prompt, master_key, master_key_sched,
				 verify, NULL);
}

/* The caller is reasponsible for cleaning up the master key and sched,
   even if we can't verify the master key */

/* Returns master key version if successful, otherwise -1 */

long kdb_verify_master_key (master_key, master_key_sched, out)
     C_Block master_key;
     Key_schedule master_key_sched;
     FILE *out;  /* setting this to non-null be do output */
{
  C_Block key_from_db;
  Principal principal_data[1];
  int n, more = 0;
  long master_key_version;

  /* lookup the master key version */
  n = kerb_get_principal(KERB_M_NAME, KERB_M_INST, principal_data,
			 1 /* only one please */, &more);
  if ((n != 1) || more) {
    if (out != (FILE *) NULL) 
      fprintf(out,
	      "verify_master_key: %s, %d found.\n",
	      "Kerberos error on master key version lookup",
	      n);
    return (-1);
  }

  master_key_version = (long) principal_data[0].key_version;

  /* set up the master key */
  if (out != (FILE *) NULL)  /* should we punt this? */
    fprintf(out, "Current Kerberos master key version is %d.\n",
	    principal_data[0].kdc_key_ver);

  /*
   * now use the master key to decrypt the key in the db, had better
   * be the same! 
   */
  memcpy(key_from_db, &principal_data[0].key_low, sizeof(KRB4_32));
  memcpy(((KRB4_32 *) key_from_db) + 1, &principal_data[0].key_high, sizeof(KRB4_32));
  kdb_encrypt_key (key_from_db, key_from_db, 
		   master_key, master_key_sched, DECRYPT);

  /* the decrypted database key had better equal the master key */
  n = memcmp((char *) master_key, (char *) key_from_db,
	   sizeof(master_key));
  /* this used to zero the master key here! */
  memset(key_from_db, 0, sizeof(key_from_db));
  memset(principal_data, 0, sizeof (principal_data));

  if (n && (out != (FILE *) NULL)) {
    fprintf(out, "\n\07\07verify_master_key: Invalid master key; ");
    fprintf(out, "does not match database.\n");
    return (-1);
  }
  if (out != (FILE *) NULL) {
    fprintf(out, "\nMaster key entered.\n");
    fflush(out);
  }

  return (master_key_version);
}

/* The old algorithm used the key schedule as the initial vector which
   was byte order depedent ... */

kdb_encrypt_key (in, out, master_key, master_key_sched, e_d_flag)
     C_Block in, out, master_key;
     Key_schedule master_key_sched;
     int e_d_flag;
{

#ifdef NOENCRYPTION
  memcpy(out, in, sizeof(C_Block));
#else
  pcbc_encrypt((C_Block *)in, (C_Block *)out, (long) sizeof(C_Block),
	       master_key_sched, (C_Block *)master_key, e_d_flag);
#endif
}
