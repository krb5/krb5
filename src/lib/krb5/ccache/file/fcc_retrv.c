/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * This file contains the source code for krb5_fcc_retrieve.
 */

#if !defined(lint) && !defined(SABER)
static char fcc_retrieve_c[] = "$Id$";
#endif /* !lint && !SABER */

#include <krb5/copyright.h>

#include "fcc.h"

#define set(bits) (whichfields & bits)
#define flags_match(a,b) (a & b == a)
#define times_match_exact(t1,t2) (bcmp(&t1, &t2, sizeof(t1)) == 0)
#define times_match times_match_exact /* XXX WRONG! XXX */
     
/*
 * Effects:
 * Searches the file cred cache is for a credential matching mcreds,
 * with the fields specified by whichfields.  If one if found, it is
 * returned in creds, which should be freed by the caller with
 * krb5_free_credentials().
 * 
 * The fields are interpreted in the following way (all constants are
 * preceded by KRB5_TC_).  MATCH_IS_SKEY requires the is_skey field to
 * match exactly.  MATCH_TIMES requires the requested lifetime to be
 * at least as great as that specified; MATCH_TIMES_EXACT requires the
 * requested lifetime to be exactly that specified.  MATCH_FLAGS
 * requires only the set bits in mcreds be set in creds;
 * MATCH_FLAGS_EXACT requires all bits to match.
 *
 * Errors:
 * system errors
 * permission errors
 * KRB5_NOMEM
 */
krb5_error_code
krb5_fcc_retrieve(id, whichfields, mcreds, creds)
   krb5_ccache id;
   krb5_flags whichfields;
   krb5_creds *mcreds;
   krb5_creds *creds;
{
     /* This function could be considerably faster if it kept indexing */
     /* information.. sounds like a "next version" idea to me. :-) */

     krb5_cc_cursor cursor;
     krb5_error_code kret;

     kret = krb5_fcc_start_seq_get(id, &cursor);
     if (kret != KRB5_OK)
	  return kret;

     while ((kret = krb5_fcc_next_cred(id, &cursor, creds)) == KRB5_OK) {
	  if (1 /* XXX standard_fields_match(mcreds, creds) */
	      &&
	      (! set(KRB5_TC_MATCH_IS_SKEY) ||
	       mcreds->is_skey == creds->is_skey)
	      &&
	      (! set(KRB5_TC_MATCH_FLAGS_EXACT) ||
	       mcreds->ticket_flags == creds->ticket_flags)
	      &&
	      (! set(KRB5_TC_MATCH_FLAGS) ||
	       flags_match(mcreds->ticket_flags, creds->ticket_flags))
	      &&
	      (! set(KRB5_TC_MATCH_TIMES_EXACT) ||
	       times_match_exact(mcreds->times, creds->times))
	      &&
	      (! set(KRB5_TC_MATCH_TIMES) ||
	       times_match(mcreds->times, creds->times)))
	  {
	       krb5_fcc_end_seq_get(id, &cursor);
	       return KRB5_OK;
	  }

	  /* This one doesn't match */
	  /* XXX krb5_free_credentials(creds); */
     }

     /* If we get here, a match wasn't found */
     krb5_fcc_end_seq_get(id, &cursor);
     return KRB5_NOTFOUND;
}

