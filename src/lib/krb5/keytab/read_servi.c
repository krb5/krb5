/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * This routine is designed to be passed to krb5_rd_req.  
 * It is a convenience function that reads a key out of a keytab.
 * It handles all of the opening and closing of the keytab 
 * internally. 
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_krb5_kt_read_service_key_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>

#include <krb5/ext-proto.h>

/* XXX  Things that I need and don't know where to get yet */
#define KSUCCESS 0

krb5_error_code 
krb5_kt_read_service_key(DECLARG(krb5_pointer, keyprocarg),
			 DECLARG(krb5_principal, principal),
			 DECLARG(krb5_kvno, vno),
			 DECLARG(krb5_keyblock **, key))
OLDDECLARG(krb5_pointer, keyprocarg)
OLDDECLARG(krb5_principal, principal)
OLDDECLARG(krb5_kvno, vno)
OLDDECLARG(krb5_keyblock **, key)
/*
	effects: If keyprocarg is not NULL, it is taken to be 
		the name of a keytab.  Otherwise, the default
		keytab will be used.  This routine opens the
		keytab and finds the principal associated with
		principal and vno, returning the resulting key
		in *key or returning an error code if it is not
		found. 
	returns: nothing
	errors: error code if not found
*/
{
    krb5_error_code kerror = KSUCCESS;
    char keytabname[MAX_KEYTAB_NAME_LEN + 1]; /* + 1 for NULL termination */
    krb5_keytab id;
    krb5_keytab_entry entry;
        
    /*
     * Get the name of the file that we should use. 
     */
    if (!keyprocarg) {
	if ((kerror = krb5_kt_default_name((char *)keytabname, 
					   sizeof(keytabname) - 1))!= KSUCCESS)
	    return (kerror);
    } else {
	memset(keytabname, 0, sizeof(keytabname));
	(void) strncpy(keytabname, (char *)keyprocarg, 
		       sizeof(keytabname) - 1);
    }

    if (kerror = krb5_kt_resolve((char *)keytabname, &id))
	return (kerror);

    kerror = krb5_kt_get_entry(id, principal, vno, &entry);
    krb5_kt_close(id);

    if (kerror)
	return(kerror);

    /* 
     * This routine takes a krb5_keyblock **.   Should it?  I assume this
     * means that it is supposed allocate the key and return it...
     * XXX
     */

    if (!(*key = (krb5_keyblock *)malloc(sizeof(krb5_keyblock))))
	return (ENOMEM);	/* XXX */

    krb5_copy_keyblock(&entry.key, *key);

    krb5_kt_free_entry(&entry);

    return (KSUCCESS);
}
