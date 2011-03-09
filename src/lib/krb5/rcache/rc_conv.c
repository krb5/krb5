/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/rcache/rc_conv.c */
/*
 * This file of the Kerberos V5 software is derived from public-domain code
 * contributed by Daniel J. Bernstein, <brnstnd@acf10.nyu.edu>.
 *
 */

/*
 * An implementation for the default replay cache type.
 */

#include "rc_base.h"

/*
  Local stuff:
  krb5_auth_to_replay(context, krb5_tkt_authent *auth,krb5_donot_replay *rep)
  given auth, take important information and make rep; return -1 if failed
*/

krb5_error_code
krb5_auth_to_rep(krb5_context context, krb5_tkt_authent *auth, krb5_donot_replay *rep)
{
    krb5_error_code retval;
    rep->cusec = auth->authenticator->cusec;
    rep->ctime = auth->authenticator->ctime;
    if ((retval = krb5_unparse_name(context, auth->ticket->server, &rep->server)))
        return retval; /* shouldn't happen */
    if ((retval = krb5_unparse_name(context, auth->authenticator->client,
                                    &rep->client))) {
        free(rep->server);
        return retval; /* shouldn't happen. */
    }
    return 0;
}

/*
 * Generate a printable hash value for a message for use in a replay
 * record.  It is not necessary for this hash function to be
 * collision-proof (the only thing you can do with a second preimage
 * is produce a false replay error) but it is necessary for the
 * function to be consistent across implementations.  We do an unkeyed
 * MD5 hash of the message and convert it into uppercase hex
 * representation.
 */
krb5_error_code
krb5_rc_hash_message(krb5_context context, const krb5_data *message,
                     char **out)
{
    krb5_error_code retval;
    krb5_checksum cksum;
    char *hash, *ptr;
    unsigned int i;

    *out = NULL;

    /* Calculate the binary checksum. */
    retval = krb5_c_make_checksum(context, CKSUMTYPE_RSA_MD5, 0, 0,
                                  message, &cksum);
    if (retval)
        return retval;

    /* Convert the checksum into printable form. */
    hash = malloc(cksum.length * 2 + 1);
    if (!hash) {
        krb5_free_checksum_contents(context, &cksum);
        return KRB5_RC_MALLOC;
    }

    for (i = 0, ptr = hash; i < cksum.length; i++, ptr += 2)
        snprintf(ptr, 3, "%02X", cksum.contents[i]);
    *ptr = '\0';
    *out = hash;
    krb5_free_checksum_contents(context, &cksum);
    return 0;
}
