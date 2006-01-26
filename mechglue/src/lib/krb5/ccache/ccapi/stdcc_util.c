/*
 * stdcc_util.c
 * utility functions used in implementing the ccache api for krb5
 * not publicly exported
 * Frank Dabek, July 1998
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#if defined(_WIN32)
#include <malloc.h>
#endif

#include "stdcc_util.h"
#include "krb5.h"
#include "kv5m_err.h"

#define fieldSize 255

/*
 * CopyCCDataArrayToK5
 * - copy and translate the null terminated arrays of data records
 * 	 used in k5 tickets
 */
int copyCCDataArrayToK5(cc_creds *ccCreds, krb5_creds *v5Creds, char whichArray) {

    if (whichArray == kAddressArray) {
	if (ccCreds->addresses == NULL) {
	    v5Creds->addresses = NULL;
	} else {

	    krb5_address 	**addrPtr, *addr;
	    cc_data			**dataPtr, *data;
	    unsigned int		numRecords = 0;

	    /* Allocate the array of pointers: */
	    for (dataPtr = ccCreds->addresses; *dataPtr != NULL; numRecords++, dataPtr++) {}

	    v5Creds->addresses = (krb5_address **) malloc (sizeof(krb5_address *) * (numRecords + 1));
	    if (v5Creds->addresses == NULL)
		return ENOMEM;

	    /* Fill in the array, allocating the address structures: */
	    for (dataPtr = ccCreds->addresses, addrPtr = v5Creds->addresses; *dataPtr != NULL; addrPtr++, dataPtr++) {

		*addrPtr = (krb5_address *) malloc (sizeof(krb5_address));
		if (*addrPtr == NULL)
		    return ENOMEM;
		data = *dataPtr;
		addr = *addrPtr;

		addr->addrtype = data->type;
		addr->magic    = KV5M_ADDRESS;
		addr->length   = data->length;
		addr->contents = (krb5_octet *) malloc (sizeof(krb5_octet) * addr->length);
		if (addr->contents == NULL)
		    return ENOMEM;
		memmove(addr->contents, data->data, addr->length); /* copy contents */
	    }

	    /* Write terminator: */
	    *addrPtr = NULL;
	}
    }

    if (whichArray == kAuthDataArray) {
	if (ccCreds->authdata == NULL) {
	    v5Creds->authdata = NULL;
	} else {
	    krb5_authdata 	**authPtr, *auth;
	    cc_data			**dataPtr, *data;
	    unsigned int		numRecords = 0;

	    /* Allocate the array of pointers: */
	    for (dataPtr = ccCreds->authdata; *dataPtr != NULL; numRecords++, dataPtr++) {}

	    v5Creds->authdata = (krb5_authdata **) malloc (sizeof(krb5_authdata *) * (numRecords + 1));
	    if (v5Creds->authdata == NULL)
		return ENOMEM;

	    /* Fill in the array, allocating the address structures: */
	    for (dataPtr = ccCreds->authdata, authPtr = v5Creds->authdata; *dataPtr != NULL; authPtr++, dataPtr++) {

		*authPtr = (krb5_authdata *) malloc (sizeof(krb5_authdata));
		if (*authPtr == NULL)
		    return ENOMEM;
		data = *dataPtr;
		auth = *authPtr;

		auth->ad_type  = data->type;
		auth->magic    = KV5M_AUTHDATA;
		auth->length   = data->length;
		auth->contents = (krb5_octet *) malloc (sizeof(krb5_octet) * auth->length);
		if (auth->contents == NULL)
		    return ENOMEM;
		memmove(auth->contents, data->data, auth->length); /* copy contents */
	    }

	    /* Write terminator: */
	    *authPtr = NULL;
	}
    }

    return 0;
}

/*
 * copyK5DataArrayToCC
 * - analagous to above, but in the other direction
 */
int copyK5DataArrayToCC(krb5_creds *v5Creds, cc_creds *ccCreds, char whichArray)
{
    if (whichArray == kAddressArray) {
	if (v5Creds->addresses == NULL) {
	    ccCreds->addresses = NULL;
	} else {

	    krb5_address 	**addrPtr, *addr;
	    cc_data			**dataPtr, *data;
	    unsigned int			numRecords = 0;

	    /* Allocate the array of pointers: */
	    for (addrPtr = v5Creds->addresses; *addrPtr != NULL; numRecords++, addrPtr++) {}

	    ccCreds->addresses = (cc_data **) malloc (sizeof(cc_data *) * (numRecords + 1));
	    if (ccCreds->addresses == NULL)
		return ENOMEM;

	    /* Fill in the array, allocating the address structures: */
	    for (dataPtr = ccCreds->addresses, addrPtr = v5Creds->addresses; *addrPtr != NULL; addrPtr++, dataPtr++) {

		*dataPtr = (cc_data *) malloc (sizeof(cc_data));
		if (*dataPtr == NULL)
		    return ENOMEM;
		data = *dataPtr;
		addr = *addrPtr;

		data->type   = addr->addrtype;
		data->length = addr->length;
		data->data   = malloc (sizeof(char) * data->length);
		if (data->data == NULL)
		    return ENOMEM;
		memmove(data->data, addr->contents, data->length); /* copy contents */
	    }

	    /* Write terminator: */
	    *dataPtr = NULL;
	}
    }

    if (whichArray == kAuthDataArray) {
	if (v5Creds->authdata == NULL) {
	    ccCreds->authdata = NULL;
	} else {
	    krb5_authdata 	**authPtr, *auth;
	    cc_data			**dataPtr, *data;
	    unsigned int			numRecords = 0;

	    /* Allocate the array of pointers: */
	    for (authPtr = v5Creds->authdata; *authPtr != NULL; numRecords++, authPtr++) {}

	    ccCreds->authdata = (cc_data **) malloc (sizeof(cc_data *) * (numRecords + 1));
	    if (ccCreds->authdata == NULL)
		return ENOMEM;

	    /* Fill in the array, allocating the address structures: */
	    for (dataPtr = ccCreds->authdata, authPtr = v5Creds->authdata; *authPtr != NULL; authPtr++, dataPtr++) {

		*dataPtr = (cc_data *) malloc (sizeof(cc_data));
		if (*dataPtr == NULL)
		    return ENOMEM;
		data = *dataPtr;
		auth = *authPtr;

		data->type   = auth->ad_type;
		data->length = auth->length;
		data->data   = malloc (sizeof(char) * data->length);
		if (data->data == NULL)
		    return ENOMEM;
		memmove(data->data, auth->contents, data->length); /* copy contents */
	    }

	    /* Write terminator: */
	    *dataPtr = NULL;
	}
    }

    return 0;
}

/*
 * dupcctok5
 * - allocate an empty k5 style ticket and copy info from the cc_creds ticket
 */

void dupCCtoK5(krb5_context context, cc_creds *src, krb5_creds *dest)
{
    krb5_int32 offset_seconds = 0, offset_microseconds = 0;
    int err;

    /*
     * allocate and copy
     * copy all of those damn fields back
     */
    err = krb5_parse_name(context, src->client, &(dest->client));
    err = krb5_parse_name(context, src->server, &(dest->server));
    if (err) return; /* parsename fails w/o krb5.ini for example */

    /* copy keyblock */
    dest->keyblock.enctype = src->keyblock.type;
    dest->keyblock.length = src->keyblock.length;
    dest->keyblock.contents = (krb5_octet *)malloc(dest->keyblock.length);
    memcpy(dest->keyblock.contents, src->keyblock.data, dest->keyblock.length);

    /* copy times */
#if TARGET_OS_MAC
    err = krb5_get_time_offsets(context, &offset_seconds, &offset_microseconds);
    if (err) return;
#endif
    dest->times.authtime   = src->authtime     + offset_seconds;
    dest->times.starttime  = src->starttime    + offset_seconds;
    dest->times.endtime    = src->endtime      + offset_seconds;
    dest->times.renew_till = src->renew_till   + offset_seconds;
    dest->is_skey          = src->is_skey;
    dest->ticket_flags     = src->ticket_flags;

    /* more branching fields */
    err = copyCCDataArrayToK5(src, dest, kAddressArray);
    if (err) return;

    dest->ticket.length = src->ticket.length;
    dest->ticket.data = (char *)malloc(src->ticket.length);
    memcpy(dest->ticket.data, src->ticket.data, src->ticket.length);
    dest->second_ticket.length = src->second_ticket.length;
    (dest->second_ticket).data = ( char *)malloc(src->second_ticket.length);
    memcpy(dest->second_ticket.data, src->second_ticket.data, src->second_ticket.length);

    /* zero out magic number */
    dest->magic = 0;

    /* authdata */
    err = copyCCDataArrayToK5(src, dest, kAuthDataArray);
    if (err) return;

    return;
}

/*
 * dupK5toCC
 * - analagous to above but in the reverse direction
 */
void dupK5toCC(krb5_context context, krb5_creds *creds, cred_union **cu)
{
    cc_creds *c;
    int err;
    krb5_int32 offset_seconds = 0, offset_microseconds = 0;

    if (cu == NULL) return;

    /* allocate the cred_union */
    *cu = (cred_union *)malloc(sizeof(cred_union));
    if ((*cu) == NULL)
	return;

    (*cu)->cred_type = CC_CRED_V5;

    /* allocate creds structure (and install) */
    c  = (cc_creds *)malloc(sizeof(cc_creds));
    if (c == NULL) return;
    (*cu)->cred.pV5Cred = c;

    /* convert krb5 principals to flat principals */
    err = krb5_unparse_name(context, creds->client, &(c->client));
    err = krb5_unparse_name(context, creds->server, &(c->server));
    if (err) return;

    /* copy more fields */
    c->keyblock.type = creds->keyblock.enctype;
    c->keyblock.length = creds->keyblock.length;

    if (creds->keyblock.contents != NULL) {
	c->keyblock.data = (unsigned char *)malloc(creds->keyblock.length);
	memcpy(c->keyblock.data, creds->keyblock.contents, creds->keyblock.length);
    } else {
	c->keyblock.data = NULL;
    }

#if TARGET_OS_MAC
    err = krb5_get_time_offsets(context, &offset_seconds, &offset_microseconds);
    if (err) return;
#endif
    c->authtime     = creds->times.authtime   - offset_seconds;
    c->starttime    = creds->times.starttime  - offset_seconds;
    c->endtime      = creds->times.endtime    - offset_seconds;
    c->renew_till   = creds->times.renew_till - offset_seconds;
    c->is_skey      = creds->is_skey;
    c->ticket_flags = creds->ticket_flags;

    err = copyK5DataArrayToCC(creds, c, kAddressArray);
    if (err) return;

    c->ticket.length = creds->ticket.length;
    if (creds->ticket.data != NULL) {
	c->ticket.data = (unsigned char *)malloc(creds->ticket.length);
	memcpy(c->ticket.data, creds->ticket.data, creds->ticket.length);
    } else {
	c->ticket.data = NULL;
    }

    c->second_ticket.length = creds->second_ticket.length;
    if (creds->second_ticket.data != NULL) {
	c->second_ticket.data = (unsigned char *)malloc(creds->second_ticket.length);
	memcpy(c->second_ticket.data, creds->second_ticket.data, creds->second_ticket.length);
    } else {
	c->second_ticket.data = NULL;
    }

    err = copyK5DataArrayToCC(creds, c, kAuthDataArray);
    if (err) return;

    return;
}

/*
 * Utility functions...
 */
static krb5_boolean
times_match(t1, t2)
    register const krb5_ticket_times *t1;
register const krb5_ticket_times *t2;
{
    if (t1->renew_till) {
	if (t1->renew_till > t2->renew_till)
	    return FALSE;		/* this one expires too late */
    }
    if (t1->endtime) {
	if (t1->endtime > t2->endtime)
	    return FALSE;		/* this one expires too late */
    }
    /* only care about expiration on a times_match */
    return TRUE;
}

static krb5_boolean
times_match_exact (t1, t2)
    register const krb5_ticket_times *t1, *t2;
{
    return (t1->authtime == t2->authtime
	    && t1->starttime == t2->starttime
	    && t1->endtime == t2->endtime
	    && t1->renew_till == t2->renew_till);
}

static krb5_boolean
standard_fields_match(context, mcreds, creds)
    krb5_context context;
register const krb5_creds *mcreds, *creds;
{
    return (krb5_principal_compare(context, mcreds->client,creds->client) &&
	    krb5_principal_compare(context, mcreds->server,creds->server));
}

/* only match the server name portion, not the server realm portion */

static krb5_boolean
srvname_match(context, mcreds, creds)
    krb5_context context;
register const krb5_creds *mcreds, *creds;
{
    krb5_boolean retval;
    krb5_principal_data p1, p2;

    retval = krb5_principal_compare(context, mcreds->client,creds->client);
    if (retval != TRUE)
	return retval;
    /*
     * Hack to ignore the server realm for the purposes of the compare.
     */
    p1 = *mcreds->server;
    p2 = *creds->server;
    p1.realm = p2.realm;
    return krb5_principal_compare(context, &p1, &p2);
}


static krb5_boolean
authdata_match(mdata, data)
    krb5_authdata *const *mdata, *const *data;
{
    const krb5_authdata *mdatap, *datap;

    if (mdata == data)
	return TRUE;

    if (mdata == NULL)
	return *data == NULL;

    if (data == NULL)
	return *mdata == NULL;

    while ((mdatap = *mdata)
	   && (datap = *data)
	   && mdatap->ad_type == datap->ad_type
	   && mdatap->length == datap->length
	   && !memcmp ((char *) mdatap->contents, (char *) datap->contents,
		       datap->length)) {
	mdata++;
	data++;
    }

    return !*mdata && !*data;
}

static krb5_boolean
data_match(data1, data2)
    register const krb5_data *data1, *data2;
{
    if (!data1) {
	if (!data2)
	    return TRUE;
	else
	    return FALSE;
    }
    if (!data2) return FALSE;

    if (data1->length != data2->length)
	return FALSE;
    else
	return memcmp(data1->data, data2->data, data1->length) ? FALSE : TRUE;
}

#define MATCH_SET(bits) (whichfields & bits)
#define flags_match(a,b) (((a) & (b)) == (a))

/*  stdccCredsMatch
 *  - check to see if the creds match based on the whichFields variable
 *  NOTE: if whichfields is zero we are now comparing 'standard fields.'
 * 		 This is the bug that was killing fetch for a
 * 		 week. The behaviour is what krb5 expects, however.
 */
int stdccCredsMatch(krb5_context context, krb5_creds *base,
		    krb5_creds *match, int whichfields)
{
    if (((MATCH_SET(KRB5_TC_MATCH_SRV_NAMEONLY) &&
	  srvname_match(context, match, base)) ||
	 standard_fields_match(context, match, base))
	&&
	(! MATCH_SET(KRB5_TC_MATCH_IS_SKEY) ||
	 match->is_skey == base->is_skey)
	&&
	(! MATCH_SET(KRB5_TC_MATCH_FLAGS_EXACT) ||
	 match->ticket_flags == base->ticket_flags)
	&&
	(! MATCH_SET(KRB5_TC_MATCH_FLAGS) ||
	 flags_match(match->ticket_flags, base->ticket_flags))
	&&
	(! MATCH_SET(KRB5_TC_MATCH_TIMES_EXACT) ||
	 times_match_exact(&match->times, &base->times))
	&&
	(! MATCH_SET(KRB5_TC_MATCH_TIMES) ||
	 times_match(&match->times, &base->times))
	&&
	(! MATCH_SET(KRB5_TC_MATCH_AUTHDATA) ||
	 authdata_match (match->authdata, base->authdata))
	&&
	(! MATCH_SET(KRB5_TC_MATCH_2ND_TKT) ||
	 data_match (&match->second_ticket, &base->second_ticket))
	&&
	((! MATCH_SET(KRB5_TC_MATCH_KTYPE))||
	 (match->keyblock.enctype == base->keyblock.enctype))
	)
	return TRUE;
    return FALSE;
}

/* ----- free_cc_cred_union, etc -------------- */
/*
  Since the Kerberos5 library allocates a credentials cache structure
  (in dupK5toCC() above) with its own memory allocation routines - which
  may be different than how the CCache allocates memory - the Kerb5 library
  must have its own version of cc_free_creds() to deallocate it.  These
  functions do that.  The top-level function to substitue for cc_free_creds()
  is krb5_free_cc_cred_union().

  If the CCache library wants to use a cred_union structure created by
  the Kerb5 library, it should make a deep copy of it to "translate" to its
  own memory allocation space.
*/
static void deep_free_cc_data (cc_data data)
{
    if (data.data != NULL)
	free (data.data);
}

static void deep_free_cc_data_array (cc_data** data) {

    unsigned int	index;

    if (data == NULL)
	return;

    for (index = 0; data [index] != NULL; index++) {
	deep_free_cc_data (*(data [index]));
	free (data [index]);
    }

    free (data);
}

static void deep_free_cc_v5_creds (cc_creds* creds)
{
    if (creds == NULL)
	return;

    if (creds -> client != NULL)
	free (creds -> client);
    if (creds -> server != NULL)
	free (creds -> server);

    deep_free_cc_data (creds -> keyblock);
    deep_free_cc_data (creds -> ticket);
    deep_free_cc_data (creds -> second_ticket);

    deep_free_cc_data_array (creds -> addresses);
    deep_free_cc_data_array (creds -> authdata);

    free(creds);
}

static void deep_free_cc_creds (cred_union creds)
{
    if (creds.cred_type == CC_CRED_V4) {
	/* we shouldn't get this, of course */
	free (creds.cred.pV4Cred);
    } else if (creds.cred_type == CC_CRED_V5) {
	deep_free_cc_v5_creds (creds.cred.pV5Cred);
    }
}

/* top-level exported function */
cc_int32 krb5_free_cc_cred_union (cred_union** creds)
{
    if (creds == NULL)
	return CC_BAD_PARM;

    if (*creds != NULL) {
	deep_free_cc_creds (**creds);
	free (*creds);
	*creds = NULL;
    }

    return CC_NOERROR;
}
