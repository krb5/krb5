// stdcc_util.c
// utility functions used in implementing the ccache api for krb5
// not publicly exported
// Frank Dabek, July 1998

#include <stdlib.h>
#include <string.h>
#include "stdcc_util.h"
#include "krb5.h"
#include "kv5m_err.h"

#define fieldSize 255

/* on the Mac, we need the calls which allocate memory for the Credentials Cache to use
   Ptr's in the system help, so that they stay global and so that bad things don't happen
   when we call DisposePtr() on them.  However, on other systems, malloc is probably the
   right thing to use.
   So for any place where we allocate memory for the Credentials Cache, use sys_alloc() and
   define it accordingly.
*/

#if defined(macintosh)
#define sys_alloc(size) NewSafePtrSys(size)
#else
#define sys_alloc(size) malloc(size)
#endif

#if defined(macintosh)
//stolen from CCacheUtils.c
// -- NewSafePtrSys -----------------
//  - analagous to NewSafePtr but memory is allocated in the system heap
Ptr NewSafePtrSys(long size) {

	Ptr retPtr;
	
	retPtr = NewPtrSys(size);
	
	if (retPtr != NULL)
		HoldMemory(retPtr, size);
	
	return retPtr;
}
#endif

// CopyCCDataArrayToK5
// - copy and translate the null terminated arrays of data records
//	 used in k5 tickets
int copyCCDataArrayToK5(cc_creds *cc, krb5_creds *kc, char whichArray) {

	cc_data *ccAdr, **cbase;
	krb5_address *kAdr, **kbase, **constKBase;
	int numRecords = 0;
		
	
	if (whichArray == kAddressArray) {
		//check pointer
		if (cc->addresses == NULL) {
			kc->addresses = NULL;
			return 0; }
	} else if (whichArray == kAuthDataArray) {
		//check pointer
		if (cc->authdata == NULL) {
			kc->authdata = NULL;
			return 0; }
	} else return -1;
	

	cbase = (whichArray == kAddressArray) ? cc->addresses : cc->authdata;
	//calc number of records
	while (*cbase++ != NULL) numRecords++;
	//allocate new array
	constKBase = kbase = (krb5_address **)malloc((numRecords+1)*sizeof(char *));
	//reset base
	cbase = (whichArray == kAddressArray) ? cc->addresses : cc->authdata;
		
		
	//copy records
	while (*cbase != NULL) {
		*kbase = (krb5_address *)malloc(sizeof(krb5_address));
		kAdr = *kbase;
		ccAdr = *cbase;
		kAdr->magic = (whichArray == kAddressArray) ? KV5M_ADDRESS : KV5M_AUTHDATA;
		kAdr->addrtype = ccAdr->type;
		kAdr->length = ccAdr->length;
		kAdr->contents = (krb5_octet *)malloc(kAdr->length);
		memcpy(kAdr->contents, ccAdr->data, kAdr->length);
		//next element please
		kbase++; cbase++;
	}
	
	//write terminator
	*kbase = NULL;
	if (whichArray == kAddressArray) kc->addresses = constKBase;
	else kc->authdata = (krb5_authdata **)constKBase;

	return 0;
}

// copyK5DataArrayToCC
// - analagous to above, but in the other direction
int copyK5DataArrayToCC(krb5_creds *kc, cc_creds *cc, char whichArray) {

	cc_data *ccAdr, **cbase, **constCBase;
	krb5_address *kAdr, **kbase;
	int numRecords = 0;
		
	
	if (whichArray == kAddressArray) {
		//check pointer
		if (kc->addresses == NULL) {
			cc->addresses = NULL;
			return 0; }
	} else if (whichArray == kAuthDataArray) {
		//check pointer
		if (kc->authdata == NULL) {
			cc->authdata = NULL;
			return 0; }
	} else return -1;
	

	kbase = (whichArray == kAddressArray) ? kc->addresses : (krb5_address **)kc->authdata;
	//calc number of records
	while (*kbase++ != NULL) numRecords++;
	//allocate new array
	constCBase = cbase = (cc_data **)sys_alloc((numRecords+1)*sizeof(char *));
	//reset base
	kbase = (whichArray == kAddressArray) ? kc->addresses : (krb5_address **)kc->authdata;
		
		
	//copy records
	while (*kbase != NULL) {
		*cbase = (cc_data *)sys_alloc(sizeof(krb5_address));
		kAdr = *kbase;
		ccAdr = *cbase;
		ccAdr->type = kAdr->addrtype;
		ccAdr->length = kAdr->length;
		ccAdr->data = (unsigned char *)sys_alloc(ccAdr->length);
		memcpy(ccAdr->data, kAdr->contents, kAdr->length);
		//next element please
		kbase++; cbase++;
	}
	
	//write terminator
	*cbase = NULL;
	if (whichArray == kAddressArray) cc->addresses = (cc_data **)constCBase;
	else cc->authdata = (cc_data **)constCBase;

	return 0;
}


// dupcctok5
// - allocate an empty k5 style ticket and copy info from the cc_creds ticket
void dupCCtoK5(krb5_context context, cc_creds *src, krb5_creds *dest) {

	int err;
	
	//allocate and copy
	//copy all of those damn fields back
	err = krb5_parse_name(context, src->client, &(dest->client));
	err = krb5_parse_name(context, src->server, &(dest->server));
	if (err) return; //parsename fails w/o krb5.ini for example
	
	//copy keyblock
	dest->keyblock.enctype = src->keyblock.type;
	dest->keyblock.length = src->keyblock.length;
	dest->keyblock.contents = (krb5_octet *)malloc(dest->keyblock.length);
	memcpy(dest->keyblock.contents, src->keyblock.data, dest->keyblock.length);
	
	//copy times
	dest->times.authtime = src->authtime;
	dest->times.starttime = src->starttime;
	dest->times.endtime = src->endtime;
	dest->times.renew_till = src->renew_till;
	dest->is_skey = src->is_skey;
	dest->ticket_flags = src->ticket_flags;
	
	//more branching fields
	copyCCDataArrayToK5(src, dest, kAddressArray);
	dest->ticket.length = src->ticket.length;
	dest->ticket.data = (char *)malloc(src->ticket.length);
	memcpy(dest->ticket.data, src->ticket.data, src->ticket.length);
	dest->second_ticket.length = src->second_ticket.length;
	(dest->second_ticket).data = ( char *)malloc(src->second_ticket.length);
	memcpy(dest->second_ticket.data, src->second_ticket.data, src->second_ticket.length);
	
	//zero out magic number
	dest->magic = 0;
	//later
	//copyCCDataArrayToK5(src, dest, kAuthDataArray);
	//krb5 docs say that authdata can be nulled out if we 
	//only want default behavior
	dest->authdata = NULL;
	
	return;
}

// dupK52CC
// - analagous to above but in the reverse direction
void dupK52cc(krb5_context context, krb5_creds *creds, cred_union **cu) {

		cc_creds *c;
		int err;
	#ifdef macintosh
		char *tempname = NULL;
	#endif
	  
		if (cu == NULL) return;
		
		//allocate the cred_union
		*cu = (cred_union *)sys_alloc(sizeof(cred_union));
		if ((*cu) == NULL) return;
		
		(*cu)->cred_type = CC_CRED_V5;
		
		//allocate creds structure (and install)
		c  = (cc_creds *)sys_alloc(sizeof(cc_creds));
		if (c == NULL) return;
		(*cu)->cred.pV5Cred = c;
		
		//convert krb5 principals to flat principals
	#ifdef macintosh
		//and make sure the memory for c->client and c->server is on the system heap with NewPtr
		//for the Mac (krb5_unparse_name puts it in appl heap with malloc)
		err = krb5_unparse_name(context, creds->client, &tempname);
		c->client = sys_alloc(strlen(tempname));
		if (c->client != NULL)
			strcpy(c->client,tempname);
		free(tempname);
		tempname = NULL;
		
		err = krb5_unparse_name(context, creds->server, &tempname);
		c->server = sys_alloc(strlen(tempname));
		if (c->server != NULL)
			strcpy(c->server,tempname);
		free(tempname);
	#else
		err = krb5_unparse_name(context, creds->client, &(c->client));
		err = krb5_unparse_name(context, creds->server, &(c->server));
	#endif
		if (err) return;
		
		//copy more fields
		c->keyblock.type = creds->keyblock.enctype;
		c->keyblock.length = creds->keyblock.length;
		
		if (creds->keyblock.contents != NULL) {
			c->keyblock.data = (unsigned char *)sys_alloc(creds->keyblock.length);
			memcpy(c->keyblock.data, creds->keyblock.contents, creds->keyblock.length);
		} else {
			c->keyblock.data = NULL;
		}
		
		c->authtime = creds->times.authtime;
		c->starttime = creds->times.starttime;
		c->endtime = creds->times.endtime;
		c->renew_till = creds->times.renew_till;
		c->is_skey = creds->is_skey;
		c->ticket_flags = creds->ticket_flags;

		copyK5DataArrayToCC(creds, c, kAddressArray);	

		c->ticket.length = creds->ticket.length;
		if (creds->ticket.data != NULL) {
			c->ticket.data = (unsigned char *)sys_alloc(creds->ticket.length);
			memcpy(c->ticket.data, creds->ticket.data, creds->ticket.length);
		} else {
			c->ticket.data = NULL;
		}
		
		c->second_ticket.length = creds->second_ticket.length;
		if (creds->second_ticket.data != NULL) {
			c->second_ticket.data = (unsigned char *)sys_alloc(creds->second_ticket.length);
			memcpy(c->second_ticket.data, creds->second_ticket.data, creds->second_ticket.length);
		} else {
			c->second_ticket.data = NULL;
		}
		
		c->authdata = NULL;
	
	return;
}

// bitTst
// - utility function for below function
int bitTst(int var, int mask) {

	return var & mask;
} 

// stdccCredsMatch
// - check to see if the creds match based on the whichFields variable
// NOTE: if whichfields is zero we are now comparing 'standard fields.'
//		 This is the bug that was killing fetch for a week. The behaviour
//		 is what krb5 expects, however.
int stdccCredsMatch(krb5_context context, krb5_creds *base, krb5_creds *match, int whichfields) {

	krb5_ticket_times b, m;
	krb5_authdata **bp, **mp;
	krb5_boolean retval;
	

	//always check the standard fields
	if ((krb5_principal_compare(context, base->client, match->client) &&
	    krb5_principal_compare(context, base->server, match->server)) == FALSE)
	    return FALSE;

	if (bitTst(whichfields, KRB5_TC_MATCH_TIMES)) {
		//test for matching times
		//according to the file cache implementation we do:
		if (match->times.renew_till) {
		if (match->times.renew_till > base->times.renew_till)
		    return FALSE;		/* this one expires too late */
	    }
	    if (match->times.endtime) {
		if (match->times.endtime > base->times.endtime)
		    return FALSE;		/* this one expires too late */
	    }
	} //continue search
	
	if (bitTst(whichfields, KRB5_TC_MATCH_IS_SKEY)) 
		if (base->is_skey != match->is_skey) return FALSE;
	
	if (bitTst(whichfields, KRB5_TC_MATCH_FLAGS)) 
		if (base->ticket_flags != match->ticket_flags) return FALSE;
		
	if (bitTst(whichfields, KRB5_TC_MATCH_TIMES_EXACT)) {
		b = base->times; m = match->times;
		if ((b.authtime != m.authtime) ||
			(b.starttime != m.starttime) ||
			(b.endtime != m.endtime) ||
			(b.renew_till != m.renew_till)) return FALSE;
		}
		
	if (bitTst(whichfields, KRB5_TC_MATCH_AUTHDATA)) {
		bp = base->authdata;
		mp = match->authdata;
		if ((bp != NULL) && (mp != NULL)) {
		while ( (bp) && (*bp != NULL) ){
			if (( (*bp)->ad_type != (*mp)->ad_type) ||
				( (*bp)->length != (*mp)->length) ||
				( memcmp( (*bp)->contents, (*mp)->contents, (*bp)->length) != 0)) return FALSE;
			mp++; bp++;
		}
	  }
	}
	
	if (bitTst(whichfields, KRB5_TC_MATCH_SRV_NAMEONLY)) {
		//taken from cc_retrv.c
		retval = krb5_principal_compare(context, base->client,match->client);
		if (!retval) return FALSE;
	  
	  }
	 
	if (bitTst(whichfields, KRB5_TC_MATCH_2ND_TKT)) 
		if ( (base->second_ticket.length != match->second_ticket.length) ||
			(memcmp(base->second_ticket.data, match->second_ticket.data, base->second_ticket.length) != 0))
			return FALSE;
			
	if (bitTst(whichfields,	KRB5_TC_MATCH_KTYPE))
		if (base->keyblock.enctype != match->keyblock.enctype) return FALSE;
			
	//if we fall through to here, they must match
	return TRUE;
}
