#ident  "@(#)get_mech_type.c 1.4     95/06/08 SMI"
/*
 *  glue routine for get_mech_type
 *
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include "mechglueP.h"

OM_uint32 get_mech_type(OID, token)

gss_OID *	OID;
gss_buffer_t	token;

{
    unsigned char * buffer_ptr;
    
    /*
     * This routine reads the prefix of "token" in order to determine
     * its mechanism type. It assumes the encoding suggested in
     * Appendix B of RFC 1508. This format starts out as follows :
     *
     * tag for APPLICATION 0, Sequence[constructed, definite length]
     * length of remainder of token
     * tag of OBJECT IDENTIFIER
     * length of mechanism OID
     * encoding of mechanism OID
     * <the rest of the token>
     *
     * Numerically, this looks like :
     *
     * 0x60
     * <length> - could be multiple bytes
     * 0x06
     * <length> - assume only one byte, hence OID length < 127
     * <mech OID bytes>
     *
     * The routine returns a pointer to the OID value. The return code is
     * the length of the OID, if successful; otherwise it is 0.
     */
    
    if (OID == NULL || *OID == GSS_C_NULL_OID)
	return (0);

    /* if the token is a null pointer, return a zero length OID */
    
    if(token == NULL) {
	(*OID)->length = 0;
	(*OID)->elements = NULL;
	return (0);
    }
    
    /* Skip past the APP/Sequnce byte and the token length */
    
    buffer_ptr = (unsigned char *) token->value;
    
    while(*(++buffer_ptr) & (1<<7))
	continue;
    
    /* increment buffer_ptr to point to the OID and return its length */
    
    (*OID)->length = (OM_uint32) *(buffer_ptr+3);
    (*OID)->elements = (void *) (buffer_ptr+4);
    return ((*OID)->length);
}
