/*
 * dsp_status.c --- display_status
 * 
 * $Source$
 * $Author$
 * $Header$
 * 
 * Copyright 1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America is assumed
 *   to require a specific license from the United States Government.
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
 *
 */

#include <gssapi.h>

#define GSS_CE_MASK 0xFF000000
#define GSS_RE_MASK 0x00FF0000
#define GSS_SS_MASK 0x0000FFFF

#define GSS_CONTEXT_THIS(i) ((i) & 0xFFFF)
#define GSS_CONTEXT_NEXT(i) ((i) >> 16)

struct gss_error_table {
	int	code;
	int	mask;
	char	*string;
};

static struct gss_error_table table[] = {
       { GSS_S_CALL_INACCESSIBLE_READ, GSS_CE_MASK,
	 "GSSAPI Calling Error: Inaccessible read" },
       { GSS_S_CALL_INACCESSIBLE_WRITE, GSS_CE_MASK,
	 "GSSAPI Calling Error: Inaccessible write" },
       { GSS_S_CALL_BAD_STRUCTURE, GSS_CE_MASK,
	 "GSSAPI Calling Error: Bad Structure" },
       { GSS_S_BAD_MECH, GSS_RE_MASK,
	 "GSSAPI Routine Error: Bad Mechanism" },
       { GSS_S_BAD_NAME, GSS_RE_MASK,
	 "GSSAPI Routine Error: Bad Name" },
       { GSS_S_BAD_NAMETYPE, GSS_RE_MASK,
	 "GSSAPI Routine Error: Bad Nametype" },
       { GSS_S_BAD_BINDINGS, GSS_RE_MASK,
	 "GSSAPI Routine Error: Bad Bindings" },
       { GSS_S_BAD_STATUS, GSS_RE_MASK,
	 "GSSAPI Routine Error: Bad Status" },
       { GSS_S_BAD_SIG, GSS_RE_MASK,
	 "GSSAPI Routine Error: Invalid Signature" },
       { GSS_S_NO_CRED, GSS_RE_MASK,
	 "GSSAPI Routine Error: Missing Credentials" },
       { GSS_S_NO_CONTEXT, GSS_RE_MASK,
	 "GSSAPI Routine Error: Missing Context" },
       { GSS_S_DEFECTIVE_TOKEN, GSS_RE_MASK,
	 "GSSAPI Routine Error: Defective Token" },
       { GSS_S_DEFECTIVE_CREDENTIAL, GSS_RE_MASK,
	 "GSSAPI Routine Error: Defective Credential" },
       { GSS_S_CREDENTIALS_EXPIRED, GSS_RE_MASK,
	 "GSSAPI Routine Error: Credentials Expired" },
       { GSS_S_CONTEXT_EXPIRED, GSS_RE_MASK,
	 "GSSAPI Routine Error: Context expired" },
       { GSS_S_FAILURE, GSS_RE_MASK,
	 "GSSAPI Routine Error: Mechanism-specific failure" },
};
static int nentries = sizeof (struct gss_error_table) / sizeof (*table);

OM_uint32 gss_display_status(minor_status, status_value, status_type,
			     mech_type, message_context, status_string)
	OM_uint32	*minor_status;
	int		status_value;
	int		status_type;
	gss_OID		mech_type;
	int		*message_context;
	gss_buffer_t    status_string;
{
	const char	*str;
	int	next;
	int	retval;
	
	*minor_status = 0;
	
	if (status_type == GSS_C_MECH_CODE) {
		/*
		 * We only handle Kerberos V5...
		 */
		if ((mech_type != GSS_C_NULL_OID) &&
		    !gss_compare_OID(mech_type, &gss_OID_krb5)) {
			return(GSS_S_BAD_MECH);
		}
		str = error_message(status_value);
		retval = GSS_S_COMPLETE;
		goto return_message_found;
	} else {
		next = *message_context;

		if (next < 0 || next >= nentries) {
			return(GSS_S_FAILURE);
		}
		if (next == 0) {
			while (next < nentries) {
				if ((status_value & table[next].mask) ==
				    table[next].code)
					break;
				next++;
			}
			if (next >= nentries)
				return(GSS_S_BAD_STATUS);
		}
		str = table[next].string;
		next++;
		while (next < nentries) {
			if ((status_value & table[next].mask) ==
			    table[next].code)
				break;
			next++;
		}
		if (next >= nentries)
			retval = GSS_S_COMPLETE;
		else
			retval = GSS_S_CONTINUE_NEEDED;
		*message_context = next;
	}

return_message_found:
	status_string->length = strlen(str);
	if (!(status_string->value = malloc(status_string->length))) {
		*minor_status = ENOMEM;
		return(GSS_S_FAILURE);
	}
	strcpy(status_string->value, str);
	return(GSS_S_COMPLETE);
}

