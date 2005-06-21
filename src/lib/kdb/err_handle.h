/**********************************************************************
*
*	C Header:		err_handle.h
*	Instance:		idc_sec_1
*	Description:	
*	%created_by:	spradeep %
*	%date_created:	Thu Apr  7 14:05:33 2005 %
*
**********************************************************************/
#ifndef _idc_sec_1_err_handle_h_H
#define _idc_sec_1_err_handle_h_H
#include <k5-int.h>

/* Everything else goes here */

#define KRB5_MAX_ERR_STR 1024
typedef enum krb5_err_subsystem {
    krb5_err_unknown = 0, /* no error or unknown system. Has to be probed */
    krb5_err_system,	/* error in system call */
    krb5_err_krblib,	/* error in kerberos library call, should lookup in the error table */
    krb5_err_have_str,	/* error message is available in the string */
    krb5_err_db		/* error is a database error, should be handled by calling DB */
} krb5_err_subsystem;

typedef krb5_error_code(*krb5_set_err_func_t) (krb5_context,
					       krb5_err_subsystem, long,
					       char *);

krb5_error_code krb5_set_err(krb5_context kcontext,
			     krb5_err_subsystem subsystem, long err_code,
			     char *str);

const char *KRB5_CALLCONV krb5_get_err_string(long err_code);

void    krb5_clr_error(void);

#endif
