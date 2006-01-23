#ifndef err_handle_h_H
#define err_handle_h_H

#include <com_err.h>

#define KRB5_MAX_ERR_STR 1024

void krb5_kdb_set_err_str (char *str);
void krb5_kdb_get_err_str (char *str, int len);
void krb5_kdb_clear_err_str ();
void krb5_kdb_prepend_err_str (char *str);

#define error_message_w(code,err,size)				\
	{							\
	    krb5_kdb_get_err_str (err, size);			\
	    if(err[0] == '\0')					\
		strncpy (err, error_message(code), size);	\
	}

#endif
