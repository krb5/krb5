/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * This file contains the source code for conditional open/close calls.
 */

#include "scc.h"

krb5_error_code
krb5_scc_close_file (id)
    krb5_ccache id;
{
     krb5_scc_data *data;
     int ret;

     data = (krb5_scc_data *) id->data;
     if (data->file == (FILE *) NULL) {
	 abort ();
     }
     ret = fflush (data->file);
     bzero (data->stdio_buffer, sizeof (data->stdio_buffer));
     if (ret) {
	  (void) fclose (data->file);
	  data->file = 0;
	  return krb5_scc_interpret (errno);
     }
     ret = fclose (data->file);
     data->file = 0;
     return ret ? krb5_scc_interpret (errno) : 0;
}

krb5_error_code
krb5_scc_open_file (id, mode)
    krb5_ccache id;
    const char *mode;
{
     krb5_scc_data *data;
     FILE *f;
     int ret;

     data = (krb5_scc_data *) id->data;
     if (data->file) {
	  /* Don't know what state it's in; shut down and start anew.  */
	  (void) fclose (data->file);
	  data->file = 0;
     }
     f = fopen (data->filename, mode);
     if (!f)
	  return krb5_scc_interpret (errno);
     setbuf (f, data->stdio_buffer);
#if 0 /* alternative, not requiring sizeof stdio_buffer == BUFSIZ */
     setvbuf(f, data->stdio_buffer, _IOFBF, sizeof (data->stdio_buffer));
#endif
     data->file = f;
     return 0;
}
