/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * This file contains the source code for krb5_scc_destroy.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_scc_destry_c[] = "$Id$";
#endif /* !lint && !SABER */

#include <krb5/copyright.h>

#include "scc.h"

#ifndef SEEK_SET
#define SEEK_SET 0
#endif

/*
 * Effects:
 * Destroys the contents of id.
 *
 * Errors:
 * system errors
 */
krb5_error_code krb5_scc_destroy(id)
   krb5_ccache id;
{
     unsigned long size;
     char zeros[BUFSIZ];
     krb5_scc_data *data = (krb5_scc_data *) id->data;
     register int ret;
     
     if (!OPENCLOSE(id)) {
	 (void) fclose(data->file);
	 data->file = 0;
     }

     ret = remove (data->filename);
     if (ret < 0) {
	 ret = krb5_scc_interpret(errno);
	 if (OPENCLOSE(id)) {
	     (void) fclose(data->file);
	     data->file = 0;
	 }
	 return ret;
     }

#if 0
     /*
      * Possible future extension: Read entire file to determine
      * length, then write nulls all over it.  This was the UNIX
      * version...
      */
     ret = fstat(fileno(data->file), &buf);
     if (ret < 0) {
	 ret = krb5_scc_interpret(errno);
	 if (OPENCLOSE(id)) {
	     (void) fclose(data->file);
	     data->file = 0;
	 }
	 return ret;
     }

     /* XXX This may not be legal XXX */
     size = (unsigned long) buf.st_size;

     memset (zeros, 0, BUFSIZ);
     for (i=0; i < size / BUFSIZ; i++)
	  if (fwrite(data->file, zeros, BUFSIZ) < 0) {
	      ret = krb5_scc_interpret(errno);
	      if (OPENCLOSE(id)) {
		  (void) fclose(data->file);
		  data->file = 0;
	      }
	      return ret;
	  }

     if (fwrite(data->file, zeros, size % BUFSIZ) < 0) {
	 ret = krb5_scc_interpret(errno);
	 if (OPENCLOSE(id)) {
	     (void) fclose(data->file);
	     data->file = 0;
	 }
	 return ret;
     }
     
     ret = fclose(data->file);
     data->file = 0;
#endif

     if (ret)
	 ret = krb5_scc_interpret(errno);

     return ret;
}
