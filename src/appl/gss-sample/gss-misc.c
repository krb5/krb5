/*
 * Copyright 1994 by OpenVision Technologies, Inc.
 * 
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 * 
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_generic.h>

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#else
extern char *malloc();
#endif

static void display_status_1();

FILE *display_file = NULL;

/*
 * Function: send_token
 *
 * Purpose: Writes a token to a file descriptor.
 *
 * Arguments:
 *
 * 	s		(r) an open file descriptor
 * 	tok		(r) the token to write
 *
 * Returns: 0 on success, -1 on failure
 *
 * Effects:
 *
 * send_token writes the token length (as a network long) and then the
 * token data to the file descriptor s.  It returns 0 on success, and
 * -1 if an error occurs or if it could not write all the data.
 */
int send_token(s, tok)
     int s;
     gss_buffer_t tok;
{
     int len, ret;

     len = htonl(tok->length);

     ret = write(s, (char *) &len, 4);
     if (ret < 0) {
	  perror("sending token length");
	  return -1;
     } else if (ret != 4) {
	 if (display_file)
	     fprintf(display_file, 
		     "sending token length: %d of %d bytes written\n", 
		     ret, 4);
	  return -1;
     }

     ret = write(s, tok->value, tok->length);
     if (ret < 0) {
	  perror("sending token data");
	  return -1;
     } else if (ret != tok->length) {
	 if (display_file)
	     fprintf(display_file, 
		     "sending token data: %d of %d bytes written\n", 
		     ret, tok->length);
	 return -1;
     }
     
     return 0;
}

/*
 * Function: recv_token
 *
 * Purpose: Reads a token from a file descriptor.
 *
 * Arguments:
 *
 * 	s		(r) an open file descriptor
 * 	tok		(w) the read token
 *
 * Returns: 0 on success, -1 on failure
 *
 * Effects:
 * 
 * recv_token reads the token length (as a network long), allocates
 * memory to hold the data, and then reads the token data from the
 * file descriptor s.  It blocks to read the length and data, if
 * necessary.  On a successful return, the token should be freed with
 * gss_release_buffer.  It returns 0 on success, and -1 if an error
 * occurs or if it could not read all the data.
 */
int recv_token(s, tok)
     int s;
     gss_buffer_t tok;
{
     int ret;
     int readsofar = 0;

     ret = read(s, (char *) &tok->length, 4);
     if (ret < 0) {
	  perror("reading token length");
	  return -1;
     } else if (ret != 4) {
	 if (display_file)
	     fprintf(display_file, 
		     "reading token length: %d of %d bytes read\n", 
		     ret, 4);
	 return -1;
     }
	  
     tok->length = ntohl(tok->length);
     tok->value = (char *) malloc(tok->length);
     if (tok->value == NULL) {
	 if (display_file)
	     fprintf(display_file, 
		     "Out of memory allocating token data\n");
	  return -1;
     }

     while (readsofar < tok->length) {
	 ret = read(s, (char *) tok->value + readsofar, 
		    tok->length - readsofar);
	 readsofar += ret;
	 if (ret < 0) {
	     perror("reading token data");
	     free(tok->value);
	     return -1;
	 }
     }

     return 0;
}

/*
 * Function: display_status
 *
 * Purpose: displays GSS-API messages
 *
 * Arguments:
 *
 * 	msg		a string to be displayed with the message
 * 	maj_stat	the GSS-API major status code
 * 	min_stat	the GSS-API minor status code
 *
 * Effects:
 *
 * The GSS-API messages associated with maj_stat and min_stat are
 * displayed on stderr, each preceeded by "GSS-API error <msg>: " and
 * followed by a newline.
 */
void display_status(msg, maj_stat, min_stat)
     char *msg;
     OM_uint32 maj_stat;
     OM_uint32 min_stat;
{
     display_status_1(msg, maj_stat, GSS_C_GSS_CODE);
     display_status_1(msg, min_stat, GSS_C_MECH_CODE);
}

static void display_status_1(m, code, type)
     char *m;
     OM_uint32 code;
     int type;
{
     OM_uint32 maj_stat, min_stat;
     gss_buffer_desc msg;
#ifdef	GSSAPI_V2
     OM_uint32 msg_ctx;
#else	/* GSSAPI_V2 */
     int msg_ctx;
#endif	/* GSSAPI_V2 */
     
     msg_ctx = 0;
     while (1) {
	  maj_stat = gss_display_status(&min_stat, code,
				       type, GSS_C_NULL_OID,
				       &msg_ctx, &msg);
	  if (display_file)
	      fprintf(display_file, "GSS-API error %s: %s\n", m,
		      (char *)msg.value); 
	  (void) gss_release_buffer(&min_stat, &msg);
	  
	  if (!msg_ctx)
	       break;
     }
}
