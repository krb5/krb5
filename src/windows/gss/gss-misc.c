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
#include "gss.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

/*+
 * Function: send_token
 *
 * Purpose: Writes a token to a file descriptor.
 *
 * Arguments:
 *
 *	s		(r) an open file descriptor
 *	tok		(r) the token to write
 *
 * Returns: 0 on success, -1 on failure
 *
 * Effects:
 *
 * send_token writes the token length (as a network long) and then the
 * token data to the file descriptor s.	 It returns 0 on success, and
 * -1 if an error occurs or if it could not write all the data.
 */
int send_token(int s, gss_buffer_t tok) {
    long len;
    size_t ret;
    size_t ws_err;

    len = htonl(tok->length);

    ret = send (s, (char *) &len, 4, 0);        // Send length over the socket
    if (ret < 0) {
		ws_err = WSAGetLastError();
		errno = ws_err;
		my_perror("sending token length");
		OkMsgBox ("Winsock error  %d \n", ws_err);
		return -1;
    } else if (ret != 4) {
	    ws_err = WSAGetLastError();
	    OkMsgBox("sending token length: %d of %d bytes written\nWinsock error = %d\n",
		     ret, 4, ws_err);
	    return -1;
    }

    ret = send (s, tok->value, tok->length, 0); // Send the data
    if (ret < 0) {
	    ws_err = WSAGetLastError();
	    errno = ws_err;
	    my_perror("sending token data");
	    OkMsgBox ("Winsock error  %d \n", ws_err);
	    return -1;
    } else if (ret != tok->length) {
	    ws_err = WSAGetLastError();
	    OkMsgBox ("sending token data: %d of %d bytes written\nWinsock error = %d\n",
		      ret, tok->length, ws_err);
	    return -1;
    }

    return 0;
}

/*+
 * Function: recv_token
 *
 * Purpose: Reads a token from a file descriptor.
 *
 * Arguments:
 *
 *	s		(r) an open file descriptor
 *	tok		(w) the read token
 *
 * Returns: 0 on success, -1 on failure
 *
 * Effects:
 * 
 * recv_token reads the token length (as a network long), allocates
 * memory to hold the data, and then reads the token data from the
 * file descriptor s.  It blocks to read the length and data, if
 * necessary.  On a successful return, the token should be freed with
 * gss_release_buffer.	It returns 0 on success, and -1 if an error
 * occurs or if it could not read all the data.
 */
int
recv_token (int s, gss_buffer_t tok) {
    int ret;
    unsigned long len;
	size_t ws_err;

    ret = recv (s, (char *) &len, 4, 0);
    if (ret < 0) {
	    ws_err = WSAGetLastError();
	    errno = ws_err;
	    my_perror("reading token length");
	    OkMsgBox ("Winsock error  %d \n", ws_err);
        return -1;
    } else if (ret != 4) {
	    ws_err = WSAGetLastError();
	    OkMsgBox ("reading token length: %d of %d bytes written\nWinsock error = %d\n",
		      ret, 4, ws_err);
	    return -1;
    }
	  
    len = ntohl(len);
    tok->length = (size_t) len;
    tok->value = (char *) malloc(tok->length);
    if (tok->value == NULL) {
        OkMsgBox ("Out of memory allocating token data\n");
        return -1;
    }

    ret = recv (s, (char *) tok->value, tok->length, 0);
    if (ret < 0) {
	    ws_err = WSAGetLastError();
	    errno = ws_err;
	    my_perror("reading token data");
	    OkMsgBox ("Winsock error  %d \n", ws_err);
	    free(tok->value);
	    return -1;
    } else if ((size_t) ret != tok->length) {
	    ws_err = WSAGetLastError();
	    OkMsgBox ("reading token data: %d of %d bytes written\nWinsock error = %d\n",
		      ret, tok->length, ws_err);
	    free(tok->value);
	    return -1;
    }

    return 0;
}

/*+
 * Function: display_status
 *
 * Purpose: displays GSS-API messages
 *
 * Arguments:
 *
 *	msg		a string to be displayed with the message
 *	maj_stat	the GSS-API major status code
 *	min_stat	the GSS-API minor status code
 *
 * Effects:
 *
 * The GSS-API messages associated with maj_stat and min_stat are
 * displayed on stderr, each preceeded by "GSS-API error <msg>: " and
 * followed by a newline.
 */
void
display_status (char *msg, OM_uint32 maj_stat, OM_uint32 min_stat) {
    display_status_1(msg, maj_stat, GSS_C_GSS_CODE);
    display_status_1(msg, min_stat, GSS_C_MECH_CODE);
}

static void
display_status_1(char *m, OM_uint32 code, int type) {
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc msg;
    OM_uint32 msg_ctx;
     
    msg_ctx = 0;
    while (1) {
        maj_stat = gss_display_status(&min_stat, code,
                                      type, GSS_C_NULL_OID,
                                      &msg_ctx, &msg);
        OkMsgBox ("GSS-API error %s: %s\n", m,
            (char *)msg.value);
        (void) gss_release_buffer(&min_stat, &msg);
	  
        if (!msg_ctx)
            break;
    }
}
/*+*************************************************************************
** 
** OkMsgBox
** 
** A MessageBox version of printf
** 
***************************************************************************/
void
OkMsgBox (char *format, ...) {
    char buf[256];								// Message goes into here
    char *args;                                 // Args for printf

    args = (char *) &format + sizeof(format);
    vsprintf (buf, format, args);
    MessageBox(NULL, buf, "", MB_OK);
}
/*+*************************************************************************
** 
** My_perror
** 
** A windows conversion of perror displaying the output into a MessageBox.
** 
***************************************************************************/
void
my_perror (char *msg) {
    char *err;

    err = strerror (errno);

    if (msg && *msg != '\0') 
        OkMsgBox ("%s: %s", msg, err);
    else
        MessageBox (NULL, err, "", MB_OK);
}

