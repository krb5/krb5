/* dgram.h - datagram (CL-mode TS) abstractions */

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:29:11  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  94/06/10  03:17:32  eichin
 * autoconfed isode for kerberos work
 * 
 * Revision 1.1  1994/05/31 20:37:49  eichin
 * reduced-isode release from /mit/isode/isode-subset/src
 *
 * Revision 8.0  91/07/17  12:33:42  isode
 * Release 7.0
 * 
 * 
 */

/*
 *				  NOTICE
 *
 *    Acquisition, use, and distribution of this module and related
 *    materials are subject to the restrictions of a license agreement.
 *    Consult the Preface in the User's Manual for the full terms of
 *    this agreement.
 *
 */


#ifndef	_DGRAM_
#define	_DGRAM_

#define	MAXDGRAM	8192


int	join_dgram_aux ();
int	read_dgram_socket ();
int	write_dgram_socket ();
int	close_dgram_socket ();
int	select_dgram_socket ();
int	check_dgram_socket ();

#endif
