/* dgram.h - datagram (CL-mode TS) abstractions */

/* 
 * isode/h/dgram.h
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
