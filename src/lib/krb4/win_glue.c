/*
 * win-glue.c
 * 
 * Glue code for pasting Kerberos into the Windows environment.
 *
 * Originally written by John Gilmore, Cygnus Support, May '94.
 * Public Domain.
 */

#define	DEFINE_SOCKADDR
#include "krb.h"

#include <sys/types.h>
#include <stdio.h>
#include <windows.h>

static HINSTANCE hlibinstance;

/* 
 * WinSock support.
 *
 * Do the WinSock initialization call, keeping all the hair here.
 *
 * This routine is called by SOCKET_INITIALIZE in include/c-windows.h.
 * The code is pretty much copied from winsock.txt from winsock-1.1,
 * available from:
 * ftp://sunsite.unc.edu/pub/micro/pc-stuff/ms-windows/winsock/winsock-1.1
 */
int
win_socket_initialize()
{
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;

    wVersionRequested = 0x0101;		/* We need version 1.1 */

    err = WSAStartup (wVersionRequested, &wsaData);
    if (err != 0) 
	return err;		/* Library couldn't initialize */

    if (wVersionRequested != wsaData.wVersion) {
	/* DLL couldn't support our version of the spec */
	WSACleanup ();
	return -104;		/* FIXME -- better error? */
    }

    return 0;
}

/*
 * We needed a way to print out what might be FAR pointers on Windows,
 * but might be ordinary pointers on real machines.  Printf modifiers
 * scattered through the code don't cut it,
 * since they might break on real machines.  Microloss
 * didn't provide a function to print a char FAR *, so we wrote one.
 * It gets #define'd to fputs on real machines. 
 */
int
far_fputs(string, stream)
	char FAR *string;
	FILE *stream;
{
	return fprintf(stream, "%Fs", string);
}


BOOL CALLBACK
LibMain(hInst, wDataSeg, cbHeap, CmdLine)
	HINSTANCE hInst;
	WORD wDataSeg;
	WORD cbHeap;
	LPSTR CmdLine;
{
	hlibinstance = hInst;

	return 1;
}


int CALLBACK __export
WEP(nParam)
	int nParam;
{
	return 1;
}


HINSTANCE
get_lib_instance()
{
	return hlibinstance;
}


int INTERFACE
krb_start_session(x)
     char *x;
{
	return KSUCCESS;
}

int INTERFACE
krb_end_session(x)
     char *x;
{
	return KSUCCESS;
}

void
krb_set_tkt_string(val)
char *val;
{
}

/* FIXME -- Mark... */
int krb_ignore_ip_address = 0;
