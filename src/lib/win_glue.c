/* 
 * WinSock support.
 *
 * Do the WinSock initialization call, keeping all the hair here.
 *
 * This routine is called by SOCKET_INITIALIZE in include/c-windows.h.
 * The code is pretty much copied from winsock.txt from winsock-1.1,
 * available from:
 * ftp://sunsite.unc.edu/pub/micro/pc-stuff/ms-windows/winsock/winsock-1.1
 *
 * Note: WSAStartup and WSACleanup is called here (and only here).
 * This assumes that under Windows, we only use this library via the
 * DLL.  Note that calls to WSAStartup and WSACleanup must be in
 * matched pairs.  If there is a missing WSACleanup call when a
 * program exits, under Lan Workplace, the name resolver will stop
 * working. 
 */

/* We can't include winsock.h directly because of /Za (stdc) options */
#define NEED_SOCKETS
#include "k5-int.h"

int
win_socket_initialize()
{
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;

    wVersionRequested = 0x0101;                 /* We need version 1.1 */

    err = WSAStartup (wVersionRequested, &wsaData);
    if (err != 0)
        return err;                             /* Library can't initialize */

    if (wVersionRequested != wsaData.wVersion) {
	/* DLL couldn't support our version of the spec */
        WSACleanup ();
        return -104;                            /* FIXME -- better error? */
    }

    return 0;
}

BOOL CALLBACK
LibMain (hInst, wDataSeg, cbHeap, CmdLine)
HINSTANCE hInst;
WORD wDataSeg;
WORD cbHeap;
LPSTR CmdLine;
{
    win_socket_initialize ();
    return 1;
}

int CALLBACK __export
WEP(nParam)
	int nParam;
{
    WSACleanup();
    return 1;
}
