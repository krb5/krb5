#ifndef TELNET_H_INC
#define TELNET_H_INC

#include <windows.h>
#include <stdarg.h>

#ifdef KRB5
	#include "krb5.h"
	#include "k5stream.h"
#endif

#include "dialog.h"
#include "screen.h"
#include "struct.h"
#include "wt-proto.h"
#include "winsock.h"
#include "ini.h"

/* globals */
extern char szAutoHostName[64];
extern char szUserName[64];
extern char szHostName[64];

#ifdef KRB5
   extern krb5_context k5_context;
#endif

extern void parse(
	CONNECTION *con,
	unsigned char *st,
	int cnt);

extern void send_naws(
	CONNECTION *con);

extern char strTmp[1024];

#define DEF_WIDTH 80
#define DEF_HEIGHT 24

#endif /* TELNET_H_INC */

