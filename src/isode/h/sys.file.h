/* sys.file.h - system independent sys/file.h */

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:30:00  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  94/06/10  03:18:25  eichin
 * autoconfed isode for kerberos work
 * 
 * Revision 1.1  1994/05/31 20:38:39  eichin
 * reduced-isode release from /mit/isode/isode-subset/src
 *
 * Revision 8.0  91/07/17  12:33:57  isode
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

#ifndef _ISODE_SYS_FILE_H
#define _ISODE_SYS_FILE_H

#include "general.h"

/* Beware the ordering is important to avoid symbol clashes */

#ifndef SVR4_UCB
#include <sys/ioctl.h>
#endif

#ifdef  BSD42
#include <sys/file.h>
#else    
#ifdef  SYS5
#include <fcntl.h>
#else
#include <sys/fcntl.h>
#endif
#endif

#ifdef SYS5
#include <termio.h>
#endif

#endif 
