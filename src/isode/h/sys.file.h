/* sys.file.h - system independent sys/file.h */

/* 
 * isode/h/sys.file.h
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
