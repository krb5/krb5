/*
 * include/kerberosIV/admin_server.h
 *
 * Copyright 1987-1994 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 */

#ifndef ADMIN_SERVER_DEFS
#define ADMIN_SERVER_DEFS

#define PW_SRV_VERSION		 2	/* version number */

#define INSTALL_NEW_PW		(1<<0)	/*
					 * ver, cmd, name, password,
					 * old_pass, crypt_pass, uid
					 */

#define ADMIN_NEW_PW		(2<<1)	/*
					 * ver, cmd, name, passwd,
					 * old_pass
					 * (grot), crypt_pass (grot)
					 */

#define ADMIN_SET_KDC_PASSWORD	(3<<1)	/* ditto */
#define ADMIN_ADD_NEW_KEY	(4<<1)	/* ditto */
#define ADMIN_ADD_NEW_KEY_ATTR	(5<<1)  /*
					 * ver, cmd, name, passwd,
					 * inst, attr (grot)
					 */
#define INSTALL_REPLY		(1<<1)	/* ver, cmd, name, password */
#define	RETRY_LIMIT		 1
#define	TIME_OUT		30
#define USER_TIMEOUT		90
#define MAX_KPW_LEN		40

#define KADM	"changepw"		/* service name */

#endif /* ADMIN_SERVER_DEFS */
