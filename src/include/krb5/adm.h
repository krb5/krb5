/*
 * include/krb5/adm.h
 *
 * Copyright 1995 by the Massachusetts Institute of Technology.
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 */
#ifndef	KRB5_ADM_H__
#define	KRB5_ADM_H__

/*
 * Kerberos V5 Change Password service name
 */
#define	KRB5_ADM_SERVICE_NAME	"changepw"

/*
 * Maximum password length.
 */
#define	KRB5_ADM_MAX_PASSWORD_LEN	512

/*
 * Protocl command strings.
 */
#define	KRB5_ADM_QUIT_CMD	"QUIT"
#define	KRB5_ADM_CHECKPW_CMD	"CHECKPW"
#define	KRB5_ADM_CHANGEPW_CMD	"CHANGEPW"
#define	KRB5_ADM_MOTD_CMD	"MOTD"
#define	KRB5_ADM_MIME_CMD	"MIME"
#define	KRB5_ADM_LANGUAGE_CMD	"LANGUAGE"

/*
 * Reply status values.
 */
#define	KRB5_ADM_SUCCESS		0
#define	KRB5_ADM_CMD_UNKNOWN		1
#define	KRB5_ADM_PW_UNACCEPT		2
#define	KRB5_ADM_BAD_PW			3
#define	KRB5_ADM_NOT_IN_TKT		4
#define	KRB5_ADM_CANT_CHANGE		5
#define	KRB5_ADM_LANG_NOT_SUPPORTED	6

/*
 * Subcodes.
 */
#define	KRB5_ADM_BAD_ARGS		10
#define	KRB5_ADM_BAD_CMD		11
#define	KRB5_ADM_NO_CMD			12
#define	KRB5_ADM_BAD_PRINC		20
#define	KRB5_ADM_PWD_TOO_SHORT		21
#define	KRB5_ADM_PWD_WEAK		22
#define	KRB5_ADM_NOT_ALLOWED		100
#endif	/* KRB5_ADM_H__ */
