/*
 * kadmin/server/adm_msgs.c
 *
 * Copyright 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 * Top-level loop of the Kerberos Version 5 Administration server
 */

/* 
 * Sandia National Laboratories also makes no representations about the 
 * suitability of the modifications, or additions to this software for 
 * any purpose.  It is provided "as is" without express or implied warranty.
 */


char *oper_type[] = {
	"complete",					/* 0 */
	"addition",					/* 1 */
	"deletion",					/* 2 */
	"change",					/* 3 */
	"modification",					/* 4 */
	"inquiry"					/* 5 */
};

char *ksrvutil_message[] = {
	"Service Key Changed",				/* 0 */
	"New Key and Version Received"			/* 1 */
};

char *kadmind_general_response[] = {
	"Success",					/* 0 */
	"Service Access Granted"			/* 1 */
};

char *kadmind_kpasswd_response[] = {
	"Password Changed",				/* 0 */
	"Password NOT Changed!"				/* 1 */
};

char *kadmind_ksrvutil_response[] = {
	"Service Password Change Complete",		/* 0 */
	"One or More Service Password Change(s) Failed!",	/* 1 */
	"Database Update Failure - Possible Catastrophe!!"	/* 2 */
};

char *kadmind_kadmin_response[] = {
	"Administrative Service Completed",		/* 0 */
	"Principal Unknown!",				/* 1 */
	"Principal Already Exists!",			/* 2 */
	"Allocation Failure!",				/* 3 */
	"Password Failure!",				/* 4 */
	"Protocol Failure!",				/* 5 */
	"Security Failure!",				/* 6 */
	"Admin Client Not in ACL List!",			/* 7 */
	"Database Update Failure - Possible Catastrophe!!"	/* 8 */
};
