%{
/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved.
 *
 * $Id$
 * $Source$
 * 
 * $Log$
 * Revision 1.3  1996/07/22 20:28:49  marc
 * this commit includes all the changes on the OV_9510_INTEGRATION and
 * OV_MERGE branches.  This includes, but is not limited to, the new openvision
 * admin system, and major changes to gssapi to add functionality, and bring
 * the implementation in line with rfc1964.  before committing, the
 * code was built and tested for netbsd and solaris.
 *
 * Revision 1.2.4.1  1996/07/18 03:03:31  marc
 * merged in changes from OV_9510_BP to OV_9510_FINAL1
 *
 * Revision 1.2.2.1  1996/06/20  21:56:31  marc
 * File added to the repository on a branch
 *
 * Revision 1.2  1993/11/05  07:47:46  bjaspan
 * add and use cmp_gss_names, fix regexp bug
 *
 * Revision 1.1  1993/11/05  07:08:48  bjaspan
 * Initial revision
 *
 */

#if !defined(lint) && !defined(__CODECENTER__)
static char *rcsid = "$Header$";
#endif

enum tokens {
     NEWLINE = 257,
     COMMA,
     SEMI,

     GET = 300,
     ADD,
     MODIFY,
     DELETE,

     ID = 350,
};

typedef union {
     char *s;
} toktype;

toktype tokval;
int acl_lineno = 0;

%}

%%

\n		acl_lineno++; 
[ \t]*		;
[ ]*#.*		;
","		return (COMMA);
";"		return (SEMI);
"get"		return (GET);
"add"		return (ADD);
"modify"	return (MODIFY);
"delete"	return (DELETE);
^[^ \t\n]+		{ tokval.s = yytext; return (ID); }

%%
     
#include <string.h>
#include <syslog.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <ovsec_admin/admin.h>

typedef struct _entry {
     gss_name_t gss_name;
     char *name;
     u_int privs;
     struct _entry *next;
} acl_entry;

static acl_entry *acl_head = NULL;

static void error(char *msg);

int parse_aclfile(FILE *acl_file)
{
     OM_uint32 gssstat, minor_stat;
     gss_buffer_desc in_buf;
     acl_entry *entry;
     enum tokens tok;

     yyin = acl_file;

     acl_lineno = 1;
     while ((tok = yylex()) != 0) {
	  if (tok != ID) {
	       error("expected identifier");
	       goto error;
	  }

	  entry = (acl_entry *) malloc(sizeof(acl_entry));
	  if (entry == NULL) {
	       error("out of memory");
	       goto error;
	  }
	  entry->name = strdup(tokval.s);
	  entry->privs = 0;
	  while (1) {
	       switch (tok = yylex()) {
	       case GET:
		    entry->privs |= OVSEC_KADM_PRIV_GET;
		    break;
	       case ADD:
		    entry->privs |= OVSEC_KADM_PRIV_ADD;
		    break;
	       case MODIFY:
		    entry->privs |= OVSEC_KADM_PRIV_MODIFY;
		    break;
	       case DELETE:
		    entry->privs |= OVSEC_KADM_PRIV_DELETE;
		    break;
	       default:
		    error("expected privilege");
		    goto error;
	       }
	       tok = yylex();
	       if (tok == COMMA)
		    continue;
	       else if (tok == SEMI)
		    break;
	       else {
		    error("expected comma or semicolon");
		    goto error;
	       }
	  }

	  in_buf.value = entry->name;
	  in_buf.length = strlen(entry->name) + 1;
	  gssstat = gss_import_name(&minor_stat, &in_buf,
				    gss_nt_krb5_name, &entry->gss_name);
	  if (gssstat != GSS_S_COMPLETE) {
	       error("invalid name");
	       goto error;
	  }
	  
	  if (acl_head == NULL) {
	       entry->next = NULL;
	       acl_head = entry;
	  } else {
	       entry->next = acl_head;
	       acl_head = entry;
	  }
     }
     return 0;

error:
     return 1;
}

int acl_check(gss_name_t caller, int priv)
{
     acl_entry *entry;
     
     entry = acl_head;
     while (entry) {
	  if (cmp_gss_names(entry->gss_name, caller) && entry->privs & priv)
	       return 1;
	  entry = entry->next;
     }
     return 0;
}

int cmp_gss_names(gss_name_t name1, gss_name_t name2)
{
     OM_uint32 minor_stat;
     int eq;
     (void) gss_compare_name(&minor_stat, name1, name2, &eq);
     return eq;
}

static void error(char *msg)
{
     syslog(LOG_ERR, "Error while parsing acl file, line %d: %s\n",
	    acl_lineno, msg);
}

yywrap() { return(1); }
