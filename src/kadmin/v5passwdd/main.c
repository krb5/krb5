#include    <stdio.h>
#include    <signal.h>
#include    <syslog.h>
#include    <unistd.h>
#include    <string.h>
#include    <setjmp.h>

#include <krb5.h>
#include <kadm5/admin.h>
#include <krb5/adm_proto.h>
#include "kadm5_defs.h"

#if defined(NEED_DAEMON_PROTO)
extern int daemon(int, int);
#endif

static krb5_keytab keytab;
char *programname;
kadm5_config_params params;
void *global_server_handle;
#if	POSIX_SETJMP
static sigjmp_buf	terminal_jmp;
#else	/* POSIX_SETJMP */
static jmp_buf		terminal_jmp;
#endif	/* POSIX_SETJMP */

krb5_keytab key_keytab_id()
{
    return(keytab);
}

static krb5_sigtype
unhandled_signal(signo)
    int signo;
{
#if	POSIX_SETJMP
    siglongjmp(terminal_jmp, signo);
#else	/* POSIX_SETJMP */
    longjmp(terminal_jmp, signo);
#endif	/* POSIX_SETJMP */
    /* NOTREACHED */
}

static void usage()
{
     fprintf(stderr, "Usage: kadmind [-r realm] [-m] [-nofork] "
	     "[-D debuglevel] [-T keytable] [-port port-number]\n");
     exit(1);
}

int main(int argc, char *argv[])
{
     int ret;
     volatile int nofork;
     int timeout = -1;
     krb5_error_code code;
     volatile int debug_level = 0;
#if	POSIX_SIGNALS
     struct sigaction s_action;
#endif	/* POSIX_SIGNALS */
     krb5_context context;

     programname = argv[0];

     nofork = 0;

     memset((char *) &params, 0, sizeof(params));
     
     argc--; argv++;
     while (argc) {
	  if (strcmp(*argv, "-r") == 0) {
	       argc--; argv++;
	       if (!argc)
		    usage();
	       params.realm = *argv;
	       params.mask |= KADM5_CONFIG_REALM;
	       argc--; argv++;
	       continue;
	  } else if (strcmp(*argv, "-m") == 0) {
	       params.mkey_from_kbd = 1;
	       params.mask |= KADM5_CONFIG_MKEY_FROM_KBD;
	  } else if (strcmp(*argv, "-nofork") == 0) {
	       nofork = 1;
	  } else if(strcmp(*argv, "-port") == 0) {
	    argc--; argv++;
	    if(!argc)
	      usage();
	    params.kadmind_port = atoi(*argv);
	    params.mask |= KADM5_CONFIG_KADMIND_PORT;
	  } else if (strcmp(*argv, "-T") == 0) {
	       argc--; argv++;
	       if (!argc)
		    usage();
	       params.admin_keytab = *argv;
	       params.mask |= KADM5_CONFIG_ADMIN_KEYTAB;
	       argc--; argv++;
	       continue;
	  } else if (strcmp(*argv, "-D") == 0) {
	       if (!argc)
		    usage();
	       argc--; argv++;
	       debug_level = atoi(*argv);
	  } else
	       break;
	  argc--; argv++;
     }
     
     if (argc != 0)
	  usage();

     ret = krb5_init_context(&context);
     if (ret) {
	 fprintf(stderr, "%s: %s while initializing context, aborting\n",
		 programname, error_message(ret));
	 exit(1);
     }

     krb5_klog_init(context, "admin_server", programname, 1);

     ret = kadm5_get_config_params(context, NULL, NULL, &params,
				   &params);
     if (ret) {
	 krb5_klog_syslog(LOG_ERR, "%s: %s while initializing, aborting\n",
			  programname, error_message(ret));
	 fprintf(stderr, "%s: %s while initializing, aborting\n",
		 programname, error_message(ret));
	 krb5_klog_close(context);
	 exit(1);
     }

#define REQUIRED_PARAMS (KADM5_CONFIG_REALM | KADM5_CONFIG_ACL_FILE | \
			 KADM5_CONFIG_ADMIN_KEYTAB)

     if ((params.mask & REQUIRED_PARAMS) != REQUIRED_PARAMS) {
	  krb5_klog_syslog(LOG_ERR, "%s: Missing required configuration values "
			   "(%x) while initializing, aborting\n", programname,
			   (params.mask & REQUIRED_PARAMS) ^ REQUIRED_PARAMS);
	  fprintf(stderr, "%s: Missing required configuration values "
		  "(%lx) while initializing, aborting\n", programname,
		  (params.mask & REQUIRED_PARAMS) ^ REQUIRED_PARAMS);
	  krb5_klog_close(context);
	  exit(1);
     }

     if ((code = krb5_kt_resolve(context, params.admin_keytab, &keytab))) {
	 fprintf(stderr, "%s: cannot resolve keytab %s (%s).\n",
		 programname, params.admin_keytab, error_message(code));
	 exit(1);
     }

     if (!nofork &&
	 daemon(0, ((params.mask&KADM5_CONFIG_MKEY_FROM_KBD)?
		    params.mkey_from_kbd:0))) {
	  fprintf(stderr, "%s: cannot spawn and detach.\n", argv[0]);
	  perror(argv[0]);
	  return(2);
     }

#if	POSIX_SIGNALS
     (void) sigemptyset(&s_action.sa_mask);
     s_action.sa_flags = 0;
     s_action.sa_handler = unhandled_signal;
     (void) sigaction(SIGINT, &s_action, (struct sigaction *) NULL);
     (void) sigaction(SIGTERM, &s_action, (struct sigaction *) NULL);
     (void) sigaction(SIGHUP, &s_action, (struct sigaction *) NULL);
     (void) sigaction(SIGQUIT, &s_action, (struct sigaction *) NULL);
     (void) sigaction(SIGPIPE, &s_action, (struct sigaction *) NULL);
     (void) sigaction(SIGALRM, &s_action, (struct sigaction *) NULL);
     (void) sigaction(SIGCHLD, &s_action, (struct sigaction *) NULL);
#else	/* POSIX_SIGNALS */
     signal(SIGINT, unhandled_signal);
     signal(SIGTERM, unhandled_signal);
     signal(SIGHUP, unhandled_signal);
     signal(SIGQUIT, unhandled_signal);
     signal(SIGPIPE, unhandled_signal);
     signal(SIGALRM, unhandled_signal);
     signal(SIGCHLD, unhandled_signal);
#endif	/* POSIX_SIGNALS */

     krb5_klog_syslog(LOG_INFO, "starting");

     code = net_init(context, params.realm, debug_level,
		     (params.mask&KADM5_CONFIG_KADMIND_PORT)?
		     params.kadmind_port:0);
     if (code) {
	krb5_klog_syslog(LOG_ERR, "%s: %s while initializing network",
			 programname, error_message(code));
	fprintf(stderr, "%s: %s while initializing network\n",
		programname, error_message(code));

	exit(1);
     }

     code = proto_init(context, debug_level, timeout);
     if (code) {
	 krb5_klog_syslog(LOG_ERR, "%s: %s while initializing proto",
			  programname, error_message(code));
	 fprintf(stderr, "%s: %s while initializing  proto\n",
		 programname, error_message(code));
     }

     if (
#if	POSIX_SETJMP
	 sigsetjmp(terminal_jmp, 1) == 0
#else	/* POSIX_SETJMP */
	 setjmp(terminal_jmp) == 0
#endif	/* POSIX_SETJMP */
	 )
	 {
	     code = net_dispatch(context, !nofork);
	     if (code) {
		 krb5_klog_syslog(LOG_ERR, "%s: %s while dispatching requests",
				  programname, error_message(code));
		 fprintf(stderr, "%s: %s while dispatching requests\n",
			 programname, error_message(code));
		 
		 exit(1);
	     }
	 }

     net_finish(context, debug_level);
	 
     krb5_klog_syslog(LOG_INFO, "finished, exiting");
     krb5_klog_close(context);
     exit(2);
}

krb5_error_code key_open_db(krb5_context context)
{
     return(kadm5_init("kadmind", NULL,
		       NULL, &params,
		       KADM5_STRUCT_VERSION,
		       KADM5_API_VERSION_2,
		       &global_server_handle));
}

krb5_error_code key_close_db(krb5_context context)
{
     kadm5_destroy(global_server_handle);
     return(0);
}

krb5_int32
pwd_change(kcontext, debug_level, auth_context, ticket,
	      olddata, newdata, err_str, err_str_len)
    krb5_context	kcontext;
    int			debug_level;
    krb5_auth_context	auth_context;
    krb5_ticket		*ticket;
    krb5_data		*olddata;
    krb5_data		*newdata;
    char		err_str[];
    unsigned int	err_str_len;
{
     kadm5_ret_t ret;
     krb5_int32			now;
     kadm5_policy_ent_rec	pol;
     kadm5_principal_ent_rec	princ;
     krb5_principal		principal;

     /* Make sure the ticket is initial, otherwise don't trust it */
     if ((ticket->enc_part2->flags & TKT_FLG_INITIAL) == 0) {
	  return(KRB5_ADM_NOT_IN_TKT);
     }

     /* a principal can always change its own password, so there's no
	acl check to do here */

     principal = ticket->enc_part2->client;

     /* check to see if the min_time has passed.  this is stolen
	from chpass_principal_wrapper */

     ret = krb5_timeofday(kcontext, &now);
     if (ret) {
	     /* XXX - The only caller is known to use a 1K buffer.  */
     system_error:
	     strncpy(err_str, error_message(ret), 1024);
	 return(KRB5_ADM_SYSTEM_ERROR);
     }

     if((ret = kadm5_get_principal(global_server_handle, principal,
				  &princ,
				  KADM5_PRINCIPAL_NORMAL_MASK)) !=
       KADM5_OK) {
	 goto system_error;
    }
    if(princ.aux_attributes & KADM5_POLICY) {
	if((ret=kadm5_get_policy(global_server_handle,
				 princ.policy, &pol)) != KADM5_OK) {
	    (void) kadm5_free_principal_ent(global_server_handle, &princ);
	    goto system_error;
	}
	if((now - princ.last_pwd_change) < pol.pw_min_life &&
	   !(princ.attributes & KRB5_KDB_REQUIRES_PWCHANGE)) {
	    (void) kadm5_free_policy_ent(global_server_handle, &pol);
	    (void) kadm5_free_principal_ent(global_server_handle, &princ);
	    /* XXX - The only caller is known to use a 1K buffer.  */
	    strncpy(err_str, error_message(ret), 1024);
	    return(KRB5_ADM_PW_UNACCEPT);
	}

	ret = kadm5_free_policy_ent(global_server_handle, &pol);
	if (ret) {
	    (void) kadm5_free_principal_ent(global_server_handle, &princ);
	    goto system_error;
        }
    }

    ret = kadm5_free_principal_ent(global_server_handle, &princ);
    if (ret) {
	 goto system_error;
    }

    /* ok, it's not too early to change the password. change it. */
    
    ret = kadm5_chpass_principal_util(global_server_handle,
				      principal, newdata->data,
				      NULL, err_str, err_str_len);
    if (ret)
	return(KRB5_ADM_PW_UNACCEPT);
    
    return(KRB5_ADM_SUCCESS);
}
