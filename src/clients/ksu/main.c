/* 
 * Copyright (c) 1994 by the University of Southern California
 *
 * EXPORT OF THIS SOFTWARE from the United States of America may
 *     require a specific license from the United States Government.
 *     It is the responsibility of any person or organization contemplating
 *     export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to copy, modify, and distribute
 *     this software and its documentation in source and binary forms is
 *     hereby granted, provided that any documentation or other materials
 *     related to such distribution or use acknowledge that the software
 *     was developed by the University of Southern California. 
 *
 * DISCLAIMER OF WARRANTY.  THIS SOFTWARE IS PROVIDED "AS IS".  The
 *     University of Southern California MAKES NO REPRESENTATIONS OR
 *     WARRANTIES, EXPRESS OR IMPLIED.  By way of example, but not
 *     limitation, the University of Southern California MAKES NO
 *     REPRESENTATIONS OR WARRANTIES OF MERCHANTABILITY OR FITNESS FOR ANY
 *     PARTICULAR PURPOSE. The University of Southern
 *     California shall not be held liable for any liability nor for any
 *     direct, indirect, or consequential damages with respect to any
 *     claim by the user or distributor of the ksu software.
 *
 * KSU was writen by:  Ari Medvinsky, ari@isi.edu
 */

#include "ksu.h"
#include "adm_proto.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <grp.h>

/* globals */
char * prog_name;
int auth_debug =0;     
char k5login_path[MAXPATHLEN];
char k5users_path[MAXPATHLEN];
char * gb_err = NULL;
int quiet = 0;
/***********/

#define _DEF_CSH "/bin/csh" 
static int set_env_var (char *, char *);
static void sweep_up (krb5_context, krb5_ccache);
static char * ontty (void);
#ifdef HAVE_STDARG_H
static void print_status( const char *fmt, ...)
#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 7)
     __attribute__ ((__format__ (__printf__, 1, 2)))
#endif
     ;
#else
static void print_status();
#endif
char * get_dir_of_file();     

/* Note -e and -a options are mutually exclusive */
/* insure the proper specification of target user as well as catching         
   ill specified arguments to commands */        

void usage (){
    fprintf(stderr, "Usage: %s [target user] [-n principal] [-c source cachename] [-k] [-D] [-r time] [-pf] [-l lifetime] [-zZ] [-q] [-e command [args... ] ] [-a [args... ] ]\n", prog_name);
}

/* for Ultrix and friends ... */
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

/* These are file static so sweep_up can get to them*/
static uid_t source_uid, target_uid;

int
main (argc, argv)
    int argc;
    char ** argv;
{ 
    int hp =0;
    int some_rest_copy = 0;	
    int all_rest_copy = 0;	
    char *localhostname = NULL;
    opt_info options;
    int option=0;
    int statusp=0;
    krb5_error_code retval = 0; 
    krb5_principal client = NULL;
    krb5_ccache cc_target = NULL;
    krb5_context ksu_context;
    char * cc_target_tag = NULL; 
    char * target_user = NULL;
    char * source_user;
    
    krb5_ccache cc_source = NULL;
    const char * cc_source_tag = NULL; 
    uid_t source_gid, target_gid;
    const char * cc_source_tag_tmp = NULL;
    char * cc_target_tag_tmp=NULL; 
    char * cmd = NULL, * exec_cmd = NULL;
    int errflg = 0;
    krb5_boolean auth_val; 
    krb5_boolean authorization_val = FALSE; 
    int path_passwd = 0;
    int done =0,i,j;
    uid_t ruid = getuid ();
    struct passwd *pwd=NULL,  *target_pwd ;
    char * shell;
    char ** params;
    int keep_target_cache = 0;
    int child_pid, child_pgrp, ret_pid;
    extern char * getpass(), *crypt();
    int pargc;
    char ** pargv;
    struct stat  st_temp;
    krb5_boolean stored = FALSE;
    krb5_principal  kdc_server;
    krb5_boolean zero_password;
    char * dir_of_cc_target;     
    
    options.opt = KRB5_DEFAULT_OPTIONS;
    options.lifetime = KRB5_DEFAULT_TKT_LIFE;
    options.rlife =0; 
    options.princ =0;	

    params = (char **) xcalloc (2, sizeof (char *));
    params[1] = NULL;


    unsetenv ("KRB5_CONFIG");

    retval = krb5_init_secure_context(&ksu_context);
    if (retval) {
        com_err(argv[0], retval, "while initializing krb5");
	exit(1);
    }

    if (strrchr(argv[0], '/'))
	argv[0] = strrchr(argv[0], '/')+1;
    prog_name = argv[0];
    if (strlen (prog_name) > 50) {
	/* this many chars *after* last / ?? */
	com_err(prog_name, 0, "program name too long - quitting to avoid triggering system logging bugs");
	exit (1);
    }


#ifndef LOG_NDELAY
#define LOG_NDELAY 0
#endif
    
#ifndef LOG_AUTH /* 4.2 syslog */
    openlog(prog_name, LOG_PID|LOG_NDELAY);
#else
    openlog(prog_name, LOG_PID | LOG_NDELAY, LOG_AUTH);
#endif /* 4.2 syslog */
    
      
    if (( argc == 1) || (argv[1][0] == '-')){
	target_user = xstrdup("root");
	pargc = argc;
	pargv = argv;
    } else {
	target_user = xstrdup(argv[1]);
	pargc = argc -1;
	
	if ((pargv =(char **) calloc(pargc +1,sizeof(char *)))==NULL){
	    com_err(prog_name, errno, "while allocating memory");
	    exit(1);
	}
	
	pargv[pargc] = NULL;
	pargv[0] = argv[0];
	
	for(i =1; i< pargc; i ++){
	    pargv[i] = argv[i + 1];
	}
    }
    
    if (krb5_seteuid (ruid)) {
	com_err (prog_name, errno, "while setting euid to source user");
	exit (1);
    }
    while(!done && ((option = getopt(pargc, pargv,"n:c:r:a:zZDfpkql:e:")) != -1)){
	switch (option) {
	case 'r':
	    options.opt |= KDC_OPT_RENEWABLE;
	    if (strlen (optarg) >= 14)
		optarg = "bad-time";
	    retval = krb5_string_to_deltat(optarg, &options.rlife);
	    if (retval != 0 || options.rlife == 0) {
		fprintf(stderr, "Bad lifetime value (%s hours?)\n", optarg);
		errflg++;
	    }
	    break;
	case 'a':
            /* when integrating this remember to pass in pargc, pargv and
               take care of params argument */
	    optind --;	
	    if (auth_debug){printf("Before get_params optind=%d\n", optind);}
	    
            if ((retval = get_params( & optind, pargc, pargv, &params))){
                com_err(prog_name, retval, "when gathering parameters");
                errflg++;
            }
            if(auth_debug){ printf("After get_params optind=%d\n", optind);}
	    done = 1;
            break;
	case 'p':
	    options.opt |= KDC_OPT_PROXIABLE;
	    break;
	case 'f':
	    options.opt |= KDC_OPT_FORWARDABLE;
	    break;
	case 'k':
	    keep_target_cache =1;
	    break;
	case 'q':
	    quiet =1;
	    break;
        case 'l':
	    if (strlen (optarg) >= 14)
		optarg = "bad-time";
	    retval = krb5_string_to_deltat(optarg, &options.lifetime);
	    if (retval != 0 || options.lifetime == 0) {
		fprintf(stderr, "Bad lifetime value (%s hours?)\n", optarg);
		errflg++;
	    }
	    break;
	case 'n': 
	    if ((retval = krb5_parse_name(ksu_context, optarg, &client))){
		com_err(prog_name, retval, "when parsing name %s", optarg); 
		errflg++;
	    }	
	    
    	    options.princ = 1;
	    
	    break;
#ifdef DEBUG
	case 'D':
	    auth_debug = 1;	
	    break;
#endif
	case 'z':
	    some_rest_copy = 1;	
	    if(all_rest_copy) {  	
		fprintf(stderr, 
			"-z option is mutually exclusive with -Z.\n"); 
		errflg++;
	    }	
	    break;	
	case 'Z':
	    all_rest_copy = 1;	
	    if(some_rest_copy) {  	
		fprintf(stderr, 
			"-Z option is mutually exclusive with -z.\n"); 
		errflg++;
	    } 	
	    break;	
	case 'c':
	    if (cc_source_tag == NULL) {
		cc_source_tag = xstrdup(optarg);
		if ( strchr(cc_source_tag, ':')){
		    cc_source_tag_tmp = strchr(cc_source_tag, ':') + 1;
		    
		    if( stat( cc_source_tag_tmp, &st_temp)){
			com_err (prog_name, errno,
				 "while looking for credentials file %s",
				 cc_source_tag_tmp);
			exit (1);
		    }
		}
		else { 
		    fprintf(stderr,"malformed credential cache name %s\n",
			    cc_source_tag); 
		    errflg++;
		}
		
	    } else {
		fprintf(stderr, "Only one -c option allowed\n");
		errflg++;
	    }
	    break;
	case 'e': 
	    cmd = xstrdup(optarg);
            if(auth_debug){printf("Before get_params optind=%d\n", optind);}
            if ((retval = get_params( & optind, pargc, pargv, &params))){
                com_err(prog_name, retval, "when gathering parameters");
                errflg++;
            }
            if(auth_debug){printf("After get_params optind=%d\n", optind);}
            done = 1;

            if (auth_debug){
                fprintf(stderr,"Command to be executed: %s\n", cmd);
            }
            break;
	case '?':
	default:
	    errflg++;
	    break;
	}
    }

    if (errflg) {
	usage();
	exit(2);
    }

    if (optind != pargc ){
        usage();
        exit(2);
    }

    if (auth_debug){	
	for(j=1; params[j] != NULL; j++){
	    fprintf (stderr,"params[%d]= %s\n", j,params[j]);
	}
    }	

    /***********************************/
    source_user = getlogin(); /*checks for the the login name in /etc/utmp*/
    
    /* verify that that the user exists and get his passwd structure */
    
    if (source_user == NULL ||(pwd = getpwnam(source_user)) == NULL ||
	pwd->pw_uid != ruid){
	pwd = getpwuid(ruid);
    }
    
    if (pwd == NULL) {
	fprintf(stderr, "ksu: who are you?\n");
	exit(1);
    }
    if (pwd->pw_uid != ruid) {
	fprintf (stderr, "Your uid doesn't match your passwd entry?!\n");
	exit (1);
    }
    /* Okay, now we have *some* passwd entry that matches the
       current real uid.  */
    
    /* allocate space and copy the usernamane there */        
    source_user = xstrdup(pwd->pw_name);
    source_uid = pwd->pw_uid;
    source_gid = pwd->pw_gid;
    
    
    if (!strcmp(SOURCE_USER_LOGIN, target_user)){
	target_user = xstrdup (source_user);			
    }
    
    if ((target_pwd = getpwnam(target_user)) == NULL){ 
	fprintf(stderr, "ksu: unknown login %s\n", target_user); 
	exit(1);
    }
    target_uid = target_pwd->pw_uid;
    target_gid = target_pwd->pw_gid;
    
    init_auth_names(target_pwd->pw_dir);
    
    /***********************************/
    
    if (cc_source_tag == NULL){
	cc_source_tag = krb5_cc_default_name(ksu_context);
	cc_source_tag_tmp = strchr(cc_source_tag, ':');
	if (cc_source_tag_tmp == 0)
	    cc_source_tag_tmp = cc_source_tag;
	else
	    cc_source_tag_tmp++;
    }
    
    /* get a handle for the cache */      
    if ((retval = krb5_cc_resolve(ksu_context, cc_source_tag, &cc_source))){
	com_err(prog_name, retval,"while getting source cache");    
	exit(1);
    }
    
    if (((retval = krb5_cc_set_flags(ksu_context,  cc_source, 0x0)) != 0)
	&& (retval != KRB5_FCC_NOFILE)) {
	    com_err(prog_name, retval, "while opening ccache");
	    exit(1);
    }
    if ((retval = get_best_princ_for_target(ksu_context, source_uid,
					    target_uid, source_user, 
					    target_user, cc_source, 
					    &options, cmd, localhostname, 
					    &client, &hp))){
	com_err(prog_name,retval, "while selecting the best principal"); 
	exit(1);
    }
    
    /* We may be running as either source or target, depending on
       what happened; become source.*/
    if ( geteuid() != source_uid) {
	if (krb5_seteuid(0) || krb5_seteuid(source_uid) ) {
	    com_err(prog_name, errno, "while returning to source uid after finding best principal");
	    exit(1);
	}
    }
    
    if (auth_debug){
	if (hp){	
	    fprintf(stderr,
		    "GET_best_princ_for_target result: NOT AUTHORIZED\n");
	}else{
	    fprintf(stderr,
		    "GET_best_princ_for_target result-best principal ");
	    plain_dump_principal (ksu_context, client);
	    fprintf(stderr,"\n");
	}
    }
    
    if (hp){	
	if (gb_err) fprintf(stderr, "%s", gb_err);
	fprintf(stderr,"account %s: authorization failed\n",target_user);
	exit(1);
    }
    
    if (cc_target_tag == NULL) {
	
	cc_target_tag = (char *)xcalloc(KRB5_SEC_BUFFSIZE ,sizeof(char));
	/* make sure that the new ticket file does not already exist
	   This is run as source_uid because it is reasonable to
	   require the source user to have write to where the target
	   cache will be created.*/
	
	do {
	    sprintf(cc_target_tag, "%s%ld.%d",
		    KRB5_SECONDARY_CACHE,
		    (long) target_uid, gen_sym());
	    cc_target_tag_tmp = strchr(cc_target_tag, ':') + 1;
	    
	}while ( !stat ( cc_target_tag_tmp, &st_temp)); 
    }
    
    
    dir_of_cc_target = get_dir_of_file(cc_target_tag_tmp);
    
    if (access(dir_of_cc_target, R_OK | W_OK )){
	fprintf(stderr,
		"%s does not have correct permissions for %s\n", 
		source_user, cc_target_tag); 
	exit(1); 	
    }
    
    if (auth_debug){	
	fprintf(stderr, " source cache =  %s\n", cc_source_tag); 
	fprintf(stderr, " target cache =  %s\n", cc_target_tag); 
    }
    
    /* 
       Only when proper authentication and authorization
       takes place, the target user becomes the owner of the cache.         
       */           
    
    /* we continue to run as source uid until
       the middle of the copy, when becomewe become the target user
       The cache is owned by the target user.*/
    
	
    /* if root ksu's to a regular user, then      
       then only the credentials for that particular user 
       should be copied */            
    
    if ((source_uid == 0) && (target_uid != 0)) {
	
	if ((retval = krb5_ccache_copy_restricted(ksu_context,  cc_source,
						  cc_target_tag, client, 
						  &cc_target, &stored, 
						  target_uid))){
	    com_err (prog_name, retval, 
		     "while copying cache %s to %s",
		     krb5_cc_get_name(ksu_context, cc_source),cc_target_tag);
	    exit(1);
	}
	
    } else {
	if ((retval = krb5_ccache_copy(ksu_context, cc_source, cc_target_tag,
				       client,&cc_target, &stored, target_uid))) {
	    com_err (prog_name, retval, 
		     "while copying cache %s to %s",
		     krb5_cc_get_name(ksu_context, cc_source),
		     cc_target_tag);
	    exit(1);
	}
	
    }
    
    /* Become root for authentication*/
    
    if (krb5_seteuid(0)) {
	com_err(prog_name, errno, "while reclaiming root uid");
	exit(1);
    }
    
    if ((source_uid == 0) || (target_uid == source_uid)){
#ifdef GET_TGT_VIA_PASSWD
	if ((!all_rest_copy) && options.princ && (stored == FALSE)){
	    if ((retval = ksu_tgtname(ksu_context, 
				       krb5_princ_realm (ksu_context, client),
				       krb5_princ_realm(ksu_context, client),
				       &kdc_server))){
		com_err(prog_name, retval,
			"while creating tgt for local realm");
		sweep_up(ksu_context, cc_target);
		exit(1);
	    }
	    
	    fprintf(stderr,"WARNING: Your password may be exposed if you enter it here and are logged\n");
	    fprintf(stderr,"         in remotely using an unsecure (non-encrypted) channel.\n");
	    if (krb5_get_tkt_via_passwd (ksu_context, &cc_target, client,
					 kdc_server, &options, 
					 &zero_password) == FALSE){
		
		if (zero_password == FALSE){  
		    fprintf(stderr,"Goodbye\n");
		    sweep_up(ksu_context, cc_target);
		    exit(1);
		}
		
		fprintf(stderr,
			"Could not get a tgt for ");    
		plain_dump_principal (ksu_context, client);
		fprintf(stderr, "\n");    
		
	    }
	}
#endif /* GET_TGT_VIA_PASSWD */
    }
    
    /* if the user is root or same uid then authentication is not neccesary,
       root gets in automatically */   	
    
    if (source_uid && (source_uid != target_uid)) {
	char * client_name;
	
	auth_val = krb5_auth_check(ksu_context, client, localhostname, &options,
				   target_user,cc_target, &path_passwd, target_uid); 
	
	/* if Kerberos authentication failed then exit */     
	if (auth_val ==FALSE){
	    fprintf(stderr, "Authentication failed.\n");
	    syslog(LOG_WARNING,
		   "'%s %s' authentication failed for %s%s",
		   prog_name,target_user,source_user,ontty());
	    sweep_up(ksu_context, cc_target);
	    exit(1);
	}
	
#if 0
	/* At best, this avoids a single kdc request
	   It is hard to implement dealing with file permissions and
	   is unnecessary.  It is important
	   to properly handle races in chown if this code is ever re-enabled.
	   */
	/* cache the tickets if possible in the source cache */ 
	if (!path_passwd){ 	
	    
	    if ((retval = krb5_ccache_overwrite(ksu_context, cc_target, cc_source,
						client))){
		com_err (prog_name, retval,
			 "while copying cache %s to %s",
			 krb5_cc_get_name(ksu_context, cc_target),
			 krb5_cc_get_name(ksu_context, cc_source));
		sweep_up(ksu_context, cc_target);
		exit(1);
	    }
	    if (chown(cc_source_tag_tmp, source_uid, source_gid)){  
		com_err(prog_name, errno, 
			"while changing owner for %s",
			cc_source_tag_tmp);   
		exit(1);
	    }
	}
#endif /*0*/

	if ((retval = krb5_unparse_name(ksu_context, client, &client_name))) {
	    com_err (prog_name, retval, "When unparsing name");
	    sweep_up(ksu_context, cc_target);
	    exit(1);
	}     
	
	print_status("Authenticated %s\n", client_name);
	syslog(LOG_NOTICE,"'%s %s' authenticated %s for %s%s",
	       prog_name,target_user,client_name,
	       source_user,ontty());
	
	/* Run authorization as target.*/
	if (krb5_seteuid(target_uid)) {
	    com_err(prog_name, errno, "while switching to target for authorization check");
	    sweep_up(ksu_context, cc_target);
	    exit(1);
	}
	
	if ((retval = krb5_authorization(ksu_context, client,target_user,
					 cmd, &authorization_val, &exec_cmd))){
	    com_err(prog_name,retval,"while checking authorization");
	    krb5_seteuid(0); /*So we have some chance of sweeping up*/
	    sweep_up(ksu_context, cc_target);
	    exit(1);
	}
	
	if (krb5_seteuid(0)) {
	    com_err(prog_name, errno, "while switching back from  target after authorization check");
	    sweep_up(ksu_context, cc_target);
	    exit(1);
	}
	if (authorization_val == TRUE){

	    if (cmd) {	
		print_status(
		    "Account %s: authorization for %s for execution of\n",
		    target_user, client_name);
		print_status("               %s successful\n",exec_cmd);
		syslog(LOG_NOTICE,
		       "Account %s: authorization for %s for execution of %s successful",
		       target_user, client_name, exec_cmd);
		
	    }else{
		print_status(
		    "Account %s: authorization for %s successful\n",
			  	target_user, client_name);
		syslog(LOG_NOTICE,
		       "Account %s: authorization for %s successful",
		       target_user, client_name);
	    }
	}else {
	    if (cmd){ 	
		if (exec_cmd){ /* was used to pass back the error msg */
		    fprintf(stderr, "%s", exec_cmd );
		    syslog(LOG_WARNING, "%s",exec_cmd);
		}
		fprintf(stderr,
			"Account %s: authorization for %s for execution of %s failed\n",
			target_user, client_name, cmd );
		syslog(LOG_WARNING,
		       "Account %s: authorization for %s for execution of %s failed",
		       target_user, client_name, cmd );
		
	    }else{
		fprintf(stderr,
			"Account %s: authorization of %s failed\n",
			target_user, client_name);
		syslog(LOG_WARNING,
		       "Account %s: authorization of %s failed",
		       target_user, client_name);
		
	    }
	    
	    sweep_up(ksu_context, cc_target);
	    exit(1);
	}
    }
    
    if( some_rest_copy){ 
	if ((retval = krb5_ccache_filter(ksu_context, cc_target, client))){ 	
	    com_err(prog_name,retval,"while calling cc_filter");
	    sweep_up(ksu_context, cc_target);
	    exit(1);
	}
    }
    
    if (all_rest_copy){
	if ((retval = krb5_cc_initialize(ksu_context, cc_target, client))){  
	    com_err(prog_name, retval,
		    "while erasing target cache");    
	    exit(1);
	}
	
    }
    
    /* get the shell of the user, this will be the shell used by su */      
    target_pwd = getpwnam(target_user);
    
    if (target_pwd->pw_shell)
	shell = xstrdup(target_pwd->pw_shell);
    else {
	shell = _DEF_CSH;  /* default is cshell */   
    }
    
#ifdef HAVE_GETUSERSHELL
    
    /* insist that the target login uses a standard shell (root is omited) */ 
    
    if (!standard_shell(target_pwd->pw_shell) && source_uid) {
	fprintf(stderr, "ksu: permission denied (shell).\n");
	sweep_up(ksu_context, cc_target);
	exit(1);
    }
#endif /* HAVE_GETUSERSHELL */
    
    if (target_pwd->pw_uid){
	
	if(set_env_var("USER", target_pwd->pw_name)){
	    fprintf(stderr,"ksu: couldn't set environment variable USER\n");
	    sweep_up(ksu_context, cc_target);
	    exit(1);
	} 			
    }	
    
    if(set_env_var( "HOME", target_pwd->pw_dir)){
	fprintf(stderr,"ksu: couldn't set environment variable USER\n");
	sweep_up(ksu_context, cc_target);
	exit(1);
    } 			
    
    if(set_env_var( "SHELL", shell)){
	fprintf(stderr,"ksu: couldn't set environment variable USER\n");
	sweep_up(ksu_context, cc_target);
	exit(1);
    } 			
    
    /* set the cc env name to target */         	
    
    if(set_env_var( KRB5_ENV_CCNAME, cc_target_tag)){
	fprintf(stderr,"ksu: couldn't set environment variable %s\n",
		KRB5_ENV_CCNAME);
	sweep_up(ksu_context, cc_target);
	exit(1);
    } 			
    
    /* set permissions */
    if (setgid(target_pwd->pw_gid) < 0) {
	perror("ksu: setgid");
	sweep_up(ksu_context, cc_target);
	exit(1);
    }
    
    
    if (initgroups(target_user, target_pwd->pw_gid)) {
	fprintf(stderr, "ksu: initgroups failed.\n");
	sweep_up(ksu_context, cc_target);
	exit(1);
    }
    
    if ( ! strcmp(target_user, source_user)){ 			
	print_status("Leaving uid as %s (%ld)\n",
		     target_user, (long) target_pwd->pw_uid); 
    }else{
	print_status("Changing uid to %s (%ld)\n", 
		     target_user, (long) target_pwd->pw_uid); 
    }
    
#ifdef	HAVE_SETLUID
    /*
     * If we're on a system which keeps track of login uids, then
     * set the login uid. If this fails this opens up a problem on DEC OSF
     * with C2 enabled.
     */
    if (setluid((uid_t) pwd->pw_uid) < 0) {
	perror("setluid");
	sweep_up(ksu_context, cc_target);
	exit(1);
    }
#endif	/* HAVE_SETLUID */
    
    if (setuid(target_pwd->pw_uid) < 0) {
	perror("ksu: setuid");
	sweep_up(ksu_context, cc_target);
	exit(1);
    }   
    
    if (access( cc_target_tag_tmp, R_OK | W_OK )){
	com_err(prog_name, errno,
		"%s does not have correct permissions for %s, %s aborted",
		target_user, cc_target_tag_tmp, prog_name);
	exit(1);
    }
    
    if ( cc_source)
	krb5_cc_close(ksu_context, cc_source);
    
    if (cmd){
	if ((source_uid == 0) || (source_uid == target_uid )){
	    exec_cmd = cmd;
	}
	
	if( !exec_cmd){ 
	    fprintf(stderr,
		    "Internal error: command %s did not get resolved\n",cmd);
	    exit(1);	
	}
	
	params[0] = exec_cmd;
    }
    else{
	params[0] = shell;
    }
    
    if (auth_debug){		
	fprintf(stderr, "program to be execed %s\n",params[0]);
    }
    
    if( keep_target_cache ) {
	execv(params[0], params);
	com_err(prog_name, errno, "while trying to execv %s",
		params[0]);
	sweep_up(ksu_context, cc_target);
	exit(1);
    }else{
	statusp = 1;
	switch ((child_pid = fork())) {
	default:
	    if (auth_debug){
	 	printf(" The child pid is %ld\n", (long) child_pid);
        	printf(" The parent pid is %ld\n", (long) getpid());
	    }
            while ((ret_pid = waitpid(child_pid, &statusp, WUNTRACED)) != -1) {
		if (WIFSTOPPED(statusp)) {
		    child_pgrp = tcgetpgrp(1);
		    kill(getpid(), SIGSTOP);
		    tcsetpgrp(1, child_pgrp);
		    kill(child_pid, SIGCONT); 
		    statusp = 1;
		    continue;
		}
		break;
            }
	    if (auth_debug){
		printf("The exit status of the child is %d\n", statusp); 
	    }
	    if (ret_pid == -1) {
	    	com_err(prog_name, errno, "while calling waitpid");
	    }
	    sweep_up(ksu_context, cc_target);
	    exit (statusp);
	case -1:
	    com_err(prog_name, errno, "while trying to fork.");
	    sweep_up(ksu_context, cc_target);
	    exit (1);
	case 0:
	    execv(params[0], params);
	    com_err(prog_name, errno, "while trying to execv %s", params[0]);
	    exit (1);
	}
    }
}

#ifdef HAVE_GETUSERSHELL

int standard_shell(sh)
char *sh;
{
    register char *cp;
    char *getusershell();
    
    while ((cp = getusershell()) != NULL)
	if (!strcmp(cp, sh))
	    return (1);
    return (0);    
}
						  
#endif /* HAVE_GETUSERSHELL */

static char * ontty()
{
    char *p, *ttyname();
    static char buf[MAXPATHLEN + 4];
    
    buf[0] = 0;
    if ((p = ttyname(STDERR_FILENO))) {
	if (strlen (p) > MAXPATHLEN) {
	    fprintf (stderr, "terminal name %s too long\n", p);
	    exit (1);
	}
	sprintf(buf, " on %s", p);
    }
    return (buf);
}


static int set_env_var(name, value)
    char *name;
    char *value;
{
    char * env_var_buf;
    
    /* allocate extra two spaces, one for the = and one for the \0 */  
    env_var_buf = (char *) xcalloc(2 + strlen(name) + strlen(value),
				   sizeof(char)); 
    
    sprintf(env_var_buf,"%s=%s",name, value);  
    return putenv(env_var_buf);
    
}

static void sweep_up(context, cc)
    krb5_context context;
    krb5_ccache cc;
{
    krb5_error_code retval; 
    const char * cc_name;
    struct stat  st_temp;

    krb5_seteuid(0);
    if (krb5_seteuid(target_uid) < 0) {
	com_err(prog_name, errno,
		"while changing to target uid for destroying ccache");
	exit(1);
    }

    cc_name = krb5_cc_get_name(context, cc);
    if ( ! stat(cc_name, &st_temp)){
	if ((retval = krb5_cc_destroy(context, cc))){
	    com_err(prog_name, retval, 
		    "while destroying cache");   
	}
    }
}

/*****************************************************************
get_params is to be called for the -a option or -e option to
           collect all params passed in for the shell or for
           cmd.  An aray is returned containing all params.
           optindex is incremented accordingly and the first
           element in the returned array is reserved for the
           name of the command to be executed or the name of the
           shell.
*****************************************************************/

krb5_error_code
get_params(optindex, pargc, pargv, params)
    int *optindex;
    int pargc;
    char **pargv;
    char ***params;
{

    int i,j;
    char ** ret_params;
    int size = pargc - *optindex + 2;
    
    if ((ret_params = (char **) calloc(size, sizeof (char *)))== NULL ){
	return ENOMEM;
    }
    
    for (i = *optindex, j=1; i < pargc; i++,j++){
	ret_params[j] = pargv[i];
	*optindex = *optindex + 1;
    }
    
    ret_params[size-1] = NULL;
    *params = ret_params;
    return 0;
}

static
#ifdef HAVE_STDARG_H
void print_status( const char *fmt, ...)
#else
void print_status (va_alist)
     va_dcl
#endif
{
    va_list ap;
#ifndef HAVE_STDARG_H
    char *fmt;
    va_start (ap);
    fmt = va_arg (ap, char*);
    if (!quiet) vfprintf(stderr, fmt, ap);
    va_end(ap);
#else
    if (! quiet){
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
    }
#endif
}


char *get_dir_of_file(path)
    const char *path;
{
    char * temp_path;      
    char * ptr;

    temp_path =  xstrdup(path);
    
    if ((ptr = strrchr( temp_path, '/'))) {
	*ptr = '\0';  
    } else {
	free (temp_path);
	temp_path = xmalloc(MAXPATHLEN);
	if (temp_path)
	    getcwd(temp_path, MAXPATHLEN);
    }
    return temp_path;  
}

krb5_error_code
ksu_tgtname(context, server, client, tgtprinc)
    krb5_context context;
    const krb5_data *server, *client;
    krb5_principal *tgtprinc;
{
    return krb5_build_principal_ext(context, tgtprinc, client->length, client->data,
				    KRB5_TGS_NAME_SIZE, KRB5_TGS_NAME, 
				    server->length, server->data,
				    0);
}
