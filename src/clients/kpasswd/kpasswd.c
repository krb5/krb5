#include <stdio.h>
#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>

#include <krb5.h>

#define P1 "Enter new password: "
#define P2 "Enter it again: "

int main(int argc, char *argv[])
{
   krb5_error_code ret;
   krb5_context context;
   krb5_principal princ;
   char *pname;
   struct passwd *pwd;
   krb5_ccache ccache;
   krb5_get_init_creds_opt opts;
   krb5_creds creds;

   krb5_timestamp now;
   krb5_data ap_req;
   krb5_auth_context auth_context;
   char pw[1024];
   int pwlen;
   krb5_data chpw_req, chpw_rep;
   int result_code;
   krb5_data result_code_string, result_string;

   if (argc > 2) {
      fprintf(stderr, "usage: %s [principal]\n", argv[0]);
      exit(1);
   }

   pname = argv[1];

   if (ret = krb5_init_context(&context)) {
      com_err(argv[0], ret, "initializing kerberos library");
      exit(1);
   }

   krb5_init_ets(context);

   /* in order, use the first of:
      - a name specified on the command line
      - the principal name from an existing ccache
      - the name corresponding to the ruid of the process

      otherwise, it's an error.
      */

   if (pname) {
      if (ret = krb5_parse_name(context, pname, &princ)) {
	 com_err(argv[0], ret, "parsing client name");
	 exit(1);
      }
   } else if ((ret = krb5_cc_default(context, &ccache)) != KRB5_CC_NOTFOUND) {
      if (ret) {
	 com_err(argv[0], ret, "opening default ccache");
	 exit(1);
      }

      if (ret = krb5_cc_get_principal(context, ccache, &princ)) {
	 com_err(argv[0], ret, "getting principal from ccache");
	 exit(1);
      }

      if (ret = krb5_cc_close(context, ccache)) {
	 com_err(argv[0], ret, "closing ccache");
	 exit(1);
      }
   } else if (pwd = getpwuid(getuid())) {
      if (ret = krb5_parse_name(context, pwd->pw_name, &princ)) {
	 com_err(argv[0], ret, "parsing client name");
	 exit(1);
      }
   } else {
      com_err(argv[0], 0,
	      "no matching password entry while looking for username");
      exit(1);
   }

   krb5_get_init_creds_opt_init(&opts);
   krb5_get_init_creds_opt_set_tkt_life(&opts, 5*60);
   krb5_get_init_creds_opt_set_renew_life(&opts, 0);
   krb5_get_init_creds_opt_set_forwardable(&opts, 0);
   krb5_get_init_creds_opt_set_proxiable(&opts, 0);

   if (ret = krb5_get_init_creds_password(context, &creds, princ, NULL,
					  krb5_prompter_posix, NULL, 
					  0, "kadmin/changepw", &opts)) {
      if (ret == KRB5KRB_AP_ERR_BAD_INTEGRITY)
	 com_err(argv[0], 0,
		 "Password incorrect while getting initial ticket");
      else
	 com_err(argv[0], ret, "getting initial ticket");
      exit(1);
   }

   pwlen = sizeof(pw);
   if (ret = krb5_read_password(context, P1, P2, pw, &pwlen)) {
      com_err(argv[0], ret, "while reading password");
      exit(1);
   }

   if (ret = krb5_change_password(context, &creds, pw,
				  &result_code, &result_code_string,
				  &result_string)) {
      com_err(argv[0], ret, "changing password");
      exit(1);
   }

   if (result_code) {
      printf("%.*s%s%.*s\n",
	     result_code_string.length, result_code_string.data,
	     result_string.length?": ":"",
	     result_string.length, result_string.data);
      exit(2);
   }

   free(result_string.data);
   free(result_code_string.data);

   printf("Password changed.\n");
   exit(0);
}
