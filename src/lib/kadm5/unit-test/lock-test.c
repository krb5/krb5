#if USE_KADM5_API_VERSION == 1
#undef USE_KADM5_API_VERSION
#define USE_KADM5_API_VERSION 2
#endif

#include <stdio.h>
#include <krb5.h>
#include <kadm5/admin.h>
#include <kadm5/adb.h>

char *whoami;

static void usage()
{
     fprintf(stderr,
	     "Usage: %s {shared|exclusive|permanent|release|"
	     "get name|wait} ...\n", whoami);
     exit(1);
}

int main(int argc, char **argv)
{
     osa_adb_ret_t ret;
     osa_adb_policy_t policy_db;
     osa_policy_ent_t entry;
     krb5_context context;
     kadm5_config_params params;
     krb5_error_code kret;

     whoami = argv[0];

     kret = krb5_init_context(&context);
     if (kret) {
	 com_err(whoami, kret, "while initializing krb5");
	 exit(1);
     }

     initialize_ovk_error_table();
     initialize_adb_error_table();
     initialize_ovku_error_table();

     params.mask = 0;
     ret = kadm5_get_config_params(context, NULL, NULL, &params,
				   &params);
     if (ret) {
	  com_err(whoami, ret, "while retrieving configuration parameters");
	  exit(1);
     }
     if (! (params.mask & KADM5_CONFIG_ADBNAME)) {
	  com_err(whoami, KADM5_BAD_SERVER_PARAMS,
		  "while retrieving configuration parameters");
	  exit(1);
     }

     ret = osa_adb_open_policy(&policy_db, &params);
     if (ret != OSA_ADB_OK) {
	  com_err(whoami, ret, "while opening database");
	  exit(1);
     }

     argc--; argv++;
     while (argc) {
	  if (strcmp(*argv, "shared") == 0) {
	       ret = osa_adb_get_lock(policy_db, OSA_ADB_SHARED);
	       if (ret != OSA_ADB_OK)
		    com_err(whoami, ret, "while getting shared lock");
	       else
		    printf("shared\n");
	  } else if (strcmp(*argv, "exclusive") == 0) {
	       ret = osa_adb_get_lock(policy_db, OSA_ADB_EXCLUSIVE);
	       if (ret != OSA_ADB_OK)
		    com_err(whoami, ret, "while getting exclusive lock");
	       else
		    printf("exclusive\n");
	  } else if (strcmp(*argv, "permanent") == 0) {
	       ret = osa_adb_get_lock(policy_db, OSA_ADB_PERMANENT);
	       if (ret != OSA_ADB_OK)
		    com_err(whoami, ret, "while getting permanent lock");
	       else
		    printf("permanent\n");
	  } else if (strcmp(*argv, "release") == 0) {
	       ret = osa_adb_release_lock(policy_db);
	       if (ret != OSA_ADB_OK)
		    com_err(whoami, ret, "while releasing lock");
	       else
		    printf("released\n");
	  } else if (strcmp(*argv, "get") == 0) {
	       argc--; argv++;
	       if (!argc) usage();
	       if ((ret = osa_adb_get_policy(policy_db, *argv,
					     &entry)) != OSA_ADB_OK) {
		    com_err(whoami, ret, "while getting policy");
	       } else {
		    printf("retrieved\n");
		    osa_free_policy_ent(entry);
	       }
	  } else if (strcmp(*argv, "wait") == 0) {
	       getchar();
	  } else {
	       fprintf(stderr, "%s: Invalid argument \"%s\"\n",
		       whoami, *argv);
	       usage();
	  }

	  argc--; argv++;
     }

     ret = osa_adb_close_policy(policy_db);
     if (ret != OSA_ADB_OK) {
	  com_err(whoami, ret, "while closing database");
	  exit(1);
     }

     return 0;
}
