#undef USE_KADM5_API_VERSION
#include <kadm5/admin.h>
#include <com_err.h>
#include <stdio.h>
#include <stdlib.h>
#include <krb5.h>

int main()
{
     kadm5_ret_t ret;
     void *server_handle;
     kadm5_config_params params;

     memset(&params, 0, sizeof(params));
     params.mask |= KADM5_CONFIG_NO_AUTH;
     ret = kadm5_init("admin", "admin", NULL, &params,
		      KADM5_STRUCT_VERSION, KADM5_API_VERSION_2,
		      &server_handle);
     if (ret == KADM5_RPC_ERROR)
	  exit(0);
     else if (ret != 0) {
	  com_err("init-test", ret, "while initializing without auth");
	  exit(1);
     } else {
	 fprintf(stderr, "Unexpected success while initializing without auth!\n");
	 (void) kadm5_destroy(server_handle);
	 exit(1);
     }
}
