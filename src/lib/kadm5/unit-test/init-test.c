#include <kadm5/admin.h>
#include <com_err.h>
#include <stdio.h>
#include <krb5.h>

int main()
{
     ovsec_kadm_ret_t ret;
     void *server_handle;

     ret = ovsec_kadm_init("admin", "admin", OVSEC_KADM_ADMIN_SERVICE, 0,
			   OVSEC_KADM_STRUCT_VERSION,
			   OVSEC_KADM_API_VERSION_1,
			   &server_handle);
     if (ret == OVSEC_KADM_RPC_ERROR)
	  exit(0);
     else if (ret != OVSEC_KADM_OK) {
	  com_err("init-test", ret, "while (hacked) initializing");
	  exit(1);
     }
     else {
	 fprintf(stderr, "Unexpected success while (hacked) initializing!\n");
	 (void) ovsec_kadm_destroy(server_handle);
	 exit(1);
     }
}
