#include <stdio.h>
#include <kadm5/admin.h>

int main(int argc, char **argv)
{
     ovsec_kadm_ret_t ret;
     void *server_handle;
     char **names;
     int count, princ, i;

     if (argc != 3) {
	  fprintf(stderr, "Usage: %s [-princ|-pol] exp\n", argv[0]);
	  exit(1);
     }
     princ = (strcmp(argv[1], "-princ") == 0);
     
     ret = ovsec_kadm_init("admin", "admin", OVSEC_KADM_ADMIN_SERVICE, 0,
			   OVSEC_KADM_STRUCT_VERSION,
			   OVSEC_KADM_API_VERSION_1,
			   &server_handle);
     if (ret != OVSEC_KADM_OK) {
	  com_err("iter-test", ret, "while initializing");
	  exit(1);
     }

     if (princ)
	  ret = ovsec_kadm_get_principals(server_handle, argv[2], &names,
					  &count);
     else
	  ret = ovsec_kadm_get_policies(server_handle, argv[2],
					&names, &count);
					
     if (ret != OVSEC_KADM_OK) {
	  com_err("iter-test", ret, "while retrieving list");
	  exit(1);
     }

     for (i = 0; i < count; i++)
	  printf("%d: %s\n", i, names[i]);

     ovsec_kadm_free_name_list(server_handle, names, count);

     (void) ovsec_kadm_destroy(server_handle);

     return 0;
}

