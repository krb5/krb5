#include <kadm5/admin.h>
#include <com_err.h>
#include <stdio.h>
#include <krb5.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <unistd.h>
#include <netinet/in.h>
#include <kadm5/client_internal.h>
#include <string.h>

#define	TEST_NUM    25

int main()
{
     ovsec_kadm_ret_t ret;
     char   *cp;
     int    x;
     void *server_handle;
     kadm5_server_handle_t handle;

     for(x = 0; x < TEST_NUM; x++) {
	ret = ovsec_kadm_init("admin", "admin", "ovsec_adm/admin", 0,
			      OVSEC_KADM_STRUCT_VERSION,
			      OVSEC_KADM_API_VERSION_1,
			      &server_handle);
	if(ret != OVSEC_KADM_OK) {
	    com_err("test", ret, "init");
	    exit(2);
	}
	handle = (kadm5_server_handle_t) server_handle;
	cp = (char *) strdup(((char *) (strchr(handle->cache_name, ':')) + 1));
	ovsec_kadm_destroy(server_handle);
	if(access(cp, F_OK) == 0) {
	    puts("ticket cache not destroyed");
	    exit(2);
	}
	free(cp);
     }
     exit(0);
}

