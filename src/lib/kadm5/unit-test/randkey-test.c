#include <kadm5/admin.h>
#include <com_err.h>
#include <stdio.h>
#include <krb5.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

#define	TEST_NUM    1000

int main()
{
     ovsec_kadm_ret_t ret;
     krb5_keyblock  *keys[TEST_NUM];
     krb5_principal tprinc;
     krb5_keyblock  *newkey;
     krb5_context context;
     void *server_handle;

     int    x, i;

     kadm5_init_krb5_context(&context);

     krb5_parse_name(context, "testuser", &tprinc);
     ret = ovsec_kadm_init("admin", "admin", "ovsec_adm/admin", 0,
			   OVSEC_KADM_STRUCT_VERSION,
			   OVSEC_KADM_API_VERSION_1, NULL,
			   &server_handle);
     if(ret != OVSEC_KADM_OK) {
	com_err("test", ret, "init");
	exit(2);
     }
     for(x = 0; x < TEST_NUM; x++) {
	ovsec_kadm_randkey_principal(server_handle, tprinc, &newkey);
	for(i = 0; i < x; i++) {
	    if (!memcmp(newkey->contents, keys[i]->contents, newkey->length))
		puts("match found");
	}
	krb5_copy_keyblock(context, newkey, &keys[x]);
	krb5_free_keyblock(context, newkey);
     }
     ovsec_kadm_destroy(server_handle);
     exit(0);
}

