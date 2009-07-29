#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gssapi.h>
#include <gssapi_krb5.h>

/*
 * Note: because of name canonicalization, the following tips may help:
 *
 * - Create a computer account FOO$
 * - Set the UPN to host/foo.domain (no sufix)
 * - Add a SPN of host/foo.domain
 * - Add host/foo.domain to the keytab
 *
 * For S4U2Proxy to work the TGT must be forwardable too.
 */

/*
 * Usage eg:
 * s4utest delegtest@WIN.MIT.EDU HOST@WIN-EQ7E4AA2WR8.win.mit.edu krb5.keytab
 */

int main(int argc, char *argv[])
{
    OM_uint32 minor, major;
    gss_ctx_id_t context_handle = GSS_C_NO_CONTEXT;
    gss_cred_id_t verifier_cred_handle = GSS_C_NO_CREDENTIAL;
    gss_name_t principal = GSS_C_NO_NAME, target = GSS_C_NO_NAME;
    gss_name_t src_name = GSS_C_NO_NAME;
    gss_cred_id_t delegated_cred_handle = GSS_C_NO_CREDENTIAL;
    gss_buffer_desc buf;
    gss_OID mech_type;
    OM_uint32 ret_flags, time_ret;

    if (argc != 4) {
	fprintf(stderr, "Usage: %s [user] [proxy-target] [keytab]\n", argv[0]);
	exit(1);
    }

    buf.value = argv[1];
    buf.length = strlen((char *)buf.value);

    major = gss_import_name(&minor, &buf, (gss_OID)GSS_KRB5_NT_ENTERPRISE_NAME, &principal);
    if (major) {
	fprintf(stderr, "gss_import_name(%s) failed: %08x\n", argv[1], major);
	goto out;
    }

    buf.value = argv[2];
    buf.length = strlen((char *)buf.value);

    major = gss_import_name(&minor, &buf, (gss_OID)GSS_C_NT_HOSTBASED_SERVICE, &target);
    if (major) {
	fprintf(stderr, "gss_import_name(%s) failed: %08x\n", argv[2], major);
	goto out;
    }

    major = krb5_gss_register_acceptor_identity(argv[3]);
    if (major) {
	fprintf(stderr, "krb5_gss_register_acceptor_identity(%s) failed: %08x\n", argv[3], major);
	goto out;
    }

    major = gss_krb5_add_sec_context_delegatee(&minor, &context_handle, target);
    if (major) {
	fprintf(stderr, "gss_krb5_add_sec_context_delegatee(%s) failed: %08x\n", argv[2], major);
	goto out;
    }

    major = gss_krb5_create_sec_context_for_principal(&minor,
	&context_handle,
	verifier_cred_handle,
	principal,
	GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG,
	0,
	&src_name,
	&mech_type,
	&ret_flags,
	&time_ret,
	&delegated_cred_handle);
    if (major) {
	fprintf(stderr, "gss_krb5_create_sec_context_for_principal failed: %08x\n", major);
	goto out;
    }

    buf.value = NULL;

    if (gss_display_name(&minor, src_name, &buf, NULL) == GSS_S_COMPLETE) {
	printf("Client name: %s\n", (char *)buf.value);
	gss_release_buffer(&minor, &buf);
	buf.value = NULL;
    }

    if (delegated_cred_handle != GSS_C_NO_CREDENTIAL) {
	gss_name_t cred_name = GSS_C_NO_NAME;
	OM_uint32 lifetime;
	gss_cred_usage_t usage;

	buf.value = NULL;

	if (gss_inquire_cred(&minor, delegated_cred_handle, &cred_name,
			     &lifetime, &usage, NULL) == GSS_S_COMPLETE &&
	    gss_display_name(&minor, cred_name, &buf, NULL) == GSS_S_COMPLETE)
	    printf("Credential principal name: %s\n", (char *)buf.value);

	gss_release_buffer(&minor, &buf);
	gss_release_name(&minor, &cred_name);
    }

out:
    gss_release_name(&minor, &principal);
    gss_release_name(&minor, &target);
    gss_release_name(&minor, &src_name);
    gss_delete_sec_context(&minor, &context_handle, NULL);
    gss_release_cred(&minor, &delegated_cred_handle);

    return major ? 1 : 0;
}

