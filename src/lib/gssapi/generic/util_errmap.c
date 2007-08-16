#include "gssapiP_generic.h"
#include <string.h>
#include <unistd.h>

/* The mapping table is 0-based, but let's export codes that are
   1-based, keeping 0 for errors or unknown errors.

   The elements in the mapping table currently have separate copies of
   each OID stored.  This is a bit wasteful, but we are assuming the
   table isn't likely to grow very large.  */

struct mecherror {
    gss_OID_desc mech;
    OM_uint32 code;
};

static inline int
mecherror_cmp(struct mecherror m1, struct mecherror m2)
{
    if (m1.code < m2.code)
	return -1;
    if (m1.code > m2.code)
	return 1;
    if (m1.mech.length < m2.mech.length)
	return -1;
    if (m1.mech.length > m2.mech.length)
	return 1;
    if (m1.mech.length == 0)
	return 0;
    return memcmp(m1.mech.elements, m2.mech.elements, m1.mech.length);
}

static inline int
mecherror_copy(struct mecherror *dest, struct mecherror src)
{
    *dest = src;
    if (src.mech.length) {
	dest->mech.elements = malloc(src.mech.length);
	if (dest->mech.elements == NULL)
	    return ENOMEM;
    }
    memcpy(dest->mech.elements, src.mech.elements, src.mech.length);
    return 0;
}

static void
mecherror_print(struct mecherror value, FILE *f)
{
    OM_uint32 minor;
    gss_buffer_desc str;
    static const struct {
	const char *oidstr, *name;
    } mechnames[] = {
	{ "{ 1 2 840 113554 1 2 2 }", "krb5-new" },
	{ "{ 1 3 5 1 5 2 }", "krb5-old" },
	{ "{ 1 2 840 48018 1 2 2 }", "krb5-microsoft" },
	{ "{ 1 3 6 1 5 5 2 }", "spnego" },
    };
    int i;

    fprintf(f, "%lu@", (unsigned long) value.code);

    if (value.mech.length == 0) {
	fprintf(f, "(com_err)");
	return;
    }
    if (generic_gss_oid_to_str(&minor, &value.mech, &str)) {
	fprintf(f, "(error in conversion)");
	return;
    }
    /* Note: generic_gss_oid_to_str returns a null-terminated string.  */
    for (i = 0; i < sizeof(mechnames)/sizeof(mechnames[0]); i++) {
	if (!strcmp(str.value, mechnames[i].oidstr) && mechnames[i].name != 0) {
	    fprintf(f, "%s", mechnames[i].name);
	    break;
	}
    }
    if (i == sizeof(mechnames)/sizeof(mechnames[0]))
	fprintf(f, "%s", (char *) str.value);
    generic_gss_release_buffer(&minor, &str);
}

#include "errmap.h"
#include "krb5.h"		/* for KRB5KRB_AP_WRONG_PRINC */

static mecherrmap m;

int gssint_mecherrmap_init(void)
{
    int err;
    OM_uint32 n;

    err = mecherrmap_init(&m);
    if (err)
	return err;

    /* This is *so* gross.

       The RPC code depends on being able to recognize the "wrong
       principal" minor status return from the Kerberos mechanism.
       But a totally generic enumeration of status codes as they come
       up makes that impossible.  So "register" that status code
       early, and always with the same value.

       Of course, to make things worse, we're treating each mechanism
       OID separately, and there are three for Kerberos.  */
    {
	/* Declare here to avoid including header files not generated
	   yet.  */
	extern const gss_OID_desc *const gss_mech_krb5;
	extern const gss_OID_desc *const gss_mech_krb5_old;
	extern const gss_OID_desc *const gss_mech_krb5_wrong;

	const OM_uint32 wrong_princ = (OM_uint32) KRB5KRB_AP_WRONG_PRINC;

	n = gssint_mecherrmap_map(wrong_princ, gss_mech_krb5);
	if (n <= 0)
	    return ENOMEM;
	n = gssint_mecherrmap_map(wrong_princ, gss_mech_krb5_old);
	if (n <= 0)
	    return ENOMEM;
	n = gssint_mecherrmap_map(wrong_princ, gss_mech_krb5_wrong);
	if (n <= 0)
	    return ENOMEM;
    }

    return 0;
}

/* Currently the enumeration template doesn't handle freeing
   element storage when destroying the collection.  */
static int free_one(size_t i, struct mecherror value, void *p)
{
    if (value.mech.length && value.mech.elements)
	free(value.mech.elements);
    return 0;
}

void gssint_mecherrmap_destroy(void)
{
    mecherrmap_foreach(&m, free_one, NULL);
    mecherrmap_destroy(&m);
}

OM_uint32 gssint_mecherrmap_map(OM_uint32 minor, const gss_OID_desc * oid)
{
    struct mecherror me;
    int err, added;
    long idx;

    me.code = minor;
    me.mech = *oid;
    err = mecherrmap_find_or_append(&m, me, &idx, &added);
    if (err) {
	return 0;
    }
    return idx+1;
}

static gss_OID_desc no_oid = { 0, 0 };
OM_uint32 gssint_mecherrmap_map_errcode(OM_uint32 errcode)
{
    return gssint_mecherrmap_map(errcode, &no_oid);
}

int gssint_mecherrmap_get(OM_uint32 minor, gss_OID mech_oid,
			  OM_uint32 *mech_minor)
{
    struct mecherror me;
    int err;
    long size;

    if (minor == 0) {
	return EINVAL;
    }
    err = mecherrmap_size(&m, &size);
    if (err) {
	return err;
    }
    if (minor > size) {
	return EINVAL;
    }
    err = mecherrmap_get(&m, minor-1, &me);
    if (err) {
	return err;
    }
    *mech_oid = me.mech;
    *mech_minor = me.code;
    return 0;
}
