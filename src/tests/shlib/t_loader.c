/* foo */
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "krb5/autoconf.h"
#include "krb5.h"
#include "gssapi/gssapi.h"
#define HAVE_DLOPEN 1

#ifdef HAVE_DLFCN_H
# include <dlfcn.h>
#endif
/* Solaris man page recommends link.h too */

/* lazy = 1 means resolve symbols later, 0 means now; any
   other flags we should be testing?  On Windows, maybe?

   Return value is the library handle.  On error, print a message and
   exit.  */
#define do_open(LIB,FLAGS) do_open_1(LIB,FLAGS,__FILE__,__LINE__)
static void *do_open_1(const char *libname, int lazy,
		       const char *file, int line);

/* Look up a function symbol in the library and return a pointer.

   The return value may need casting to the correct type.  On error,
   print a message and exit.  */
static void *get_sym(void *libhandle, const char *sym);
#define GET_FSYM(TYPE, LIB, NAME) ((TYPE) get_sym(LIB, NAME))
#define get_gfun(LIB, NAME) ((OM_uint32 KRB5_CALLCONV(*)()) get_sym(LIB, NAME))

/* Close dynamically-opened library.

   If the OS reports an error in doing so, print a message and
   exit.  */
#define do_close(X) do_close_1(X, __FILE__, __LINE__)
static void do_close_1(void *libhandle, const char *file, int line);

static inline const char *xbasename(const char *path)
{
    const char *p = strrchr(path, '/');
    if (p)
	return p+1;
    else
	return path;
}

#ifdef HAVE_DLOPEN

#ifdef _AIX
# define SHLIB_SUFFIX ".a"
#else
# define SHLIB_SUFFIX ".so"
#endif

static void *do_open_1(const char *libname, int lazy,
		       const char *file, int line)
{
    void *p;
    char *namebuf;

    file = xbasename(file);
    printf("from %s:%d: do_open(%s)\n", file, line, libname);
    namebuf = malloc(strlen(SHLIB_SUFFIX) + strlen(libname) + 4);
    if (namebuf == 0) {
	perror("malloc");
	exit(1);
    }
    strcpy(namebuf, "lib");
    strcat(namebuf, libname);
    strcat(namebuf, SHLIB_SUFFIX);

    p = dlopen(namebuf, lazy ? RTLD_LAZY : RTLD_NOW);
    if (p == 0) {
	fprintf(stderr, "dlopen of %s failed: %s\n", namebuf, dlerror());
	exit(1);
    }
    free(namebuf);
    return p;
}

#define SYM_PREFIX ""
static void *get_sym(void *libhandle, const char *symname)
{
    void *s;

    /* Bah.  Fix this later, if we care.  */
    assert(strlen(SYM_PREFIX) == 0);

    s = dlsym(libhandle, symname);
    if (s == 0) {
	fprintf(stderr, "symbol %s not found\n", symname);
	exit(1);
    }
    return s;
}

#define do_close(X) do_close_1(X, __FILE__, __LINE__)
static void do_close_1(void *libhandle, const char *file, int line)
{
    file = xbasename(file);
    printf("from %s:%d: do_close\n", file, line), fflush(stdout);
    if (dlclose(libhandle) != 0) {
	fprintf(stderr, "dlclose failed: %s\n", dlerror());
	exit(1);
    }
}

#elif defined _WIN32

static void *do_open(const char *libname, int lazy)
{
    /* To be written?  */
    abort();
}

static void *get_sym(void *libhandle, const char *symname)
{
    abort();
}

static void do_close(void *libhandle)
{
    abort();
}

#else

static void *do_open(const char *libname, int lazy)
{
    printf("don't know how to do dynamic loading here, punting\n");
    exit(0);
}

static void *get_sym(void *libhandle, const char *symname)
{
    abort();
}

static void do_close(void *libhandle)
{
    abort();
}

#endif

int main()
{
    void *celib, *k5lib, *gsslib, *celib2;

    celib = do_open("com_err", 0);
    k5lib = do_open("krb5", 0);
    gsslib = do_open("gssapi_krb5", 0);
    celib2 = do_open("com_err", 0);
    do_close(celib);
    do_close(k5lib);
    do_close(celib2);
    do_close(gsslib);

    celib = do_open("com_err", 0);
    k5lib = do_open("krb5", 0);
    gsslib = do_open("gssapi_krb5", 0);
    celib2 = do_open("com_err", 0);
    do_close(celib2);
    {
	typedef krb5_error_code KRB5_CALLCONV (*ict)(krb5_context *);
	typedef void KRB5_CALLCONV (*fct)(krb5_context);

	ict init_context = (ict) get_sym(k5lib, "krb5_init_context");
	fct free_context = (fct) get_sym(k5lib, "krb5_free_context");
	krb5_context ctx;
	krb5_error_code err;

	err = init_context(&ctx);
	if (err) {
	    fprintf(stderr, "error 0x%lx initializing context\n",
		    (unsigned long) err);
	    exit(1);
	}
	free_context(ctx);
    }
    celib2 = do_open("com_err", 0);
    do_close(celib);
    do_close(k5lib);
    do_close(celib2);
    do_close(gsslib);

    celib = do_open("com_err", 1);
    gsslib = do_open("gssapi_krb5", 1);
    {
	OM_uint32 KRB5_CALLCONV (*init_sec_context)(OM_uint32 *, gss_cred_id_t,
						    gss_ctx_id_t *, gss_name_t,
						    gss_OID,
						    OM_uint32, OM_uint32,
						    gss_channel_bindings_t,
						    gss_buffer_t, gss_OID *,
						    gss_buffer_t,
						    OM_uint32 *, OM_uint32 *)
	    = get_gfun(gsslib, "gss_init_sec_context");
	OM_uint32 KRB5_CALLCONV (*import_name)(OM_uint32 *, gss_buffer_t,
					       gss_OID, gss_name_t *)
	    = get_gfun(gsslib, "gss_import_name");
	OM_uint32 KRB5_CALLCONV (*release_buffer)(OM_uint32 *, gss_buffer_t)
	    = get_gfun(gsslib, "gss_release_buffer");
	OM_uint32 KRB5_CALLCONV (*release_name)(OM_uint32 *, gss_name_t *)
	    = get_gfun(gsslib, "gss_release_name");
	OM_uint32 KRB5_CALLCONV (*delete_sec_context)(OM_uint32 *,
						      gss_ctx_id_t *,
						      gss_buffer_t)
	    = get_gfun(gsslib, "gss_delete_sec_context");

	OM_uint32 gmaj, gmin;
	OM_uint32 retflags;
	gss_ctx_id_t gctx = GSS_C_NO_CONTEXT;
	gss_buffer_desc token;
	gss_name_t target;
	static gss_buffer_desc target_name_buf = {
	    9, "x@mit.edu"
	};
	static gss_OID_desc service_name = {
	    10, "\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x04"
	};

	gmaj = import_name(&gmin, &target_name_buf, &service_name, &target);
	if (gmaj != GSS_S_COMPLETE) {
	    fprintf(stderr,
		    "import_name reports error major 0x%lx minor 0x%lx(%ld)\n",
		    (unsigned long) gmaj, (unsigned long) gmin,
		    (signed long) gmin);
	    exit(1);
	}
	/* This will probably get different errors, depending on
	   whether we have tickets at the time.  Doesn't matter much,
	   we're ignoring the error and testing whether we're doing
	   cleanup properly.  (Though the internal cleanup needed in
	   the two cases might be different.)  */
	gmaj = init_sec_context(&gmin, GSS_C_NO_CREDENTIAL, &gctx, target,
				GSS_C_NULL_OID, 0, 0, NULL, GSS_C_NO_BUFFER,
				NULL, &token, &retflags, NULL);
	/* Ignore success/failure indication.  */
	if (token.length)
	    release_buffer(&gmin, &token);
	release_name(&gmin, &target);
	if (gctx != GSS_C_NO_CONTEXT)
	    delete_sec_context(&gmin, gctx, GSS_C_NO_BUFFER);
    }
    do_close(celib);
    do_close(gsslib);

    return 0;
}
