#define _(X) (X)
#define KRB5_CALLCONV
struct errinfo {
    long code;
    const char *msg;
    char scratch_buf[1024];
};

void
krb5int_set_error (struct errinfo *ep,
		   long code,
		   const char *fmt, ...);
void
krb5int_vset_error (struct errinfo *ep, long code,
		    const char *fmt, va_list args);
char *
krb5int_get_error (struct errinfo *ep, long code);
void
krb5int_free_error (struct errinfo *ep, char *msg);
void
krb5int_clear_error (struct errinfo *ep);
void
krb5int_set_error_info_callout_fn (const char *(KRB5_CALLCONV *f)(long));
