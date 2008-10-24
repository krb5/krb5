/* Can't include krb5.h here, or k5-int.h which includes it, because
   krb5.h needs to be generated with error tables, after util/et,
   which builds after this directory.  */
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "k5-err.h"

#include "k5-thread.h"
#include "k5-platform.h"
#include "supp-int.h"

#ifdef __APPLE__
#import <CoreFoundation/CoreFoundation.h>
#include "kim_library_private.h"
#endif

/* It would be nice to just use error_message() always.  Pity that
   it's defined in a library that depends on this one, and we're not
   allowed to make circular dependencies.  */
/* We really want a rwlock here, since we should hold it while calling
   the function and copying out its results.  But I haven't
   implemented shims for rwlock yet.  */
static k5_mutex_t krb5int_error_info_support_mutex =
    K5_MUTEX_PARTIAL_INITIALIZER;
static const char *(KRB5_CALLCONV *fptr)(long); /* = &error_message */

int
krb5int_err_init (void)
{
    return k5_mutex_finish_init (&krb5int_error_info_support_mutex);
}
#define initialize()	krb5int_call_thread_support_init()
#define lock()		k5_mutex_lock(&krb5int_error_info_support_mutex)
#define unlock()	k5_mutex_unlock(&krb5int_error_info_support_mutex)

void
krb5int_set_error (struct errinfo *ep, long code, const char *fmt, ...)
{
    va_list args;
    va_start (args, fmt);
    krb5int_vset_error (ep, code, fmt, args);
    va_end (args);
}

void
krb5int_vset_error (struct errinfo *ep, long code,
		    const char *fmt, va_list args)
{
    char *p;
    char *str = NULL;
    va_list args2;

    if (ep->msg && ep->msg != ep->scratch_buf) {
	free ((char *) ep->msg);
	ep->msg = NULL;
    }
    ep->code = code;
    va_copy(args2, args);
    if (vasprintf(&str, fmt, args2) >= 0 && str != NULL) {
	va_end(args2);
	ep->msg = str;
	return;
    }
    va_end(args2);
    /* Allocation failure?  */
    vsnprintf(ep->scratch_buf, sizeof(ep->scratch_buf), fmt, args);
    /* Try again, just in case.  */
    p = strdup(ep->scratch_buf);
    ep->msg = p ? p : ep->scratch_buf;
}

static inline char * 
krb5int_get_localized_error (const char *string) 
{
    char *loc_string = NULL;
    
#ifdef __APPLE__
    if (kim_library_allow_home_directory_access ()) {
        CFStringRef cfstring = NULL;
        
        cfstring = CFStringCreateWithCStringNoCopy(kCFAllocatorDefault,
                                                   string, 
                                                   kCFStringEncodingUTF8,
                                                   kCFAllocatorNull);
        if (cfstring) {
            CFStringRef loc_cfstring = NULL;
            
            loc_cfstring = CFCopyLocalizedString(cfstring, "");
            if (loc_cfstring) {
                char *loc_ptr = NULL;
                
                /* check if loc_cfstring is a UTF8 string internally 
                 * so we can avoid using CFStringGetMaximumSizeForEncoding */
                loc_ptr = (char *) CFStringGetCStringPtr(loc_cfstring, 
                                                         kCFStringEncodingUTF8);
                if (loc_ptr) {
                    loc_string = strdup(loc_ptr);
                    
                } else {
                    CFIndex len = 0;
                    
                    len = CFStringGetMaximumSizeForEncoding(CFStringGetLength(loc_cfstring),
                                                            kCFStringEncodingUTF8) + 1;
                    
                    loc_string = malloc(len);
                    if (loc_string) {
                        if (!CFStringGetCString(loc_cfstring, loc_string, 
                                                len, kCFStringEncodingUTF8)) {
                            /* Conversion to C string failed. */
                            free (loc_string);
                            loc_string = NULL;
                        }
                    }
                }
                
                CFRelease(loc_cfstring);
            }
            
            CFRelease(cfstring);
        }
    }
#endif
    return loc_string;
}

const char *
krb5int_get_error (struct errinfo *ep, long code)
{
    char *r, *r2;
    if (code == ep->code && ep->msg) {
	r = strdup(ep->msg);
	if (r == NULL) {
	    strlcpy(ep->scratch_buf, _("Out of memory"),
		    sizeof(ep->scratch_buf));
	    r = ep->scratch_buf;
	}
	return r;
    }
    if (initialize() != 0) {
	strncpy(ep->scratch_buf, _("Kerberos library initialization failure"),
		sizeof(ep->scratch_buf));
	ep->scratch_buf[sizeof(ep->scratch_buf)-1] = 0;
	ep->msg = NULL;
	return ep->scratch_buf;
    }
    if (lock())
	goto no_fptr;
    if (fptr == NULL) {
	unlock();
    no_fptr:
#ifdef HAVE_STRERROR_R
	if (strerror_r (code, ep->scratch_buf, sizeof(ep->scratch_buf)) == 0) {
	    char *p = strdup(ep->scratch_buf);
	    if (p)
		return p;
	    return ep->scratch_buf;
	}
	/* If strerror_r didn't work with the 1K buffer, we can try a
	   really big one.  This seems kind of gratuitous though.  */
#define BIG_ERR_BUFSIZ 8192
	r = malloc(BIG_ERR_BUFSIZ);
	if (r) {
	    if (strerror_r (code, r, BIG_ERR_BUFSIZ) == 0) {
		r2 = realloc (r, 1 + strlen(r));
		if (r2)
		    return r2;
		return r;
	    }
	    free (r);
	}
#endif
	r = strerror (code);
	if (r) {
	    if (strlen (r) < sizeof (ep->scratch_buf)
		|| (r2 = strdup (r)) == NULL) {
		strncpy (ep->scratch_buf, r, sizeof(ep->scratch_buf));
		return ep->scratch_buf;
	    } else
		return r2;
	}
    format_number:
	snprintf (ep->scratch_buf, sizeof(ep->scratch_buf),
		  _("error %ld"), code);
	return ep->scratch_buf;
    }
    r = (char *) fptr(code);
    if (r == NULL) {
	unlock();
	goto format_number;
    }

    r2 = krb5int_get_localized_error(r);
    
    if (r2 == NULL) {
        r2 = strdup(r);
    }

    if (r2 == NULL) {
	strncpy(ep->scratch_buf, r, sizeof(ep->scratch_buf));
	unlock();
	return ep->scratch_buf;
    } else {
	unlock();
	return r2;
    }
}

void
krb5int_free_error (struct errinfo *ep, const char *msg)
{
    if (msg != ep->scratch_buf)
	free ((char *) msg);
}

void
krb5int_clear_error (struct errinfo *ep)
{
    krb5int_free_error (ep, ep->msg);
    ep->msg = NULL;
}

void
krb5int_set_error_info_callout_fn (const char *(KRB5_CALLCONV *f)(long))
{
    initialize();
    if (lock() == 0) {
	fptr = f;
	unlock();
    }
}
