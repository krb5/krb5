/* -*- mode: c; indent-tabs-mode: nil -*- */
/*
 * lib/krb5/krb/trace.c
 *
 * Copyright 2009 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * k5trace implementation
 */

/* k5trace is defined in k5-int.h as a macro or static inline function,
 * and is called like so:
 *
 *   void k5trace(krb5_context context, const char *fmt, ...)
 *
 * Arguments may or may not be evaluated, so don't pass argument
 * expressions with side effects.  Tracing support and calls can be
 * explicitly compiled out with DISABLE_TRACING, but compile-time
 * support is enabled by default.  Tracing calls use a custom
 * formatter supporting the following format specifications:
 */

#include "k5-int.h"

#ifndef DISABLE_TRACING

static void subfmt(krb5_context context, struct k5buf *buf,
                   const char *fmt, ...);

/* Return a four-byte hex string from the first two bytes of a SHA-1 hash of a
 * byte array.  Return NULL on failure. */
static char *
hash_bytes(krb5_context context, const void *ptr, size_t len)
{
    krb5_checksum cksum;
    krb5_data d = make_data((void *) ptr, len);
    char *s = NULL;

    if (krb5_k_make_checksum(context, CKSUMTYPE_NIST_SHA, NULL, 0, &d,
                             &cksum) != 0)
        return NULL;
    if (cksum.length >= 2)
        (void) asprintf(&s, "%02X%02X", cksum.contents[0], cksum.contents[1]);
    krb5_free_checksum_contents(context, &cksum);
    return s;
}

static char *
trace_format(krb5_context context, const char *fmt, va_list ap)
{
    struct k5buf buf;
    krb5_error_code kerr;
    size_t len, i;
    int err;
    struct addrinfo *ai;
    const krb5_data *d;
    krb5_data data;
    char addrbuf[NI_MAXHOST], portbuf[NI_MAXSERV], tmpbuf[200], *str;
    const char *p;
    krb5_const_principal princ;
    const krb5_keyblock *keyblock;
    krb5_key key;
    const krb5_checksum *cksum;
    krb5_pa_data **padata;
    krb5_ccache ccache;
    krb5_keytab keytab;
    krb5_creds *creds;
    krb5_enctype *etypes, etype;

    krb5int_buf_init_dynamic(&buf);
    while (TRUE) {
        /* Advance to the next word in braces. */
        len = strcspn(fmt, "{");
        krb5int_buf_add_len(&buf, fmt, len);
        if (fmt[len] == '\0')
            break;
        fmt += len + 1;
        len = strcspn(fmt, "}");
        if (fmt[len] == '\0' || len > sizeof(tmpbuf) - 1)
            break;
        memcpy(tmpbuf, fmt, len);
        tmpbuf[len] = '\0';
        fmt += len + 1;

        /* Process the format word. */
        if (strcmp(tmpbuf, "int") == 0) {
            krb5int_buf_add_fmt(&buf, "%d", va_arg(ap, int));
        } else if (strcmp(tmpbuf, "long") == 0) {
            krb5int_buf_add_fmt(&buf, "%ld", va_arg(ap, long));
        } else if (strcmp(tmpbuf, "str") == 0) {
	    p = va_arg(ap, const char *);
	    krb5int_buf_add(&buf, (p == NULL) ? "(null)" : p);
        } else if (strcmp(tmpbuf, "lenstr") == 0) {
            len = va_arg(ap, size_t);
	    p = va_arg(ap, const char *);
            if (p == NULL && len != 0)
                krb5int_buf_add(&buf, "(null)");
            else
                krb5int_buf_add_len(&buf, p, len);
        } else if (strcmp(tmpbuf, "hexlenstr") == 0) {
            len = va_arg(ap, size_t);
	    p = va_arg(ap, const char *);
            if (p == NULL && len != 0)
                krb5int_buf_add(&buf, "(null)");
            else {
                for (i = 0; i < len; i++)
                    krb5int_buf_add_fmt(&buf, "%02X", (unsigned char) p[i]);
            }
        } else if (strcmp(tmpbuf, "hashlenstr") == 0) {
            len = va_arg(ap, size_t);
	    p = va_arg(ap, const char *);
            if (p == NULL && len != 0)
                krb5int_buf_add(&buf, "(null)");
            else {
                str = hash_bytes(context, p, len);
                if (str != NULL)
                    krb5int_buf_add(&buf, str);
                free(str);
            }
        } else if (strcmp(tmpbuf, "addrinfo") == 0) {
	    ai = va_arg(ap, struct addrinfo *);
	    if (ai->ai_socktype == SOCK_DGRAM)
		krb5int_buf_add(&buf, "dgram");
	    else if (ai->ai_socktype == SOCK_STREAM)
		krb5int_buf_add(&buf, "stream");
	    else
		krb5int_buf_add_fmt(&buf, "socktype%d", ai->ai_socktype);

	    if (getnameinfo(ai->ai_addr, ai->ai_addrlen,
                            addrbuf, sizeof(addrbuf), portbuf, sizeof(portbuf),
                            NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
		if (ai->ai_addr->sa_family == AF_UNSPEC)
		    krb5int_buf_add(&buf, " AF_UNSPEC");
		else
		    krb5int_buf_add_fmt(&buf, " af%d", ai->ai_addr->sa_family);
	    } else
		krb5int_buf_add_fmt(&buf, " %s:%s", addrbuf, portbuf);
        } else if (strcmp(tmpbuf, "data") == 0) {
	    d = va_arg(ap, krb5_data *);
            if (d == NULL || (d->length != 0 && d->data == NULL))
                krb5int_buf_add(&buf, "(null)");
            else
                krb5int_buf_add_len(&buf, d->data, d->length);
        } else if (strcmp(tmpbuf, "hexdata") == 0) {
	    d = va_arg(ap, krb5_data *);
            if (d == NULL)
                krb5int_buf_add(&buf, "(null)");
            else
                subfmt(context, &buf, "{hexlenstr}", d->length, d->data);
        } else if (strcmp(tmpbuf, "errno") == 0) {
	    err = va_arg(ap, int);
	    p = NULL;
#ifdef HAVE_STRERROR_R
	    if (strerror_r(err, tmpbuf, sizeof(tmpbuf)) == 0)
		p = tmpbuf;
#endif
	    if (p == NULL)
		p = strerror(err);
            krb5int_buf_add_fmt(&buf, "%d/%s", err, p);
        } else if (strcmp(tmpbuf, "kerr") == 0) {
	    kerr = va_arg(ap, krb5_error_code);
            p = krb5_get_error_message(context, kerr);
            krb5int_buf_add_fmt(&buf, "%ld/%s", (long) kerr,
                                (kerr == 0) ? "success" : p);
            krb5_free_error_message(context, p);
        } else if (strcmp(tmpbuf, "keyblock") == 0) {
            keyblock = va_arg(ap, const krb5_keyblock *);
            if (keyblock == NULL)
                krb5int_buf_add(&buf, "(null)");
            else {
                subfmt(context, &buf, "{etype}/{hashlenstr}",
                       keyblock->enctype, keyblock->length,
                       keyblock->contents);
            }
        } else if (strcmp(tmpbuf, "key") == 0) {
            key = va_arg(ap, krb5_key);
            if (key == NULL)
                krb5int_buf_add(&buf, "(null");
            else
                subfmt(context, &buf, "{keyblock}", &key->keyblock);
        } else if (strcmp(tmpbuf, "cksum") == 0) {
            cksum = va_arg(ap, const krb5_checksum *);
            data = make_data(cksum->contents, cksum->length);
            subfmt(context, &buf, "{int}/{hexdata}",
                   (int) cksum->checksum_type, &data);
        } else if (strcmp(tmpbuf, "princ") == 0) {
            princ = va_arg(ap, krb5_principal);
            if (krb5_unparse_name(context, princ, &str) == 0) {
                krb5int_buf_add(&buf, str);
                krb5_free_unparsed_name(context, str);
            }
        } else if (strcmp(tmpbuf, "patypes") == 0) {
            padata = va_arg(ap, krb5_pa_data **);
            if (padata == NULL || *padata == NULL)
                krb5int_buf_add(&buf, "(empty)");
            for (; padata != NULL && *padata != NULL; padata++) {
                krb5int_buf_add_fmt(&buf, "%d", (int) (*padata)->pa_type);
                if (*(padata + 1) != NULL)
                    krb5int_buf_add(&buf, ", ");
            }
        } else if (strcmp(tmpbuf, "etype") == 0) {
            etype = va_arg(ap, krb5_enctype);
            if (krb5_enctype_to_name(etype, TRUE, tmpbuf, sizeof(tmpbuf)) == 0)
                krb5int_buf_add(&buf, tmpbuf);
            else
                krb5int_buf_add_fmt(&buf, "%d", (int) etype);
        } else if (strcmp(tmpbuf, "etypes") == 0) {
            etypes = va_arg(ap, krb5_enctype *);
            if (etypes == NULL || *etypes == 0)
                krb5int_buf_add(&buf, "(empty");
            for (; etypes != NULL && *etypes != 0; etypes++) {
                subfmt(context, &buf, "{etype}", *etypes);
                if (*(etypes + 1) != 0)
                    krb5int_buf_add(&buf, ", ");
            }
        } else if (strcmp(tmpbuf, "ccache") == 0) {
            ccache = va_arg(ap, krb5_ccache);
            krb5int_buf_add(&buf, krb5_cc_get_type(context, ccache));
            krb5int_buf_add(&buf, ":");
            krb5int_buf_add(&buf, krb5_cc_get_name(context, ccache));
        } else if (strcmp(tmpbuf, "keytab") == 0) {
            keytab = va_arg(ap, krb5_keytab);
            if (krb5_kt_get_name(context, keytab, tmpbuf, sizeof(tmpbuf)) == 0)
                krb5int_buf_add(&buf, tmpbuf);
        } else if (strcmp(tmpbuf, "creds") == 0) {
            creds = va_arg(ap, krb5_creds *);
            subfmt(context, &buf, "{princ} -> {princ}",
                   creds->client, creds->server);
        }
    }
    return krb5int_buf_data(&buf);
}

/* Allows trace_format formatters to be represented in terms of other
 * formatters. */
static void
subfmt(krb5_context context, struct k5buf *buf, const char *fmt, ...)
{
    va_list ap;
    char *str;

    va_start(ap, fmt);
    str = trace_format(context, fmt, ap);
    if (str != NULL)
        krb5int_buf_add(buf, str);
    free(str);
    va_end(ap);
}

void
krb5int_init_trace(krb5_context context)
{
    const char *filename;

    filename = getenv("KRB5_TRACE");
    if (filename)
        (void) krb5_set_trace_filename(context, filename);
}

void
krb5int_trace(krb5_context context, const char *fmt, ...)
{
    va_list ap;
    struct krb5_trace_info info;
    char *str = NULL, *msg = NULL;
    krb5_int32 sec, usec;

    if (context == NULL || context->trace_callback == NULL)
        return;
    va_start(ap, fmt);
    str = trace_format(context, fmt, ap);
    if (str == NULL)
        goto cleanup;
    if (krb5_crypto_us_timeofday(&sec, &usec) != 0)
        goto cleanup;
    if (asprintf(&msg, "[%d] %d.%d: %s\n", (int) getpid(), (int) sec,
                 (int) usec, str) < 0)
        goto cleanup;
    info.message = msg;
    context->trace_callback(context, &info, context->trace_callback_data);
cleanup:
    free(str);
    free(msg);
    va_end(ap);
}

krb5_error_code KRB5_CALLCONV
krb5_set_trace_callback(krb5_context context, krb5_trace_callback fn,
                        void *cb_data)
{
    /* Allow the old callback to destroy its data if necessary. */
    if (context->trace_callback != NULL)
        context->trace_callback(context, NULL, context->trace_callback_data);
    context->trace_callback = fn;
    context->trace_callback_data = cb_data;
    return 0;
}

static void
file_trace_cb(krb5_context context, const struct krb5_trace_info *info, void *data)
{
    int *fd = data;

    if (info == NULL) {
        /* Null info means destroy the callback data. */
        close(*fd);
        free(fd);
        return;
    }

    (void) write(*fd, info->message, strlen(info->message));
}

krb5_error_code KRB5_CALLCONV
krb5_set_trace_filename(krb5_context context, const char *filename)
{
    int *fd;

    /* Create callback data containing a file descriptor. */
    fd = malloc(sizeof(*fd));
    if (fd == NULL)
        return ENOMEM;
    *fd = open(filename, O_WRONLY|O_CREAT|O_APPEND, 0600);
    if (*fd == -1) {
        free(fd);
        return errno;
    }

    return krb5_set_trace_callback(context, file_trace_cb, fd);
}

#else /* DISABLE_TRACING */

krb5_error_code KRB5_CALLCONV
krb5_set_trace_callback(krb5_context context, krb5_trace_callback fn,
                        void *cb_data)
{
    if (fn == NULL)
        return 0;
    return KRB5_TRACE_NOSUPP;
}

krb5_error_code KRB5_CALLCONV
krb5_set_trace_filename(krb5_context context, const char *filename)
{
    return KRB5_TRACE_NOSUPP;
}

#endif /* DISABLE_TRACING */
