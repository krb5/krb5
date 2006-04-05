/* foo */
#include <stdarg.h>
#include "k5-int.h"

void
krb5_set_error_message (krb5_context ctx, krb5_error_code code,
			const char *fmt, ...)
{
    va_list args;
    if (ctx == NULL)
	return;
    va_start (args, fmt);
    krb5int_vset_error (&ctx->err, code, fmt, args);
    va_end (args);
}

void
krb5_vset_error_message (krb5_context ctx, krb5_error_code code,
			 const char *fmt, va_list args)
{
    if (ctx == NULL)
	return;
    krb5int_vset_error (&ctx->err, code, fmt, args);
}

char *
krb5_get_error_message (krb5_context ctx, krb5_error_code code)
{
    if (ctx == NULL)
	return error_message(code);
    return krb5int_get_error (&ctx->err, code);
}

void
krb5_free_error_message (krb5_context ctx, char *msg)
{
    if (ctx == NULL)
	return;
    krb5int_free_error (&ctx->err, msg);
}

void
krb5_clear_error_message (krb5_context ctx)
{
    if (ctx == NULL)
	return;
    krb5int_clear_error (&ctx->err);
}
