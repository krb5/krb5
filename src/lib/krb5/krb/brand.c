/*
 * This file is used to put a "release brand" on a Krb5 library before
 * it is released via some release engineering process.  This gives us
 * an easy way to tell where a binary came from.
 *
 * It currently is manually maintained, because there's no good way to
 * automatically have CVS do the right thing.  We could put RCS tags
 * in every single file, but that (a) takes up lots of space, since we
 * have lots of files in the Kerberos library, and (b) it makes CVS
 * merges a real pain.
 */

/* Format: "KRB5_BRAND: <cvs tag> <date>" */

static char krb5_brand[] = "KRB5_BRAND: Unbranded release";
