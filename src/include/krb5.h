/*
 * This prototype for a globally useful krb5.h simply includes every file
 * in the lower krb5 directory, in alphabetical order.
 *
 * John Gilmore, Cygnus Support, Sat Jan 21 22:45:52 PST 1995
 */

#include "krb5/krb5.h"

/* krb5/krb5.h includes many other krb5/*.h files too.  The ones that it
   doesn't include, we include below.  */

#include "krb5/adm_defs.h"
#include "krb5/asn1.h"
#include "krb5/copyright.h"
/* #include "krb5/crc-32.h" -- removed from krb5 to lib/crypto/crc32 */
#include "krb5/dbm.h"
#include "krb5/ext-proto.h"
#include "krb5/kdb.h"
#include "krb5/kdb_dbm.h"
#include "krb5/libos.h"
#include "krb5/los-proto.h"
#include "krb5/mit-des.h"
/* #include "krb5/narrow.h" -- used in encryption.h and others, custom usage */
#include "krb5/preauth.h"
/* #include "krb5/rsa-md4.h" -- removed from krb5 to lib/crypto/md4 */
#include "krb5/rsa-md5.h"
/* #include "krb5/stock" */
#include "krb5/sysincl.h"
/* #include "krb5/widen.h" -- used in encryption.h, custom usage. */
/* #include "krb5/wordsize.h" -- comes in through base-defs.h. */
