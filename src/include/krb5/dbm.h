/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * DBM/NDBM include file; deals with converting old-style to new-style.
 */

#include <krb5/copyright.h>

#ifndef KRB5_DBM_COMPAT__
#define KRB5_DBM_COMPAT__

#include <krb5/osconf.h>

#ifndef ODBM
#include <ndbm.h>
#else /*ODBM*/
#include <dbm.h>
#endif /*ODBM*/

#ifndef ODBM
#define dbm_next(db,key) dbm_nextkey(db)
#else /* OLD DBM */
typedef char DBM;

#define dbm_open(file, flags, mode) ((dbminit(file) == 0)?"":((char *)0))
#define dbm_fetch(db, key) fetch(key)
#define dbm_store(db, key, content, flag) store(key, content)
#define dbm_delete(db, key) delete(key)
#define dbm_firstkey(db) firstkey()
#define dbm_next(db,key) nextkey(key)
#define dbm_close(db) dbmclose()
#endif /* OLD DBM */

#endif /* KRB5_DBM_COMPAT__ */
