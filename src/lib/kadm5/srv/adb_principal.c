/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved
 *
 * $Header$
 * 
 * $Log$
 * Revision 1.1  1996/07/24 22:23:12  tlyu
 * 	* Makefile.in, configure.in: break out server lib into a
 * 		subdirectory
 *
 * Revision 1.24  1996/07/22 20:35:23  marc
 * this commit includes all the changes on the OV_9510_INTEGRATION and
 * OV_MERGE branches.  This includes, but is not limited to, the new openvision
 * admin system, and major changes to gssapi to add functionality, and bring
 * the implementation in line with rfc1964.  before committing, the
 * code was built and tested for netbsd and solaris.
 *
 * Revision 1.23.4.1  1996/07/18 03:08:17  marc
 * merged in changes from OV_9510_BP to OV_9510_FINAL1
 *
 * Revision 1.23.2.1  1996/06/20  02:16:30  marc
 * File added to the repository on a branch
 *
 * Revision 1.23  1996/05/16  21:44:35  bjaspan
 * this file is no longer used, #if the whole thing out
 *
 * Revision 1.22  1996/05/08 20:51:44  bjaspan
 * marc's changes
 *
 * Revision 1.21  1995/08/24  20:23:43  bjaspan
 * marc is a bonehead
 *
 * Revision 1.20  1995/08/23  19:16:02  marc
 * check for db == NULL in OPENLOCK()
 *
 * Revision 1.19  1995/08/08  18:31:30  bjaspan
 * [secure/3394] first cut at admin db locking support
 *
 * Revision 1.18  1995/08/02  15:26:57  bjaspan
 * check db==NULL in iter
 *
 * Revision 1.17  1994/05/09  17:52:36  shanzer
 * fixed some include files
 *
 * Revision 1.16  1994/03/17  01:25:58  shanzer
 * include fcntl.h
 *
 * Revision 1.15  1993/12/17  18:54:06  jik
 * [secure-admin/1040]
 *
 * open_princ should return errno, rather than BAD_DB, if errno is
 * something other than BAD_DB.
 *
 * Revision 1.14  1993/12/13  18:55:58  marc
 * remove bogus free()'s
 *
 * Revision 1.13  1993/12/08  22:29:27  marc
 * fixed another xdrmem alignment thing]
 *
 * Revision 1.12  1993/12/06  22:22:22  bjaspan
 * fix alignment and free-memory-read bugs
 *
 * Revision 1.11  1993/12/05  04:15:16  shanzer
 * removed data size hack.
 *
 * Revision 1.10  1993/11/15  00:29:24  shanzer
 * added filenme to open
 *
 * Revision 1.9  1993/11/10  20:10:06  shanzer
 * now uses xdralloc instead of xdrmem
 *
 * Revision 1.8  1993/11/09  21:43:24  shanzer
 * added check to see if we overflowed our xdr buffer.
 *
 * Revision 1.7  1993/11/09  04:00:19  shanzer
 * changed bzero to memset
 *
 * Revision 1.6  1993/11/05  23:16:21  shanzer
 * return ENOMEM instead of ovsec_kadm_mem
 *
 * Revision 1.5  1993/11/05  22:17:03  shanzer
 * added principal db interative function
 *
 * Revision 1.4  1993/11/04  23:20:24  shanzer
 * made HASHINFO static.
 *
 * Revision 1.3  1993/11/04  01:52:30  shanzer
 * Restructred some code .. fixed some bugs/leaks
 *
 */

#if !defined(lint) && !defined(__CODECENTER__)
static char *rcsid = "$Header$";
#endif

#if 0
/* XXX THIS FILE IS NO LONGER USED, and should be deleted when we're done */

#include	<sys/file.h>
#include	<fcntl.h>
#include	"adb.h"
#include	<stdlib.h>
#include	<memory.h>

#define OPENLOCK(db, mode) \
{ \
       int ret; \
	    if (db == NULL) \
		 return EINVAL; \
	    else if (db->magic != OSA_ADB_PRINC_DB_MAGIC) \
		 return OSA_ADB_DBINIT; \
	    else if ((ret = osa_adb_open_and_lock(db, mode)) != OSA_ADB_OK) \
		 return ret; \
	    }

#define CLOSELOCK(db) \
{ \
     int ret; \
     if ((ret = osa_adb_close_and_unlock(db)) != OSA_ADB_OK) \
	  return ret; \
}

osa_adb_ret_t osa_adb_open_princ(osa_adb_princ_t *dbp, char *filename)
{
     return osa_adb_init_db(dbp, filename, OSA_ADB_PRINC_DB_MAGIC);
}

osa_adb_ret_t osa_adb_close_princ(osa_adb_princ_t db)
{
     return osa_adb_fini_db(db, OSA_ADB_PRINC_DB_MAGIC);
}

osa_adb_ret_t
osa_adb_create_princ(osa_adb_princ_t db, osa_princ_ent_t entry)
{

    DBT			dbkey;
    DBT			dbdata;
    XDR			xdrs;
    int			ret;

    OPENLOCK(db, OSA_ADB_EXCLUSIVE);

    if(krb5_unparse_name(db->lock->context,
			 entry->name, (char **) &dbkey.data)) {
	 ret = OSA_ADB_BAD_PRINC;
	 goto error;
    }
    if((dbkey.size = strlen(dbkey.data)) == 0) {
	 ret = OSA_ADB_BAD_PRINC;
	 goto error;
    }
	
    switch(db->db->get(db->db, &dbkey, &dbdata, 0)) {
    case 0:
	 ret = OSA_ADB_DUP;
	 goto error;
    case 1:
	break;
    default:
	 ret = OSA_ADB_FAILURE;
	 goto error;
    }
    xdralloc_create(&xdrs, XDR_ENCODE); 
    if(!xdr_osa_princ_ent_rec(&xdrs, entry)) {
	xdr_destroy(&xdrs);
	ret = OSA_ADB_XDR_FAILURE;
	goto error;
    }
    dbdata.data = xdralloc_getdata(&xdrs);
    dbdata.size = xdr_getpos(&xdrs);
    switch(db->db->put(db->db, &dbkey, &dbdata, R_NOOVERWRITE)) {
    case 0:
	if((db->db->sync(db->db, 0)) == -1)
	    ret =  OSA_ADB_FAILURE;
	else
	     ret = OSA_ADB_OK;
	break;
    case 1:
	ret = OSA_ADB_DUP;
	break;
    default:
	ret = OSA_ADB_FAILURE;
	break;
    }
    xdralloc_release(&xdrs);
    free(dbkey.data);

error:
    CLOSELOCK(db);
    
    return ret;
}
	
osa_adb_ret_t
osa_adb_destroy_princ(osa_adb_princ_t db, ovsec_kadm_princ_t name)
{
    DBT	    dbkey;
    int	    status;
    int	    ret;

    OPENLOCK(db, OSA_ADB_EXCLUSIVE);

    if(krb5_unparse_name(db->lock->context, name, (char **) &dbkey.data)) {
	 ret = OSA_ADB_BAD_PRINC;
	 goto error;
    }
    if ((dbkey.size = strlen(dbkey.data)) == 0) {
	 ret = OSA_ADB_BAD_PRINC;
	 goto error;
    }
    status = db->db->del(db->db, &dbkey, 0);
    switch(status) {
    case 1:
	ret = OSA_ADB_NOENT;
	break;
    case 0:
	if ((db->db->sync(db->db, 0)) == -1)
	    ret = OSA_ADB_FAILURE;
	else 
	     ret = OSA_ADB_OK;
	break;
    default:
	ret = OSA_ADB_FAILURE;
	break;
    }
    free(dbkey.data);

error:
    CLOSELOCK(db);
    
    return ret;
}

osa_adb_ret_t
osa_adb_get_princ(osa_adb_princ_t db, ovsec_kadm_princ_t name,
		  osa_princ_ent_t *entry)
{
    DBT			dbkey;
    DBT			dbdata;
    XDR			xdrs;
    int			ret = 0;
    char		*aligned_data;

    OPENLOCK(db, OSA_ADB_SHARED);

    if(krb5_unparse_name(db->lock->context, name, (char **) &dbkey.data)) {
	 ret = OSA_ADB_BAD_PRINC;
	 goto error;
    }
    if((dbkey.size = strlen(dbkey.data)) == 0) {
	 ret = OSA_ADB_BAD_PRINC;
	 goto error;
    }
    dbdata.size = 0;
    dbdata.data = NULL;
    switch(db->db->get(db->db, &dbkey, &dbdata, 0)) {
    case 1:
	ret = OSA_ADB_NOENT;
	break;
    case 0:
	break;
    default:
	ret = OSA_ADB_FAILURE;
	break;
    }
    free(dbkey.data);
    if (ret)
	 goto error;

    if (!(*(entry) = (osa_princ_ent_t)malloc(sizeof(osa_princ_ent_rec)))) {
	 ret = ENOMEM;
	 goto error;
    }

    aligned_data = (char *) malloc(dbdata.size);
    if (aligned_data == NULL) {
	 ret = ENOMEM;
	 goto error;
    }
    memcpy(aligned_data, dbdata.data, dbdata.size);
    
    memset(*entry, 0, sizeof(osa_princ_ent_rec));	
    xdrmem_create(&xdrs, aligned_data, dbdata.size, XDR_DECODE);
    if (!xdr_osa_princ_ent_rec(&xdrs, *entry)) {
	xdr_destroy(&xdrs);
	free(aligned_data);
	ret = OSA_ADB_FAILURE;
	goto error;
    }
    xdr_destroy(&xdrs);
    free(aligned_data);
    ret = OSA_ADB_OK;

error:
    CLOSELOCK(db);
    return ret;
}

osa_adb_ret_t
osa_adb_put_princ(osa_adb_princ_t db, osa_princ_ent_t entry)
{
    DBT			dbkey;
    DBT			dbdata;
    DBT			tmpdb;
    XDR			xdrs;
    int			ret;

    OPENLOCK(db, OSA_ADB_EXCLUSIVE);

    if(krb5_unparse_name(db->lock->context,
			 entry->name, (char **) &dbkey.data)) {
	 ret = OSA_ADB_BAD_PRINC;
	 goto error;
    }
    if((dbkey.size = strlen(dbkey.data)) == 0) {
	 ret = OSA_ADB_BAD_PRINC;
	 goto error;
    }
	
    switch(db->db->get(db->db, &dbkey, &tmpdb, 0)) {
    case 0:
	break;
    case 1:
	ret = OSA_ADB_NOENT;
	goto error;
    default:
	ret = OSA_ADB_FAILURE;
	goto error;
    }
    xdralloc_create(&xdrs, XDR_ENCODE);
    if(!xdr_osa_princ_ent_rec(&xdrs, entry)) {
	xdr_destroy(&xdrs);
	ret =  OSA_ADB_XDR_FAILURE;
	goto error;
    }
    dbdata.data = xdralloc_getdata(&xdrs);
    dbdata.size = xdr_getpos(&xdrs);
    switch(db->db->put(db->db, &dbkey, &dbdata, 0)) {
    case 0:
	if((db->db->sync(db->db, 0)) == -1)
	    ret =  OSA_ADB_FAILURE;
	else 
	     ret =  OSA_ADB_OK;
	break;
    default:
	ret = OSA_ADB_FAILURE;
	break;
    }
    xdralloc_release(&xdrs);
    free(dbkey.data);

error:
    CLOSELOCK(db);
    return ret;
}

osa_adb_ret_t
osa_adb_iter_princ(osa_adb_princ_t db, osa_adb_iter_princ_func func,
		    void *data)
{
    DBT			    dbkey,
			    dbdata;
    XDR			    xdrs;
    int			    ret;
    osa_princ_ent_t	    entry;
    char		    *aligned_data;

    OPENLOCK(db, OSA_ADB_EXCLUSIVE); /* hmmmm */
    
    if((ret = db->db->seq(db->db, &dbkey, &dbdata, R_FIRST)) == -1) {
	 ret = errno;
	 goto error;
    }
    while (ret == 0) {
	 if (!(entry = (osa_princ_ent_t) malloc(sizeof(osa_princ_ent_rec)))) {
	      ret = ENOMEM;
	      goto error;
	 }

	aligned_data = (char *) malloc(dbdata.size);
	 if (aligned_data == NULL) {
	      ret = ENOMEM;
	      goto error;
	 }
	memcpy(aligned_data, dbdata.data, dbdata.size);

	memset(entry, 0, sizeof(osa_princ_ent_rec));
	xdrmem_create(&xdrs, aligned_data, dbdata.size, XDR_DECODE);
	if(!xdr_osa_princ_ent_rec(&xdrs, entry)) {
	    xdr_destroy(&xdrs);
	    free(aligned_data);
	    ret = OSA_ADB_FAILURE;
	    goto error;
	}
	(*func)(data, entry);
	xdr_destroy(&xdrs);
	free(aligned_data);
	osa_free_princ_ent(entry);
	ret = db->db->seq(db->db, &dbkey, &dbdata, R_NEXT);
    }
    if(ret == -1)
	 ret = errno;
    else
	 ret = OSA_ADB_OK;

error:
    CLOSELOCK(db);
    return ret;
}

#endif /* 0 */
