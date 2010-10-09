/* #pragma ident	"@(#)g_initialize.c	1.36	05/02/02 SMI" */

/*
 * Copyright 1996 by Sun Microsystems, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of Sun Microsystems not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. Sun Microsystems makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 *
 * SUN MICROSYSTEMS DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL SUN MICROSYSTEMS BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * This function will initialize the gssapi mechglue library
 */

#include "mglueP.h"
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#define	M_DEFAULT	"default"

#include "k5-thread.h"
#include "k5-plugin.h"
#include "osconf.h"
#ifdef _GSS_STATIC_LINK
#include "gssapiP_krb5.h"
#include "gssapiP_spnego.h"
#endif

#define MECH_SYM "gss_mech_initialize"

#ifndef MECH_CONF
#define	MECH_CONF "/etc/gss/mech"
#endif

/* Local functions */
static gss_mech_info searchMechList(const gss_OID);
static void loadConfigFile(const char *);
static void updateMechList(void);
static void freeMechList(void);

static OM_uint32 build_mechSet(void);
static void free_mechSet(void);

/*
 * list of mechanism libraries and their entry points.
 * the list also maintains state of the mech libraries (loaded or not).
 */
static gss_mech_info g_mechList = NULL;
static gss_mech_info g_mechListTail = NULL;
static k5_mutex_t g_mechListLock = K5_MUTEX_PARTIAL_INITIALIZER;
static time_t g_confFileModTime = (time_t)0;

static time_t g_mechSetTime = (time_t)0;
static gss_OID_set_desc g_mechSet = { 0, NULL };
static k5_mutex_t g_mechSetLock = K5_MUTEX_PARTIAL_INITIALIZER;

MAKE_INIT_FUNCTION(gssint_mechglue_init);
MAKE_FINI_FUNCTION(gssint_mechglue_fini);

int
gssint_mechglue_init(void)
{
	int err;

#ifdef SHOW_INITFINI_FUNCS
	printf("gssint_mechglue_init\n");
#endif

	add_error_table(&et_ggss_error_table);

	err = k5_mutex_finish_init(&g_mechSetLock);
	err = k5_mutex_finish_init(&g_mechListLock);

#ifdef _GSS_STATIC_LINK
	err = gss_krb5int_lib_init();
	err = gss_spnegoint_lib_init();
#endif

	return err;
}

void
gssint_mechglue_fini(void)
{
	if (!INITIALIZER_RAN(gssint_mechglue_init) || PROGRAM_EXITING()) {
#ifdef SHOW_INITFINI_FUNCS
		printf("gssint_mechglue_fini: skipping\n");
#endif
		return;
	}

#ifdef SHOW_INITFINI_FUNCS
	printf("gssint_mechglue_fini\n");
#endif
#ifdef _GSS_STATIC_LINK
	gss_spnegoint_lib_fini();
	gss_krb5int_lib_fini();
#endif
	k5_mutex_destroy(&g_mechSetLock);
	k5_mutex_destroy(&g_mechListLock);
	free_mechSet();
	freeMechList();
	remove_error_table(&et_ggss_error_table);
	gssint_mecherrmap_destroy();
}

int
gssint_mechglue_initialize_library(void)
{
	return CALL_INIT_FUNCTION(gssint_mechglue_init);
}

/*
 * function used to reclaim the memory used by a gss_OID structure.
 * This routine requires direct access to the mechList.
 */
OM_uint32 KRB5_CALLCONV
gss_release_oid(minor_status, oid)
OM_uint32 *minor_status;
gss_OID *oid;
{
	OM_uint32 major;
	gss_mech_info aMech;

	if (minor_status == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	*minor_status = gssint_mechglue_initialize_library();
	if (*minor_status != 0)
		return (GSS_S_FAILURE);

	*minor_status = k5_mutex_lock(&g_mechListLock);
	if (*minor_status)
		return GSS_S_FAILURE;
	aMech = g_mechList;
	while (aMech != NULL) {

		/*
		 * look through the loaded mechanism libraries for
		 * gss_internal_release_oid until one returns success.
		 * gss_internal_release_oid will only return success when
		 * the OID was recognized as an internal mechanism OID. if no
		 * mechanisms recognize the OID, then call the generic version.
		 */
		if (aMech->mech && aMech->mech->gss_internal_release_oid) {
			major = aMech->mech->gss_internal_release_oid(
					minor_status, oid);
			if (major == GSS_S_COMPLETE) {
				k5_mutex_unlock(&g_mechListLock);
				return (GSS_S_COMPLETE);
			}
			map_error(minor_status, aMech->mech);
		}
		aMech = aMech->next;
	} /* while */
	k5_mutex_unlock(&g_mechListLock);

	return (generic_gss_release_oid(minor_status, oid));
} /* gss_release_oid */


/*
 * this function will return an oid set indicating available mechanisms.
 * The set returned is based on configuration file entries and
 * NOT on the loaded mechanisms.  This function does not check if any
 * of these can actually be loaded.
 * This routine needs direct access to the mechanism list.
 * To avoid reading the configuration file each call, we will save a
 * a mech oid set, and only update it once the file has changed.
 */
OM_uint32 KRB5_CALLCONV
gss_indicate_mechs(minorStatus, mechSet_out)
OM_uint32 *minorStatus;
gss_OID_set *mechSet_out;
{
	char *fileName;
	struct stat fileInfo;
	unsigned int i, j;
	gss_OID curItem;
	gss_OID_set mechSet;

	/* Initialize outputs. */

	if (minorStatus != NULL)
		*minorStatus = 0;

	if (mechSet_out != NULL)
		*mechSet_out = GSS_C_NO_OID_SET;

	/* Validate arguments. */
	if (minorStatus == NULL || mechSet_out == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	*minorStatus = gssint_mechglue_initialize_library();
	if (*minorStatus != 0)
		return (GSS_S_FAILURE);

	fileName = MECH_CONF;

	/*
	 * If we have already computed the mechanisms supported and if it
	 * is still valid; make a copy and return to caller,
	 * otherwise build it first.
	 */
	if ((stat(fileName, &fileInfo) == 0 &&
		fileInfo.st_mtime > g_mechSetTime)) {
	} /* if g_mechSet is out of date or not initialized */
	if (build_mechSet())
		return GSS_S_FAILURE;

	/*
	 * the mech set is created and it is up to date
	 * so just copy it to caller
	 */
	if ((mechSet =
		(gss_OID_set) malloc(sizeof (gss_OID_set_desc))) == NULL)
	{
		return (GSS_S_FAILURE);
	}

	/*
	 * need to lock the g_mechSet in case someone tries to update it while
	 * I'm copying it.
	 */
	*minorStatus = k5_mutex_lock(&g_mechSetLock);
	if (*minorStatus) {
		free(mechSet);
		return GSS_S_FAILURE;
	}

	/* allocate space for the oid structures */
	if ((mechSet->elements =
		(void*) calloc(g_mechSet.count, sizeof (gss_OID_desc)))
		== NULL)
	{
		(void) k5_mutex_unlock(&g_mechSetLock);
		free(mechSet);
		return (GSS_S_FAILURE);
	}

	/* now copy the oid structures */
	(void) memcpy(mechSet->elements, g_mechSet.elements,
		g_mechSet.count * sizeof (gss_OID_desc));

	mechSet->count = g_mechSet.count;

	/* still need to copy each of the oid elements arrays */
	for (i = 0; i < mechSet->count; i++) {
		curItem = &(mechSet->elements[i]);
		curItem->elements =
			(void *) malloc(g_mechSet.elements[i].length);
		if (curItem->elements == NULL) {
			(void) k5_mutex_unlock(&g_mechSetLock);
			/*
			 * must still free the allocated elements for
			 * each allocated gss_OID_desc
			 */
			for (j = 0; j < i; j++) {
				free(mechSet->elements[j].elements);
			}
			free(mechSet->elements);
			free(mechSet);
			return (GSS_S_FAILURE);
		}
		g_OID_copy(curItem, &g_mechSet.elements[i]);
	}
	(void) k5_mutex_unlock(&g_mechSetLock);
	*mechSet_out = mechSet;
	return (GSS_S_COMPLETE);
} /* gss_indicate_mechs */


/* Call with g_mechSetLock held, or during final cleanup.  */
static void
free_mechSet(void)
{
	unsigned int i;

	if (g_mechSet.count != 0) {
		for (i = 0; i < g_mechSet.count; i++)
			free(g_mechSet.elements[i].elements);
		free(g_mechSet.elements);
		g_mechSet.elements = NULL;
		g_mechSet.count = 0;
	}
}

static OM_uint32
build_mechSet(void)
{
	gss_mech_info mList;
	size_t i;
	size_t count;
	gss_OID curItem;

	/*
	 * lock the mutex since we will be updating
	 * the mechList structure
	 * we need to keep the lock while we build the mechanism list
	 * since we are accessing parts of the mechList which could be
	 * modified.
	 */
	if (k5_mutex_lock(&g_mechListLock) != 0)
		return GSS_S_FAILURE;

#if 0
	/*
	 * this checks for the case when we need to re-construct the
	 * g_mechSet structure, but the mechanism list is upto date
	 * (because it has been read by someone calling
	 * gssint_get_mechanism)
	 */
	if (fileInfo.st_mtime > g_confFileModTime)
	{
		g_confFileModTime = fileInfo.st_mtime;
		loadConfigFile(fileName);
	}
#endif

	updateMechList();

	/*
	 * we need to lock the mech set so that no one else will
	 * try to read it as we are re-creating it
	 */
	if (k5_mutex_lock(&g_mechSetLock) != 0)
		return GSS_S_FAILURE;

	/* if the oid list already exists we must free it first */
	free_mechSet();

	/* determine how many elements to have in the list */
	mList = g_mechList;
	count = 0;
	while (mList != NULL) {
		count++;
		mList = mList->next;
	}

	/* this should always be true, but.... */
	if (count > 0) {
		g_mechSet.elements =
			(gss_OID) calloc(count, sizeof (gss_OID_desc));
		if (g_mechSet.elements == NULL) {
			(void) k5_mutex_unlock(&g_mechSetLock);
			(void) k5_mutex_unlock(&g_mechListLock);
			return (GSS_S_FAILURE);
		}

		(void) memset(g_mechSet.elements, 0,
			      count * sizeof (gss_OID_desc));

		/* now copy each oid element */
		g_mechSet.count = count;
		count = 0;
		mList = g_mechList;
		while (mList != NULL) {
			curItem = &(g_mechSet.elements[count]);
			curItem->elements = (void*)
				malloc(mList->mech_type->length);
			if (curItem->elements == NULL) {
				/*
				 * this is nasty - we must delete the
				 * part of the array already copied
				 */
				for (i = 0; i < count; i++) {
					free(g_mechSet.elements[i].
					     elements);
				}
				free(g_mechSet.elements);
				g_mechSet.count = 0;
				g_mechSet.elements = NULL;
				(void) k5_mutex_unlock(&g_mechSetLock);
				(void) k5_mutex_unlock(&g_mechListLock);
				return (GSS_S_FAILURE);
			}
			g_OID_copy(curItem, mList->mech_type);
			count++;
			mList = mList->next;
		}
	}

#if 0
	g_mechSetTime = fileInfo.st_mtime;
#endif
	(void) k5_mutex_unlock(&g_mechSetLock);
	(void) k5_mutex_unlock(&g_mechListLock);

	return GSS_S_COMPLETE;
}


/*
 * this function has been added for use by modules that need to
 * know what (if any) optional parameters are supplied in the
 * config file (MECH_CONF).
 * It will return the option string for a specified mechanism.
 * caller is responsible for freeing the memory
 */
char *
gssint_get_modOptions(oid)
const gss_OID oid;
{
	gss_mech_info aMech;
	char *modOptions = NULL;

	if (gssint_mechglue_initialize_library() != 0)
		return (NULL);

	/* make sure we have fresh data */
	if (k5_mutex_lock(&g_mechListLock) != 0)
		return NULL;
	updateMechList();

	if ((aMech = searchMechList(oid)) == NULL ||
		aMech->optionStr == NULL) {
		(void) k5_mutex_unlock(&g_mechListLock);
		return (NULL);
	}

	if (aMech->optionStr)
		modOptions = strdup(aMech->optionStr);
	(void) k5_mutex_unlock(&g_mechListLock);

	return (modOptions);
} /* gssint_get_modOptions */

/*
 * given a mechanism string return the mechanism oid
 */
OM_uint32
gssint_mech_to_oid(const char *mechStr, gss_OID* oid)
{
	gss_mech_info aMech;

	if (oid == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	*oid = GSS_C_NULL_OID;

	if (gssint_mechglue_initialize_library() != 0)
		return (GSS_S_FAILURE);

	if ((mechStr == NULL) || (strlen(mechStr) == 0) ||
		(strcasecmp(mechStr, M_DEFAULT) == 0))
		return (GSS_S_COMPLETE);

	/* ensure we have fresh data */
	if (k5_mutex_lock(&g_mechListLock) != 0)
		return GSS_S_FAILURE;
	updateMechList();
	(void) k5_mutex_unlock(&g_mechListLock);

	aMech = g_mechList;

	/* no lock required - only looking at fields that are not updated */
	while (aMech != NULL) {
		if ((aMech->mechNameStr) &&
			strcmp(aMech->mechNameStr, mechStr) == 0) {
			*oid = aMech->mech_type;
			return (GSS_S_COMPLETE);
		}
		aMech = aMech->next;
	}
	return (GSS_S_FAILURE);
} /* gssint_mech_to_oid */


/*
 * Given the mechanism oid, return the readable mechanism name
 * associated with that oid from the mech config file
 * (/etc/gss/mech).
 */
const char *
gssint_oid_to_mech(const gss_OID oid)
{
	gss_mech_info aMech;

	if (oid == GSS_C_NULL_OID)
		return (M_DEFAULT);

	if (gssint_mechglue_initialize_library() != 0)
		return (NULL);

	/* ensure we have fresh data */
	if (k5_mutex_lock(&g_mechListLock) != 0)
		return NULL;
	updateMechList();
	aMech = searchMechList(oid);
	(void) k5_mutex_unlock(&g_mechListLock);

	if (aMech == NULL)
		return (NULL);

	return (aMech->mechNameStr);
} /* gssint_oid_to_mech */


/*
 * return a list of mechanism strings supported
 * upon return the array is terminated with a NULL entry
 */
OM_uint32
gssint_get_mechanisms(char *mechArray[], int arrayLen)
{
	gss_mech_info aMech;
	int i;

	if (mechArray == NULL || arrayLen < 1)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	if (gssint_mechglue_initialize_library() != 0)
		return (GSS_S_FAILURE);

	/* ensure we have fresh data */
	if (k5_mutex_lock(&g_mechListLock) != 0)
		return GSS_S_FAILURE;
	updateMechList();
	(void) k5_mutex_unlock(&g_mechListLock);

	aMech = g_mechList;

	/* no lock required - only looking at fields that are not updated */
	for (i = 1; i < arrayLen; i++) {
		if (aMech != NULL) {
			*mechArray = aMech->mechNameStr;
			mechArray++;
			aMech = aMech->next;
		} else
			break;
	}
	*mechArray = NULL;
	return (GSS_S_COMPLETE);
} /* gss_get_mechanisms */

/*
 * determines if the mechList needs to be updated from file
 * and performs the update.
 * this functions must be called with a lock of g_mechListLock
 */
static void
updateMechList(void)
{
	char *fileName;
	struct stat fileInfo;

	fileName = MECH_CONF;

	/* check if mechList needs updating */
	if (stat(fileName, &fileInfo) == 0 &&
		(fileInfo.st_mtime > g_confFileModTime)) {
		loadConfigFile(fileName);
		g_confFileModTime = fileInfo.st_mtime;
	}
#if 0
	init_hardcoded();
#endif
} /* updateMechList */

#ifdef _GSS_STATIC_LINK
static void
releaseMechInfo(gss_mech_info *pCf)
{
	gss_mech_info cf;
	OM_uint32 minor_status;

	if (*pCf == NULL) {
		return;
	}

	cf = *pCf;

	if (cf->kmodName != NULL)
		free(cf->kmodName);
	if (cf->uLibName != NULL)
		free(cf->uLibName);
	if (cf->mechNameStr != NULL)
		free(cf->mechNameStr);
	if (cf->optionStr != NULL)
		free(cf->optionStr);
	if (cf->mech_type != GSS_C_NO_OID &&
	    cf->mech_type != &cf->mech->mech_type)
		generic_gss_release_oid(&minor_status, &cf->mech_type);
	if (cf->mech != NULL) {
		memset(cf->mech, 0, sizeof(*cf->mech));
		free(cf->mech);
	}
	if (cf->mech_ext != NULL) {
		memset(cf->mech_ext, 0, sizeof(*cf->mech_ext));
		free(cf->mech_ext);
	}
	if (cf->dl_handle != NULL)
		krb5int_close_plugin(cf->dl_handle);

	memset(cf, 0, sizeof(*cf));
	free(cf);

	*pCf = NULL;
}

/*
 * Register a mechanism.  Called with g_mechListLock held.
 */
int
gssint_register_mechinfo(gss_mech_info template)
{
	gss_mech_info cf, new_cf;

	new_cf = calloc(1, sizeof(*new_cf));
	if (new_cf == NULL) {
		return ENOMEM;
	}

	new_cf->dl_handle = template->dl_handle;
	/* copy mech so we can rewrite canonical mechanism OID */
	new_cf->mech = (gss_mechanism)calloc(1, sizeof(struct gss_config));
	if (new_cf->mech == NULL) {
		releaseMechInfo(&new_cf);
		return ENOMEM;
	}
	*new_cf->mech = *template->mech;
	if (template->mech_type != NULL)
		new_cf->mech->mech_type = *(template->mech_type);
	new_cf->mech_type = &new_cf->mech->mech_type;
	new_cf->priority = template->priority;
	new_cf->freeMech = 1;
	new_cf->next = NULL;

	if (template->mech_ext != NULL) {
		new_cf->mech_ext = (gss_mechanism_ext)calloc(1,
						sizeof(struct gss_config_ext));
		if (new_cf->mech_ext == NULL) {
			releaseMechInfo(&new_cf);
			return ENOMEM;
		}
		*new_cf->mech_ext = *template->mech_ext;
	}

	if (template->kmodName != NULL) {
		new_cf->kmodName = strdup(template->kmodName);
		if (new_cf->kmodName == NULL) {
			releaseMechInfo(&new_cf);
			return ENOMEM;
		}
	}
	if (template->uLibName != NULL) {
		new_cf->uLibName = strdup(template->uLibName);
		if (new_cf->uLibName == NULL) {
			releaseMechInfo(&new_cf);
			return ENOMEM;
		}
	}
	if (template->mechNameStr != NULL) {
		new_cf->mechNameStr = strdup(template->mechNameStr);
		if (new_cf->mechNameStr == NULL) {
			releaseMechInfo(&new_cf);
			return ENOMEM;
		}
	}
	if (template->optionStr != NULL) {
		new_cf->optionStr = strdup(template->optionStr);
		if (new_cf->optionStr == NULL) {
			releaseMechInfo(&new_cf);
			return ENOMEM;
		}
	}
	if (g_mechList == NULL) {
		g_mechList = new_cf;
		g_mechListTail = new_cf;
		return 0;
	} else if (new_cf->priority < g_mechList->priority) {
		new_cf->next = g_mechList;
		g_mechList = new_cf;
		return 0;
	}

	for (cf = g_mechList; cf != NULL; cf = cf->next) {
		if (cf->next == NULL ||
		    new_cf->priority < cf->next->priority) {
			new_cf->next = cf->next;
			cf->next = new_cf;
			if (g_mechListTail == cf) {
				g_mechListTail = new_cf;
			}
			break;
		}
	}

	return 0;
}
#endif /* _GSS_STATIC_LINK */

#define GSS_ADD_DYNAMIC_METHOD(_dl, _mech, _symbol) \
	do { \
		struct errinfo errinfo; \
		\
		memset(&errinfo, 0, sizeof(errinfo)); \
		if (krb5int_get_plugin_func(_dl, \
					    #_symbol, \
					    (void (**)())&(_mech)->_symbol, \
					    &errinfo) || errinfo.code) \
			(_mech)->_symbol = NULL; \
	} while (0)

static gss_mechanism
build_dynamicMech(void *dl, const gss_OID mech_type)
{
	gss_mechanism mech;

	mech = (gss_mechanism)calloc(1, sizeof(*mech));
	if (mech == NULL) {
		return NULL;
	}

	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_acquire_cred);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_release_cred);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_init_sec_context);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_accept_sec_context);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_process_context_token);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_delete_sec_context);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_context_time);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_get_mic);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_verify_mic);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_wrap);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_unwrap);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_display_status);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_indicate_mechs);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_compare_name);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_display_name);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_import_name);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_release_name);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_inquire_cred);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_add_cred);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_export_sec_context);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_import_sec_context);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_inquire_cred_by_mech);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_inquire_names_for_mech);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_inquire_context);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_internal_release_oid);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_wrap_size_limit);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_export_name);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_store_cred);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_inquire_sec_context_by_oid);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_inquire_cred_by_oid);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_set_sec_context_option);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gssspi_set_cred_option);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gssspi_mech_invoke);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_wrap_aead);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_unwrap_aead);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_wrap_iov);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_unwrap_iov);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_wrap_iov_length);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_complete_auth_token);
	/* Services4User (introduced in 1.8) */
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_acquire_cred_impersonate_name);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_add_cred_impersonate_name);
	/* Naming extensions (introduced in 1.8) */
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_display_name_ext);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_inquire_name);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_get_name_attribute);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_set_name_attribute);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_delete_name_attribute);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_export_name_composite);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_map_name_to_any);
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_release_any_name_mapping);
        /* RFC 4401 (introduced in 1.8) */
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_pseudo_random);
	/* RFC 4178 (introduced in 1.8; gss_get_neg_mechs not implemented) */
	GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_set_neg_mechs);
        /* draft-ietf-sasl-gs2 */
        GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_inquire_saslname_for_mech);
        GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_inquire_mech_for_saslname);
        /* RFC 5587 */
        GSS_ADD_DYNAMIC_METHOD(dl, mech, gss_inquire_attrs_for_mech);

	assert(mech_type != GSS_C_NO_OID);

	mech->mech_type = *(mech_type);

	return mech;
}

static gss_mechanism_ext
build_dynamicMechExt(void *dl, const gss_OID mech_type)
{
	gss_mechanism_ext mech_ext;

	mech_ext = (gss_mechanism_ext)calloc(1, sizeof(*mech_ext));
	if (mech_ext == NULL) {
		return NULL;
	}

	GSS_ADD_DYNAMIC_METHOD(dl, mech_ext, gssspi_acquire_cred_with_password);

	return mech_ext;
}

static void
freeMechList(void)
{
	gss_mech_info cf, next_cf;
	OM_uint32 minor;

	for (cf = g_mechList; cf != NULL; cf = next_cf) {
		next_cf = cf->next;
		if (cf->kmodName != NULL)
			free(cf->kmodName);
		if (cf->uLibName != NULL)
			free(cf->uLibName);
		if (cf->mechNameStr != NULL)
			free(cf->mechNameStr);
		if (cf->optionStr != NULL)
			free(cf->optionStr);
		if (cf->mech_type != &cf->mech->mech_type)
			generic_gss_release_oid(&minor, &cf->mech_type);
		if (cf->mech != NULL && cf->freeMech)
			free(cf->mech);
		if (cf->mech_ext != NULL && cf->freeMech)
			free(cf->mech_ext);
		if (cf->dl_handle != NULL)
			(void) krb5int_close_plugin(cf->dl_handle);
		free(cf);
	}
}

/*
 * Register a mechanism.  Called with g_mechListLock held.
 */

/*
 * given the mechanism type, return the mechanism structure
 * containing the mechanism library entry points.
 * will return NULL if mech type is not found
 * This function will also trigger the loading of the mechanism
 * module if it has not been already loaded.
 */
gss_mechanism
gssint_get_mechanism(oid)
const gss_OID oid;
{
	gss_mech_info aMech;
	gss_mechanism (*sym)(const gss_OID);
	struct plugin_file_handle *dl;
	struct errinfo errinfo;

	if (gssint_mechglue_initialize_library() != 0)
		return (NULL);

	if (k5_mutex_lock(&g_mechListLock) != 0)
		return NULL;
	/* check if the mechanism is already loaded */
	if ((aMech = searchMechList(oid)) != NULL && aMech->mech) {
		(void) k5_mutex_unlock(&g_mechListLock);
		return (aMech->mech);
	}

	/*
	 * might need to re-read the configuration file before loading
	 * the mechanism to ensure we have the latest info.
	 */
	updateMechList();

	aMech = searchMechList(oid);

	/* is the mechanism present in the list ? */
	if (aMech == NULL) {
		(void) k5_mutex_unlock(&g_mechListLock);
		return ((gss_mechanism)NULL);
	}

	/* has another thread loaded the mech */
	if (aMech->mech) {
		(void) k5_mutex_unlock(&g_mechListLock);
		return (aMech->mech);
	}

	memset(&errinfo, 0, sizeof(errinfo));

	if (krb5int_open_plugin(aMech->uLibName, &dl, &errinfo) != 0 ||
	    errinfo.code != 0) {
#if 0
		(void) syslog(LOG_INFO, "libgss dlopen(%s): %s\n",
				aMech->uLibName, dlerror());
#endif
		(void) k5_mutex_unlock(&g_mechListLock);
		return ((gss_mechanism)NULL);
	}

	if (krb5int_get_plugin_func(dl, MECH_SYM, (void (**)())&sym,
				    &errinfo) == 0) {
		/* Call the symbol to get the mechanism table */
		aMech->mech = (*sym)(aMech->mech_type);
	} else {
		/* Try dynamic dispatch table */
		aMech->mech = build_dynamicMech(dl, aMech->mech_type);
		aMech->freeMech = 1;
	}
	if (aMech->mech == NULL) {
		(void) krb5int_close_plugin(dl);
#if 0
		(void) syslog(LOG_INFO, "unable to initialize mechanism"
				" library [%s]\n", aMech->uLibName);
#endif
		(void) k5_mutex_unlock(&g_mechListLock);
		return ((gss_mechanism)NULL);
	}

	aMech->dl_handle = dl;

	(void) k5_mutex_unlock(&g_mechListLock);
	return (aMech->mech);
} /* gssint_get_mechanism */

gss_mechanism_ext
gssint_get_mechanism_ext(oid)
const gss_OID oid;
{
	gss_mech_info aMech;

	if (gssint_mechglue_initialize_library() != 0)
		return (NULL);

	if (k5_mutex_lock(&g_mechListLock) != 0)
		return NULL;
	/* check if the mechanism is already loaded */
	if ((aMech = searchMechList(oid)) != NULL && aMech->mech_ext) {
		(void) k5_mutex_unlock(&g_mechListLock);
		return (aMech->mech_ext);
	}

	/*
	 * might need to re-read the configuration file before loading
	 * the mechanism to ensure we have the latest info.
	 */
	updateMechList();

	aMech = searchMechList(oid);

	/* is the mechanism present in the list ? */
	if (aMech == NULL || aMech->dl_handle == NULL) {
		(void) k5_mutex_unlock(&g_mechListLock);
		return ((gss_mechanism_ext)NULL);
	}

	/* has another thread loaded the mech */
	if (aMech->mech_ext) {
		(void) k5_mutex_unlock(&g_mechListLock);
		return (aMech->mech_ext);
	}

	/* Try dynamic dispatch table */
	aMech->mech_ext = build_dynamicMechExt(aMech->dl_handle,
                                               aMech->mech_type);
	if (aMech->mech_ext == NULL) {
		(void) k5_mutex_unlock(&g_mechListLock);
		return ((gss_mechanism_ext)NULL);
	}

	(void) k5_mutex_unlock(&g_mechListLock);
	return (aMech->mech_ext);
} /* gssint_get_mechanism_ext */

/*
 * this routine is used for searching the list of mechanism data.
 *
 * this needs to be called with g_mechListLock held.
 */
static gss_mech_info searchMechList(oid)
const gss_OID oid;
{
	gss_mech_info aMech = g_mechList;

	/* if oid is null -> then get default which is the first in the list */
	if (oid == GSS_C_NULL_OID)
		return (aMech);

	while (aMech != NULL) {
		if (g_OID_equal(aMech->mech_type, oid))
			return (aMech);
		aMech = aMech->next;
	}

	/* none found */
	return ((gss_mech_info) NULL);
} /* searchMechList */


/*
 * loads the configuration file
 * this is called while having a mutex lock on the mechanism list
 * entries for libraries that have been loaded can't be modified
 * mechNameStr and mech_type fields are not updated during updates
 */
static void loadConfigFile(fileName)
const char *fileName;
{
	char buffer[BUFSIZ], *oidStr, *oid, *sharedLib, *kernMod, *endp;
	char *modOptions;
	char sharedPath[sizeof (MECH_LIB_PREFIX) + BUFSIZ];
	char *tmpStr;
	FILE *confFile;
	gss_OID mechOid;
	gss_mech_info aMech, tmp;
	OM_uint32 minor;
	gss_buffer_desc oidBuf;

	if ((confFile = fopen(fileName, "r")) == NULL) {
		return;
	}

	(void) memset(buffer, 0, sizeof (buffer));
	while (fgets(buffer, BUFSIZ, confFile) != NULL) {

		/* ignore lines beginning with # */
		if (*buffer == '#')
			continue;

		/*
		 * find the first white-space character after
		 * the mechanism name
		 */
		oidStr = buffer;
		for (oid = buffer; *oid && !isspace(*oid); oid++);

		/* Now find the first non-white-space character */
		if (*oid) {
			*oid = '\0';
			oid++;
			while (*oid && isspace(*oid))
				oid++;
		}

		/*
		 * If that's all, then this is a corrupt entry. Skip it.
		 */
		if (! *oid)
			continue;

		/* Find the end of the oid and make sure it is NULL-ended */
		for (endp = oid; *endp && !isspace(*endp); endp++)
			;

		if (*endp) {
			*endp = '\0';
		}

		/*
		 * check if an entry for this oid already exists
		 * if it does, and the library is already loaded then
		 * we can't modify it, so skip it
		 */
		oidBuf.value = (void *)oid;
		oidBuf.length = strlen(oid);
		if (generic_gss_str_to_oid(&minor, &oidBuf, &mechOid)
			!= GSS_S_COMPLETE) {
#if 0
			(void) syslog(LOG_INFO, "invalid mechanism oid"
					" [%s] in configuration file", oid);
#endif
			continue;
		}

		aMech = searchMechList(mechOid);
		if (aMech && aMech->mech) {
			generic_gss_release_oid(&minor, &mechOid);
			continue;
		}

		/* Find the start of the shared lib name */
		for (sharedLib = endp+1; *sharedLib && isspace(*sharedLib);
			sharedLib++)
			;

		/*
		 * If that's all, then this is a corrupt entry. Skip it.
		 */
		if (! *sharedLib) {
			generic_gss_release_oid(&minor, &mechOid);
			continue;
		}

		/*
		 * Find the end of the shared lib name and make sure it is
		 *  NULL-terminated.
		 */
		for (endp = sharedLib; *endp && !isspace(*endp); endp++)
			;

		if (*endp) {
			*endp = '\0';
		}

		/* Find the start of the optional kernel module lib name */
		for (kernMod = endp+1; *kernMod && isspace(*kernMod);
			kernMod++)
			;

		/*
		 * If this item starts with a bracket "[", then
		 * it is not a kernel module, but is a list of
		 * options for the user module to parse later.
		 */
		if (*kernMod && *kernMod != '[') {
			/*
			 * Find the end of the shared lib name and make sure
			 * it is NULL-terminated.
			 */
			for (endp = kernMod; *endp && !isspace(*endp); endp++)
				;

			if (*endp) {
				*endp = '\0';
			}
		} else
			kernMod = NULL;

		/* Find the start of the optional module options list */
		for (modOptions = endp+1; *modOptions && isspace(*modOptions);
			modOptions++);

		if (*modOptions == '[')  {
			/* move past the opening bracket */
			for (modOptions = modOptions+1;
			    *modOptions && isspace(*modOptions);
			    modOptions++);

			/* Find the closing bracket */
			for (endp = modOptions;
				*endp && *endp != ']'; endp++);

			*endp = '\0';
		} else {
			modOptions = NULL;
		}

		snprintf(sharedPath, sizeof(sharedPath), "%s%s", MECH_LIB_PREFIX, sharedLib);

		/*
		 * are we creating a new mechanism entry or
		 * just modifying existing (non loaded) mechanism entry
		 */
		if (aMech) {
			/*
			 * delete any old values and set new
			 * mechNameStr and mech_type are not modified
			 */
			if (aMech->kmodName) {
				free(aMech->kmodName);
				aMech->kmodName = NULL;
			}

			if (aMech->optionStr) {
				free(aMech->optionStr);
				aMech->optionStr = NULL;
			}

			if ((tmpStr = strdup(sharedPath)) != NULL) {
				if (aMech->uLibName)
					free(aMech->uLibName);
				aMech->uLibName = tmpStr;
			}

			if (kernMod) /* this is an optional parameter */
				aMech->kmodName = strdup(kernMod);

			if (modOptions) /* optional module options */
				aMech->optionStr = strdup(modOptions);

			/* the oid is already set */
			generic_gss_release_oid(&minor, &mechOid);
			continue;
		}

		/* adding a new entry */
		aMech = calloc(1, sizeof (struct gss_mech_config));
		if (aMech == NULL) {
			generic_gss_release_oid(&minor, &mechOid);
			continue;
		}
		aMech->mech_type = mechOid;
		aMech->uLibName = strdup(sharedPath);
		aMech->mechNameStr = strdup(oidStr);
		aMech->freeMech = 0;

		/* check if any memory allocations failed - bad news */
		if (aMech->uLibName == NULL || aMech->mechNameStr == NULL) {
			if (aMech->uLibName)
				free(aMech->uLibName);
			if (aMech->mechNameStr)
				free(aMech->mechNameStr);
			generic_gss_release_oid(&minor, &mechOid);
			free(aMech);
			continue;
		}
		if (kernMod)	/* this is an optional parameter */
			aMech->kmodName = strdup(kernMod);

		if (modOptions)
			aMech->optionStr = strdup(modOptions);
		/*
		 * add the new entry to the end of the list - make sure
		 * that only complete entries are added because other
		 * threads might currently be searching the list.
		 */
		tmp = g_mechListTail;
		g_mechListTail = aMech;

		if (tmp != NULL)
			tmp->next = aMech;

		if (g_mechList == NULL)
			g_mechList = aMech;
	} /* while */
	(void) fclose(confFile);
} /* loadConfigFile */
