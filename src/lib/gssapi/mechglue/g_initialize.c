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
#include "gss_libinit.h"
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#define	M_DEFAULT	"default"

#include "k5-thread.h"

/* Local functions */
static gss_mech_info searchMechList(const gss_OID);
static void updateMechList(void);
static void register_mech(gss_mechanism, const char *, void *);

static OM_uint32 build_mechSet(void);
static void init_hardcoded(void);

/*
 * list of mechanism libraries and their entry points.
 * the list also maintains state of the mech libraries (loaded or not).
 */
static gss_mech_info g_mechList = NULL;
static gss_mech_info g_mechListTail = NULL;
static k5_mutex_t g_mechListLock = K5_MUTEX_PARTIAL_INITIALIZER;

static gss_OID_set_desc g_mechSet = { 0, NULL };
static k5_mutex_t g_mechSetLock = K5_MUTEX_PARTIAL_INITIALIZER;

int
gssint_mechglue_init(void)
{
	int err;

	err = k5_mutex_finish_init(&g_mechSetLock);
	return k5_mutex_finish_init(&g_mechListLock);
}

void
gssint_mechglue_fini(void)
{
	k5_mutex_destroy(&g_mechSetLock);
	k5_mutex_destroy(&g_mechListLock);
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

	if (gssint_initialize_library())
		return GSS_S_FAILURE;

	if (minor_status == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	*minor_status = 0;

	k5_mutex_lock(&g_mechListLock);
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
					aMech->mech->context,
					minor_status, oid);
			if (major == GSS_S_COMPLETE) {
				k5_mutex_unlock(&g_mechListLock);
				return (GSS_S_COMPLETE);
			}
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
gss_indicate_mechs(minorStatus, mechSet)
OM_uint32 *minorStatus;
gss_OID_set *mechSet;
{
	int i, j;
	gss_OID curItem;

	/* Initialize outputs. */

	if (minorStatus != NULL)
		*minorStatus = 0;

	if (mechSet != NULL)
		*mechSet = GSS_C_NO_OID_SET;

	/* Validate arguments. */
	if (minorStatus == NULL || mechSet == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	if (gssint_initialize_library())
		return GSS_S_FAILURE;

	if (build_mechSet())
		return GSS_S_FAILURE;

	/*
	 * the mech set is created and it is up to date
	 * so just copy it to caller
	 */
	if ((*mechSet =
		(gss_OID_set) malloc(sizeof (gss_OID_set_desc))) == NULL)
	{
		return (GSS_S_FAILURE);
	}

	/*
	 * need to lock the g_mechSet in case someone tries to update it while
	 * I'm copying it.
	 */
	(void) k5_mutex_lock(&g_mechSetLock);

	/* allocate space for the oid structures */
	if (((*mechSet)->elements =
		(void*) calloc(g_mechSet.count, sizeof (gss_OID_desc)))
		== NULL)
	{
		(void) k5_mutex_unlock(&g_mechSetLock);
		free(*mechSet);
		*mechSet = NULL;
		return (GSS_S_FAILURE);
	}

	/* now copy the oid structures */
	(void) memcpy((*mechSet)->elements, g_mechSet.elements,
		g_mechSet.count * sizeof (gss_OID_desc));

	(*mechSet)->count = g_mechSet.count;

	/* still need to copy each of the oid elements arrays */
	for (i = 0; i < (*mechSet)->count; i++) {
		curItem = &((*mechSet)->elements[i]);
		curItem->elements =
			(void *) malloc(g_mechSet.elements[i].length);
		if (curItem->elements == NULL) {
			(void) k5_mutex_unlock(&g_mechSetLock);
			/*
			 * must still free the allocated elements for
			 * each allocated gss_OID_desc
			 */
			for (j = 0; j < i; j++) {
				free((*mechSet)->elements[j].elements);
			}
			free((*mechSet)->elements);
			free(*mechSet);
			*mechSet = NULL;
			return (GSS_S_FAILURE);
		}
		g_OID_copy(curItem, &g_mechSet.elements[i]);
	}
	(void) k5_mutex_unlock(&g_mechSetLock);
	return (GSS_S_COMPLETE);
} /* gss_indicate_mechs */


static OM_uint32
build_mechSet(void)
{
	gss_mech_info mList;
	int i, count;
	gss_OID curItem;

	/*
	 * lock the mutex since we will be updating
	 * the mechList structure
	 * we need to keep the lock while we build the mechanism list
	 * since we are accessing parts of the mechList which could be
	 * modified.
	 */
	(void) k5_mutex_lock(&g_mechListLock);

	updateMechList();

	/*
	 * we need to lock the mech set so that no one else will
	 * try to read it as we are re-creating it
	 */
	(void) k5_mutex_lock(&g_mechSetLock);

	/* if the oid list already exists we must free it first */
	if (g_mechSet.count != 0) {
		for (i = 0; i < g_mechSet.count; i++)
			free(g_mechSet.elements[i].elements);
		free(g_mechSet.elements);
		g_mechSet.elements = NULL;
		g_mechSet.count = 0;
	}

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

	/* make sure we have fresh data */
	(void) k5_mutex_lock(&g_mechListLock);
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

	if ((mechStr == NULL) || (strlen(mechStr) == 0) ||
		(strcasecmp(mechStr, M_DEFAULT) == 0))
		return (GSS_S_COMPLETE);

	/* ensure we have fresh data */
	(void) k5_mutex_lock(&g_mechListLock);
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

	/* ensure we have fresh data */
	(void) k5_mutex_lock(&g_mechListLock);
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

	if (gssint_initialize_library())
		return GSS_S_FAILURE;
	if (mechArray == NULL || arrayLen < 1)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	/* ensure we have fresh data */
	(void) k5_mutex_lock(&g_mechListLock);
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

	init_hardcoded();

} /* updateMechList */

/*
 * Register a mechanism.  Called with g_mechListLock held.
 */
static void
register_mech(gss_mechanism mech, const char *namestr, void *dl_handle)
{
	gss_mech_info cf, new_cf;

	new_cf = malloc(sizeof(*new_cf));
	if (new_cf == NULL)
		return;

	memset(new_cf, 0, sizeof(*new_cf));
	new_cf->kmodName = NULL;
	new_cf->uLibName = strdup(namestr);
	new_cf->mechNameStr = strdup(mech->mechNameStr);
	new_cf->mech_type = &mech->mech_type;
	new_cf->mech = mech;
	new_cf->next = NULL;

	if (g_mechList == NULL) {
		g_mechList = new_cf;
		g_mechListTail = new_cf;
		return;
	} else if (mech->priority < g_mechList->mech->priority) {
		new_cf->next = g_mechList;
		g_mechList = new_cf;
		return;
	}
	for (cf = g_mechList; cf != NULL; cf = cf->next) {
		if (cf->next == NULL ||
		    mech->priority < cf->next->mech->priority) {
			new_cf->next = cf->next;
			cf->next = new_cf;
			if (g_mechListTail == cf) {
				g_mechListTail = new_cf;
			}
			break;
		}
	}
}

/*
 * Initialize the hardcoded mechanisms.  This function is called with
 * g_mechListLock held.
 */
static void
init_hardcoded(void)
{
	extern gss_mechanism *krb5_gss_get_mech_configs(void);
	extern gss_mechanism *spnego_gss_get_mech_configs(void);
	gss_mechanism *cflist;
	static int inited;

	if (inited)
		return;

	cflist = krb5_gss_get_mech_configs();
	if (cflist == NULL)
		return;
	for ( ; *cflist != NULL; cflist++) {
		register_mech(*cflist, "<builtin krb5>", NULL);
	}
	cflist = spnego_gss_get_mech_configs();
	if (cflist == NULL)
		return;
	for ( ; *cflist != NULL; cflist++) {
		register_mech(*cflist, "<builtin spnego>", NULL);
	}
	inited = 1;
}


/*
 * given the mechanism type, return the mechanism structure
 * containing the mechanism library entry points.
 * will return NULL if mech type is not found
 * This function will also trigger the loading of the mechanism
 * module if it has not been already loaded.
 */
gss_mechanism
gssint_get_mechanism(gss_OID oid)
{
	gss_mech_info aMech;

	if (gssint_initialize_library())
		return NULL;

	(void) k5_mutex_lock(&g_mechListLock);
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
	} else {
		return NULL;
	}
} /* gssint_get_mechanism */


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
