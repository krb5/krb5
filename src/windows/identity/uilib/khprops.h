/*
 * Copyright (c) 2005 Massachusetts Institute of Technology
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/* $Id$ */

#ifndef __KHIMAIRA_KHPROPS_H
#define __KHIMAIRA_KHPROPS_H

#include<prsht.h>

/*********************************************************************
  Property sheets
**********************************************************************/

/*! \addtogroup khui

@{*/

/*!\defgroup khui_pp Property sheets
@{*/

/* forward dcl */
struct tag_khui_property_page;

/*! \brief A property sheet
 */
typedef struct tag_khui_property_sheet {
  PROPSHEETHEADER header;    /*!< property sheet header */
  khm_int32       status;    /*!< status of property sheet.  One of
			       ::KHUI_PS_STATUS_NONE,
			       ::KHUI_PS_STATUS_RUNNING or
			       ::KHUI_PS_STATUS_DONE */

  HWND            hwnd;      /*!< handle to the property sheet window.
			       Only valid when \a status is NOT
			       ::KHUI_PS_STATUS_NONE */

  HWND            hwnd_page; /*!< handle to the current page in the
			       property sheet.  Only valid when \a
			       status is ::KHUI_PS_STATUS_RUNNING */

  khui_action_context ctx;   /*!< Context for the property sheet.  See
			       documentation for
			       ::khui_action_context */

  khm_handle      identity;  /*!< Handle to the associated identity,
                               if applicable */
  khm_int32       credtype;  /*!< Type ID of the credentials type, if
                               applicable */
  khm_handle      cred;      /*!< Handle to the associated credential,
                               if applicable */

  khm_int32       n_pages;   /*!< Number of property pages.
			       Upperbound of ::KHUI_PS_MAX_PSP */

  QDCL(struct tag_khui_property_page);
} khui_property_sheet;

/*! \brief The property sheet hasn't been created yet */
#define KHUI_PS_STATUS_NONE 0

/*! \brief The property sheet is visible and running */
#define KHUI_PS_STATUS_RUNNING 1

/*! \brief The property sheet has completed running.

    At this point, it is safe to call khui_ps_destroy_sheet() to
    destroy the property sheet.
*/
#define KHUI_PS_STATUS_DONE 2

/*! \brief The property sheet is in the process of being destroyed
 */
#define KHUI_PS_STATUS_DESTROY 3

/*! \brief Maximum number of property sheet pages in a property sheet */
#define KHUI_PS_MAX_PSP 16


/*! \brief A property sheet page
 */
typedef struct tag_khui_property_page {
  HPROPSHEETPAGE h_page;
  LPPROPSHEETPAGE p_page;
  HWND           hwnd;
  khm_int32      credtype;
  khm_int32      ordinal;

  LDCL(struct tag_khui_property_page);
} khui_property_page;

/*! \brief Special pseudo credtype for identity page
 */
#define KHUI_PPCT_IDENTITY (-8)

/*! \brief Special pseudo credtype for credential page
 */
#define KHUI_PPCT_CREDENTIAL (-9)

/*! \brief Create a property sheet

    \note Only called by the NetIDMgr application.
 */
KHMEXP khm_int32 KHMAPI
khui_ps_create_sheet(khui_property_sheet ** sheet);

/*! \brief Add a page to a property sheet

    Called by a plugin or the NetIDMgr application to add a page to a
    property sheet.

    Pages can only be added before the property sheet is made visible
    to the user.

    \param[in] sheet The property sheet to add the page to

    \param[in] credtype The credentials type ID of the owner of the
        property page.  This should be set to ::KCDB_CREDTYPE_INVALID
        if the type is not relevant.

    \param[in] ordinal Requested ordinal.  A positive integer which is
        used to order the pages in a property sheet.  The pages are
        ordered based on ordinal first and then alphabetically by
        credentials type name.  If the type is unavailable, then the
        ordering is undefined.  Ordinals for credential type property
        pages can be in the range from 0 to 127.  Ordinals 128 and
        above are reserved.  Passing in 0 will work for credentials
        providers unless they provide more than one property page per
        credential, in which case the ordinal should be used to
        enforce an order.

    \param[in] ppage Pointer to structure that will be passed to
        CreatePropertySheetPage() to create the property page.  The
        structure is not managed by NetIDMgr at all, and must exist
        until the status of the property sheet changes to
        ::KHUI_PS_STATUS_RUNNING.  The same pointer will be found in
        the \a p_page member of the ::khui_property_page structure.

    \param[out] page A pointer will be returned here that will point
        to the newly created khui_property_page structure.  Specify
        NULL if this value is not required.  You can use
        khui_ps_find_page() to retrieve a pointer to the structure
        later.
 */
KHMEXP khm_int32 KHMAPI
khui_ps_add_page(khui_property_sheet * sheet,
                 khm_int32 credtype,
                 khm_int32 ordinal,
                 LPPROPSHEETPAGE ppage,
                 khui_property_page ** page);

/*! \brief Retrieve a property page structure from a property sheet
 */
KHMEXP khm_int32 KHMAPI
khui_ps_find_page(khui_property_sheet * sheet,
                  khm_int32 credtype,
                  khui_property_page ** page);

/*! \brief Display the property sheet

    \note Only called by the NetIDMgr application
 */
KHMEXP HWND KHMAPI
khui_ps_show_sheet(HWND parent,
                   khui_property_sheet * sheet);

/*! \brief Check if the given message belongs to the property sheet

    \note Only called by the NetIDMgr application
 */
KHMEXP LRESULT KHMAPI
khui_ps_check_message(khui_property_sheet * sheet,
                      PMSG msg);

/*! \brief Destroy a property sheet and all associated data structures.

    \note Only called by the NetIDMgr application.
*/
KHMEXP khm_int32 KHMAPI
khui_ps_destroy_sheet(khui_property_sheet * sheet);

KHMEXP khm_int32 KHMAPI
khui_property_wnd_set_record(HWND hwnd_pwnd, khm_handle record);

/*!@}*/
/*!@}*/

#endif
