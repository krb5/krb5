/*
 * Copyright (c) 2005 Massachusetts Institute of Technology
 * Copyright (c) 2007 Secure Endpoints Inc.
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

/*! \page cred_prop_pages Property Pages for Credentials

   This section describes the logistics of property pages.  When a
   user selects the 'Properties' option from a menu (either the File
   menu or a context menu), then a KHUI_ACTION_PROPERTIES action is
   triggered.  This is handled by the credentials window and triggers
   the launch of a property sheet if there is a valid context to
   extract properties from.

   Sequence of actions:

   - KHUI_ACTION_PROPERTIES action is triggered.

   - The main window dispatches the action to the credentials window.

   - If there is a valid context, then the credentials window calls
     khui_ps_create_sheet() to create an empty property sheet
     structure of type ::khui_property_sheet.  The \a ctx member of
     the structure is populated with the property context obtained
     through khui_context_get().

     In addition to the \c ctx member, depending on the scope of the
     context, other fields of the ::khui_property_sheet structure
     could also be set:

     - For ::KHUI_SCOPE_IDENT, the \c identity field will be set to
       the selected identity.

     - For ::KHUI_SCOPE_CREDTYPE, the \c identity field will be set to
       the selected identity, and the \c credtype field will be set to
       the selected credential type.

     - For ::KHUI_SCOPE_CRED, in addition to the \c identity and \c
       credtype fields being set as above, the \c cred field will be
       set to a handle to the credential.

   - A global message is broadcast of type
     <::KMSG_CRED,::KMSG_CRED_PP_BEGIN> with the parameter blob that
     is a pointer to the ::khui_property_sheet structure.

     - Subscribers to <::KMSG_CRED> messages handle the message, check
       the ::khui_property_sheet structure and determine whether or
       not and what type property pages to add to the property sheet.
       New property sheets are added by calling khui_ps_add_page().

       The following code shows how this message might be handled.

       \code

       // Message handler code for KMSG_CRED_PP_BEGIN

       khui_property_sheet * ps;
       PROPSHEETPAGE       * psp;     // from prsht.h

       if (ps->credtype == credtype_id &&
           ps->cred) {

           // We have been requested to show a property sheet for one of
           // our credentials.

           // The PROPSHEETPAGE structure has to exist until we remove the
           // property sheet page when we are handling KMSG_CRED_PP_END.

           psp = malloc(sizeof(*psp));
           ZeroMemory(p, sizeof(*psp));

           psp->dwSize = sizeof(*psp);
           psp->dwFlags = 0;

           // hResModule is the handle to the resource module
           psp->hInstance = hResModule;

           // IDD_PP_CRED is the dialog template for our property page
           psp->pszTemplate = MAKEINTRESOURCE(IDD_PP_CRED);

           // pp_cred_dlg_proc is the message handler for our property
           // page.  See the Platform SDK for details.
           psp->pfnDlgProc = pp_cred_dlg_proc;

           // We can pass the khui_property_sheet structure as the
           // lParam for the message handler so it knows the scope of
           // the property sheet.
           psp->lParam = (LPARAM) ps;

           // Finally, add a property page for our credential type
           // stored in credtype_id.  Note that only one property page
           // can be added per credential type.

           khui_ps_add_page(ps, credtype_id, 0, psp, NULL);

           return KHM_ERROR_SUCCESS;
       }

       \endcode

   - Once all the plug-ins have had a chance to add their property
     sheets, a <::KMSG_CRED,::KMSG_CRED_PP_PRECREATE> message is
     broadcast.  This is a chance for the property page providers to
     do any processing before the property page is created.

   - The property sheet is created and made visible with a call to
     khui_ps_show_sheet().

   - The Network Identity Manager message loop takes over.  Further
     interaction including notifications of 'Ok','Cancel','Apply' and
     other property sheet related actions are handled through WIN32
     messages to the window procedure of the property sheet and the
     message handlers for the individual property pages.

   - Once the user closes the property sheet, a
     <::KMSG_CRED,::KMSG_CRED_PP_END> message is sent to all
     subscribers.  Individual subscribers who added pages to the
     property sheet must free up any associated resources at this
     point.

     Continuing our example from above, the following code could be
     used to handle this message:

     \code

     // Handler for KMSG_CRED_PP_END

     khui_property_page * p = NULL;

     // If a property sheet was added by us, this call would get
     // a handle to the property page structure.

     if (KHM_SUCCEEDED(khui_ps_find_page(ps, credtype_id, &p))) {

         // It is safe to assume that the property page window has
         // been destroyed by the time we receive KMSG_CRED_PP_END.
         // So we can free the PROPSHEETPAGE structure we allocated
         // above.

         if (p->p_page)
             free(p->p_page);
         p->p_page = NULL;

         // The property page structure we added will automatically
         // be removed and freed by the application.
     }

     return KHM_ERROR_SUCCESS;
     \endcode

   - All the ::khui_property_page structures that were allocated as
     well as the ::khui_property_sheet structure are freed up with a
     call to khui_ps_destroy_sheet().

\note The maximum number of property sheets that can be open at one
time is currently set to 256.  Each property sheet can have a maximum
of 16 property pages.
 */
