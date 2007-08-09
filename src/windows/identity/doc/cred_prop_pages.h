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

   - A global message is broadcast of type
     <::KMSG_CRED,::KMSG_CRED_PP_BEGIN> with the parameter blob that
     is a pointer to the ::khui_property_sheet structure.

   - Subscribers to <::KMSG_CRED> messages handle the message, check
     the \a ctx member of the structure and determine whether or not
     and what type property pages to add to the property sheet.  New
     property sheets are added by calling khui_ps_add_page().

   - Once all the pages are added, a
     <::KMSG_CRED,::KMSG_CRED_PP_PRECREATE> message is broadcast.
     This is a chance for the property page providers to do any
     processing before the property page is created.

   - The property sheet is created and made visible with a call to
     khui_ps_show_sheet().

   - The Network Identity Manager message loop takes over.  Further interaction
     including notifications of 'Ok','Cancel','Apply' and other
     property sheet related actions are handled through WIN32
     messages.

   - Once the user closes the property sheet, a
     <::KMSG_CRED,::KMSG_CRED_PP_END> message is sent to all
     subscribers.  Individual subscribers who added pages to the
     property sheet must free up any associated resources at this
     point.

   - All the ::khui_property_page structures that were allocated as
     well as the ::khui_property_sheet structure are freed up with a
     call to khui_ps_destroy_sheet().

The maximum number of property sheets that can be open at one time is
currently set to 256.  Each property sheet can have a maximum of 16
property pages.
 */
