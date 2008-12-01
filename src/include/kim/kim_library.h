/*
 * Copyright 2005-2008 Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 * require a specific license from the United States Government.
 * It is the responsibility of any person or organization contemplating
 * export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */


#ifndef KIM_LIBRARY_H
#define KIM_LIBRARY_H

#include <kim/kim.h>

/*!
 * \defgroup kim_library_reference KIM Library Documentation
 * @{
 */

/*! Do not present user interface */
#define KIM_UI_ENVIRONMENT_NONE 0
/*! Automatically determine what user interface is appropriate (default). */
#define KIM_UI_ENVIRONMENT_AUTO 1
/*! Present a graphical user interface */
#define KIM_UI_ENVIRONMENT_GUI  2
/*! Present a command line user interface */
#define KIM_UI_ENVIRONMENT_CLI  3

/*! An integer describing the type of user interface to use. */
typedef int kim_ui_environment;

/*!
 * \param in_ui_environment   an integer value describing the type of user interface to use.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \note Set to KIM_UI_ENVIRONMENT_AUTO by default.
 * \brief Tell KIM how to present UI from your application.
 */
kim_error kim_library_set_ui_environment (kim_ui_environment in_ui_environment);

/*!
 * \param in_allow_access   a boolean containing whether or not to touch the user's home directory.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \note This API is usually used for Kerberos authenticated home directories to prevent a deadlock.
 * \brief Tells KIM whether or not it is allowed to touch the user's home directory.
 */
kim_error kim_library_set_allow_home_directory_access (kim_boolean in_allow_access);

/*!
 * \param in_allow_automatic_prompting   a boolean containing whether or not to prompt automatically.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Tells KIM whether or not it is allowed to automatically present user interface.
 */
kim_error kim_library_set_allow_automatic_prompting (kim_boolean in_allow_automatic_prompting);

/*!
 * \param in_application_name   a string containing the localized name of your application.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \note On many operating systems KIM can determine the caller's application
 * name automatically.  This call exists for applications to use when those
 * mechanisms fail or do not exist.
 * \brief Set the name of your application for KIM to use for user interface.
 */
kim_error kim_library_set_application_name (kim_string in_application_name);

/*!@}*/

#endif /* KIM_LIBRARY_H */
