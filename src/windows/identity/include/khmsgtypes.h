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

#ifndef __KHIMAIRA_KHMSGTYPES_H
#define __KHIMAIRA_KHMSGTYPES_H

/*! \addtogroup kmq
@{*/
/*! \defgroup kmq_msg Message Types
@{*/

/*! \name Global message types
@{*/

/*! \brief System messages.

    All subscribers are subscribed to the system message class by default.

    \see \ref kmq_msg_system
*/
#define KMSG_SYSTEM     0

/*! \brief Ad-hoc messages.

    These are messages that are sent through add hoc publishers and
    subscribers.
*/
#define KMSG_ADHOC      1

/*! \brief NetIDMgr Credentials Database messages

    These messages notify subscribers of events related to the
    credentials database, such as the registration, unregistration and
    modification of identities, attributes, attribute types and
    credential types.  It also provides notifications of changes to
    the root crednetial set.

    \see \ref kmq_msg_kcdb
*/
#define KMSG_KCDB       2

/*! \brief NetIDMgr Module Manager messages
 
    \see \ref kmq_msg_kmm
*/
#define KMSG_KMM        3

/*! \brief NetIDMgr Credential messages

    Notifications of crednetial events.  These are the most important
    events that a credentials provider should respond to.  The
    notifications provide co-oridination between credential providers
    for performing basic credentials management tasks such as
    obtaining new credentials for an identity, deleting credentials
    for an identity, obtaining or deleting credentials of a particular
    type for an identity etc.

    \see \ref cred_msgs
    \see \ref kmq_msg_cred
 */
#define KMSG_CRED       4

/*! \brief Action list messages

    Notifications of changes in action state and firing of custom
    actions.

    \see \ref kmq_msg_act
 */
#define KMSG_ACT        5

/*! \brief Alert messages

    Notifier is the component which displays alerts and error messages
    when the NetIDMgr window is normally in operation and which
    displays balloon prompts when the window is minimized to alert the
    user to important messages such as credentials expiring etc.

    \note This is an internal message class.  Components that are not
        the notifier should not be subscribing to alert messages.

    \see \ref kmq_msg_alert
 */
#define KMSG_ALERT      6

/*! \brief Identity messages

    These are messages that are sent to the identity provider.  These
    are generally dispatched through a specific subscription object
    and are not broadcast.

    \see \ref kmq_msg_ident
 */
#define KMSG_IDENT      7

/*! \brief Base message type ID for customized message types
 */
#define KMSGBASE_USER   16

/*@}*/

/*! \defgroup kmq_msg_system KMSG_SYSTEM subtypes 
@{*/
/*! \brief Generic initialization message

    This message is used by specific components to signal that the
    recipient is to perform initialization tasks.  As a convention,
    the recipient should return KHM_ERROR_SUCCESS if it successfully
    performed the initlization tasks or some other value if it failed
    to do so.  Failure to successfully initialize is usually taken to
    mean that the recipient component is not able to perform its
    function.

    Usually this is the first message to be received by the recipient.

    \see \ref pi_pt_cred_init
 */
#define KMSG_SYSTEM_INIT    1

/*! \brief Generic uninitialization message

    Used by specific components to signal that the recipient should
    perform uninitilization tasks in preparation of termination.  The
    return value of this message is not used.

    Usually this is the last message to be received by the recipient.

    \see \ref pi_pt_cred_exit
 */
#define KMSG_SYSTEM_EXIT    2

/*! \brief Message completion

    This is an internal message
 */
#define KMSG_SYSTEM_COMPLETION 3
/*@}*/

/*! \defgroup kmq_msg_kcdb KMSG_KCDB subtypes 
@{*/
#define KMSG_KCDB_IDENT     1
#define KMSG_KCDB_CREDTYPE  2
#define KMSG_KCDB_ATTRIB    3
#define KMSG_KCDB_TYPE      4

/*! \brief Generic credentials request

    \see ::kcdb_cred_request for more information
 */
#define KMSG_KCDB_REQUEST   256
/*@}*/

/*! \defgroup kmq_msg_kmm KMSG_KMM subtypes
@{*/
#define KMSG_KMM_I_REG      1

#define KMSG_KMM_I_DONE     2
/*@}*/

/*! \defgroup kmq_msg_act KMSG_ACT subtypes
  @{*/

/*! \brief One or more actions changed state

    This message is sent in response to a call to
    khui_enable_actions() or khui_enable_action() and indicates that
    one or more actions have changed their state.
 */
#define KMSG_ACT_ENABLE     1

/*! \brief One or more actions changed check state

    Sent in response to khui_check_radio_action() or
    khui_check_action() and indicates that one or more actions have
    either been checked or unchecked.
 */
#define KMSG_ACT_CHECK      2

/*! \brief Refresh action states

    Sent after a batch of modifications were made to action states.
 */
#define KMSG_ACT_REFRESH    3

/*! \brief A new action was created

    Sent when a new custom action was created.  The \a uparam
    parameter of the message contains the identifier of the newly
    created action.
*/
#define KMSG_ACT_NEW        4

/*! \brief A custom action was deleted

    Sent after a custom action is deleted.  The \a uparam parameter of
    the message contains the identifier of the deleted action.
 */
#define KMSG_ACT_DELETE     5

/*! \brief A custom action has been activated

    When a custom action is activated, then the listener of that
    custom action receives this message.  Note that only the listener
    for that custom action will receive this notification.

    \a uparam of the message is set to the identifier of the custom
    action.
 */
#define KMSG_ACT_ACTIVATE   6

/*! \brief Internal */
#define KMSG_ACT_BEGIN_CMDLINE       128

/*! \brief Internal */
#define KMSG_ACT_CONTINUE_CMDLINE    129

/*! \brief Internal */
#define KMSG_ACT_SYNC_CFG            130

/*! \brief Internal */
#define KMSG_ACT_END_CMDLINE         131

/*@}*/

/*! \defgroup kmq_msg_cred KMSG_CRED subtypes
  @{*/
/*! \brief Root credential set changed
    
    This message is issued when the root credential set successfully
    collected credentials from another credential set.

    \a uparam of the message is set to a bitmask indicating the change
    that occured.  It is a combination of ::KCDB_DELTA_ADD,
    ::KCDB_DELTA_DEL and ::KCDB_DELTA_MODIFY.
 */
#define KMSG_CRED_ROOTDELTA 1

/*! \brief Re-enumerate credentials

    A notice to all credential providers to re-enumerate their
    respective credentials.

    \note May be sent to individual credential subscriptions.
 */
#define KMSG_CRED_REFRESH   2

/*! \brief Change the password

    This message notifies credentials providers that a password change
    request has been received.

    A plug-in handling this message that wishes to participate in the
    password change operation is expected to add a
    ::khui_new_creds_by_type to the list of participants in the
    ::khui_new_creds structure by calling khui_cw_add_type().

    The password change operation requires user interaction.  Any
    plug-ins that are participating in the operation need to provide a
    user-interface.

    Message parameters:
    - \b vparam : pointer to a ::khui_new_creds structure

    \see khui_cw_add_type(), ::khui_new_creds, ::khui_new_creds_by_type
 */
#define KMSG_CRED_PASSWORD  16

/*! \brief Initiate the process of obtaining new credentials

    The UI sends this message to start the process of obtaining new
    credentials.  See \ref cred_acq for more information about
    handling this message.

    A plug-in handling this message that wishes to participate in the
    new credentials acquisition operation is expected to add a
    ::khui_new_creds_by_type to hte list of participants in the
    ::khui_new_creds structure by calling khui_cw_add_type().

    Message parameters:
    - \b vparam : pointer to a ::khui_new_creds structure

    \see \ref cred_acq, khui_cw_add_type(), ::khui_new_creds,
    ::khui_new_creds_by_type
 */
#define KMSG_CRED_NEW_CREDS 17

/*! \brief Renew credentials

    This is a notification sent to individual credentials providers
    that a specified identity's credentials should be renewed.

    A plug-in handling this message that wishes to participate in the
    renew credentials operation is expected to add a
    ::khui_new_creds_by_type to the list of participants in the
    ::khui_new_creds structure by calling khui_cw_add_type().

    Message parameters:
    - \b vparam : Pointer to a khui_new_creds object

    \see khui_cw_add_type(), ::khui_new_creds,
    ::khui_new_creds_by_type
 */
#define KMSG_CRED_RENEW_CREDS       18

/*! \brief Dialog setup

    Once ::KMSG_CRED_NEW_CREDS has been responded to by all the
    credential types, the UI creates the dialog windows using the data
    supplied in the ::khui_new_creds_by_type structures and issues
    this message.  Each credentials provider is expected to respond by
    finalizing dialog creation operations.

    Message parameters:
    - \b vparam : pointer to a ::khui_new_creds structure

    \note May be sent to individual credential subscriptions.
 */
#define KMSG_CRED_DIALOG_SETUP      19

/*! \brief Dialog pre-start

    Sent after all the credentials providers have responded to
    ::KMSG_CRED_DIALOG_SETUP and all the initialization has been
    completed.  Credentials providers are expected to respond to this
    message by loading any default data into the dialog controls for
    each credential type.

    Message parameters:
    - \b vparam : pointer to a ::khui_new_creds structure

    \note May be sent to individual credential subscriptions.
 */
#define KMSG_CRED_DIALOG_PRESTART   20

/*! \brief Dialog start

    A notification that the dialog is now in progress.

    Message parameters:
    - \b vparam : pointer to a ::khui_new_creds structure

    \note May be sent to individual credential subscriptions.
 */
#define KMSG_CRED_DIALOG_START      21

/*! \brief The primary identity of the new credentials dialog has changed

    This message is not sent out by the UI, but is reserved here for
    use by individual credentials providers.  The message may be sent
    from the dialog procedure to the plugin.

    Message parameters:
    - \b vparam : pointer to a ::khui_new_creds structure

    \note Be careful when sending this message.  All messages that are
        not sent by the system should not be sent via broadcast.
        Instead, create a subscription using kmq_create_subscription()
        for the individual plugin that you want to send the message
        and use one of the per-subscription message functions to send
        the actual message.
 */
#define KMSG_CRED_DIALOG_NEW_IDENTITY 22

/*! \brief New credentials options have changed.

    This message is not sent out by the UI, but is reserved here for
    use by individual credentials providers.  The message may be sent
    from the dialog procedure to the plugin.

    Message parameters:
    - \b vparam : pointer to a ::khui_new_creds structure

    \note Be careful when sending this message.  All messages that are
        not sent by the system should not be sent via broadcast.
        Instead, create a subscription using kmq_create_subscription()
        for the individual plugin that you want to send the message
        and use one of the per-subscription message functions to send
        the actual message.
 */
#define KMSG_CRED_DIALOG_NEW_OPTIONS  23

/*! \brief Process dialog

    Sent to all the credential providers to look at the contents of
    the given ::khui_new_creds structure and do any required
    processing.

    If the \a result field in the structure is set to
    ::KHUI_NC_RESULT_PROCESS, then new credentials should be
    obtained using the given data.

    Set the \a response field in the structure to indicate how the UI
    should proceed from here.

    Message parameters:
    - \b vparam : pointer to a ::khui_new_creds structure

    \note May be sent to individual credential subscriptions.
 */
#define KMSG_CRED_PROCESS             24

/*! \brief End a credentials acquisition operation

    A notification that the credentials acquisition operation has
    ended.

    Message parameters:
    - \b vparam : pointer to a ::khui_new_creds structure

    \note May be sent to individual credential subscriptions.
 */
#define KMSG_CRED_END                 25

/*! \brief Import credentials from the operating system

    Notification to all credentials providers to import any available
    credentials from the operating system.

    Message parameters:
    - This message does not have any parameters
*/
#define KMSG_CRED_IMPORT              26

/*! \brief Destroy credentials

    Notification that the specified credentials should be destroyed.
    Once this message has completed processing a ::KMSG_CRED_REFRESH
    message will be issued.

    The credentials that should be destroyed are specified by a
    ::khui_action_context structure.  The context that should be used
    is the selection context.  Hence, the credentials that must be
    destroyed are the ones lised in the credential set (\a credset).

    Message parameters:

    - \b upram : Unused. Zero.

    - \b vparam : pointer to a ::khui_action_context structure which
      describes which credentials need to be destroyed.

 */
#define KMSG_CRED_DESTROY_CREDS     32

#if 0
/*! \brief Parse an identity

    \note May be sent to individual credential subscriptions.
 */
#define KMSG_CRED_IDENT_PARSE       65
#endif

/*! \brief A property page is being launced

    Handlers of this message should determine whether or not they
    should participate in the property sheet and if so, add a
    ::khui_property_page structure to the property sheet.

    Message parameters:
    - \b vparam : pointer to a ::khui_property_sheet structure
 */
#define KMSG_CRED_PP_BEGIN          128

/*! \brief A property page is about to be created

    Message parameters:
    - \b vparam : pointer to a ::khui_property_sheet structure

    \note This message is merely a notification that the property
        sheet is being created.  Handlers should not modify the state
        of the property sheet or pages at this time.
 */
#define KMSG_CRED_PP_PRECREATE      129

/*! \brief A property page has finished processing

    Handlers of this message should remove any ::khui_property_page
    structures they added when processing ::KMSG_CRED_PP_BEGIN.

    Message parameters:
    - \b vparam : pointer to a ::khui_property_sheet structure
 */
#define KMSG_CRED_PP_END            130

/*! \brief A property page has been destroyed

    Message parameters:
    - \b vparam : pointer to a ::khui_property_sheet structure

    \note This is a notification that the property sheet processing
        has been completed and that the property sheet data structures
        should be freed.  Any property page data structures should
        have already been freed while processing KMSG_CRED_PP_END.
        The validity of the ::khui_property_sheet structure should not
        be relied upon while processing this message.
 */
#define KMSG_CRED_PP_DESTROY        131

/*! \brief An IP address change occurred

    There are no parameters for this message.  The NetIDMgr
    application handles this message and depending on configuration,
    posts message for the individual credentials providers to either
    obtain new credentials or renew old ones.
 */
#define KMSG_CRED_ADDR_CHANGE        140

/*! \brief Check if a KMSG_CRED subtype is a credentials acquisition message

    Dialog messages are those that deal with the new or initial
    credentials acquisition dialog, from initial announcement to
    dialog completion.

    Currently, the dialog messages are:
    - ::KMSG_CRED_NEW_CREDS
    - ::KMSG_CRED_RENEW_CREDS
    - ::KMSG_CRED_DIALOG_SETUP
    - ::KMSG_CRED_DIALOG_PRESTART
    - ::KMSG_CRED_DIALOG_START
    - ::KMSG_CRED_DIALOG_NEW_IDENTITY
    - ::KMSG_CRED_DIALOG_NEW_OPTIONS
    - ::KMSG_CRED_PROCESS
    - ::KMSG_CRED_END

    All dialog message numbers are allocated in a contigous block.

    Note that while ::KMSG_CRED_PROCESS and ::KMSG_CRED_END are not
    specific to dialogs, they are still included in this predicate
    because they are also part of the dialog message sequence.
 */
#define IS_CRED_ACQ_MSG(msg) ((msg) >= 16 && (msg) <=31)

/*@}*/ /* /KMSG_CRED subtypes */ 

/*! \defgroup kmq_msg_alert KMSG_ALERT Subtypes 
  @{*/

/*! \brief Show an alert

    Message parameters:
    - \b vparam : held pointer to a ::khui_alert object

    \note The ::khui_alert object will be released when the processing
        of this message completes.
 */
#define KMSG_ALERT_SHOW 1

/*! \brief Add an alert to the alert queue

    Message parameters:
    - \b vparam : held pointer to a ::khui_alert object

    \note the ::khui_alert object will be released when the queued
        messages are displayed.
 */
#define KMSG_ALERT_QUEUE 2

/*! \brief Show the next queued alert

    There are no message parameters
 */
#define KMSG_ALERT_SHOW_QUEUED 3

/*! \brief Check if there are any queued messages and, if so, update the statusbar

    There are no message parameters
 */
#define KMSG_ALERT_CHECK_QUEUE 4

/*! \brief Show a modal alert

    Message parameters:
    - \b vparam : held pointer to a ::khui_alert object.

    \note the ::khui_alert object will be released when the queued
        messages are displayed.
 */
#define KMSG_ALERT_SHOW_MODAL 5

/*@}*/

/*! \defgroup kmq_msg_ident KMSG_IDENT Subtypes
  @{*/

/*! \brief Initialize and start the identity provider


    Sent by the KCDB to notify the identity provider that it is now
    the current identity provider.

    Note that unlike regular plugins, an identity provider can be
    loaded and inert (not provide any services).  Also, the user may
    switch between multiple identity providers on the fly.
 */
#define KMSG_IDENT_INIT                 1

/*! \brief Stop the identity provider

    Sent by the KCDB as notificaton that the identity provider is no
    longer the current provider.
 */
#define KMSG_IDENT_EXIT                 2

/*! \brief Check if an identity name is valid

    This message is sent to the identity provider to verify the syntax
    of an identity name.  Note that only the syntax of the name is to
    be verfied and not the actual physical existence of said identity.

    Message parameters:

    - \b vparam : pointer to ::kcdb_ident_name_xfer object.  The
        name to be validated will be in the \a name_src member.  The
        buffer will be NULL terminated with a maximum limit of
        KCDB_IDENT_MAXCCH_NAME characters including the terminating
        NULL, consisting only of characters in KCDB_IDENT_VALID_CHARS
        The \a result member should be set to one of the following
        depending on the result of the validation:

        - KHM_ERROR_SUCCESS : The name was valid
        - KHM_ERROR_INVALID_NAME : The name was invalid
 */
#define KMSG_IDENT_VALIDATE_NAME        3

/*! \brief Check if an identity is valid

    Sent to the identity provider to verify the validity of the given
    identity.  The provider should verify that the identity exists and
    is in a state where it can be actively used.

    Depending on the result of the validation, the flags of the
    identity should be updated.

    Message parameters:
    - \b vparam : Handle to an identity cast as a void pointer.
 */
#define KMSG_IDENT_VALIDATE_IDENTITY    4

/*! \brief Canonicalize identity name

    The identity provider will be given a name, which it should put in
    canonical form, adjusting case and any character replacement or
    doing any relevant expansions if applicable, and place it in the
    supplied buffer.

    Message parameters:

    - \b vparam : Pointer to a ::kcdb_ident_name_xfer structure
          which provides the identity name to canonicalize in the \a
          name_src member, and the buffer to store the canonical name
          in the \a name_dest member.  The \a name_dest buffer is
          guaranteed to be at least KCDB_IDENT_MAXCCH_NAME characters
          in size.

    If the name cannot be canonicalized for some reason, the
    destination buffer should be set to a zero-length string and the
    \a result member of the ::kcdb_ident_name_xfer structure should be
    set to the error code.  If the destination buffer is set to a
    zero-length string and \a result is KHM_ERROR_SUCCESS, then the
    original name provided in \a name_src is assumed to be already in
    canonical form.
 */
#define KMSG_IDENT_CANON_NAME           5

/*! \brief Compare names

    Compare two identity names.  The names that are given aren't
    guaranteed to be in canonical form.  The return value should be
    akin to strcmp().

    Message parameters: 

    - \b vparam : A pointer to a ::kcdb_ident_name_xfer structure.
        The \a name_src member points at the first name, and the \a
        name_alt member specifies the second name.  The result of the
        comparison should be place in \a result.
 */
#define KMSG_IDENT_COMPARE_NAME         6

/*! \brief Set the default identity

    Set or unset the default identity.  To set the default identity,
    the \a uparam parameter will be set to a non-zero value and a
    handle to the identity will be specified in \a vparam.  To unset
    the default identity (i.e. not have a default identity), a zero
    value will be specified in \a uparam and no identities will be
    specified in \a vparam.

    When setting a default identity, the identity provider will
    receive this message prior to the ::KCDB_IDENT_FLAG_DEFAULT bit
    being set or reset on any identity.  It should return
    KHM_ERROR_SUCCESS if the requested operation can be performed.
    Returning any other value will abort the operation and will leave
    the default identity unchanged.

    When resetting the default identity, this message should be
    treated only as a notification.

    Message parameters:

    - \a uparam : Is non-zero if an identity is being made default.  If
      this is zero, then identity should be the default.

    - \a vparam : A handle to the identity to be made default if \a
      uparam is non-zero.  NULL otherwise.

    Return value:

    - KHM_ERROR_SUCCESS : The identity should be marked as default
    - Any other value : The identity should not be marked as default

 */
#define KMSG_IDENT_SET_DEFAULT          7

/*! \brief Set an identity as searchable

    Set or reset the searchable bit on an identity.  If the \a uparam
    parameter is non-zero, then the searchable bit is being set.
    Otherwise it is being reset.  The identity provider should return
    KHM_ERROR_SUCCESS in order to indicate that the identity should be
    marked as searchable.  Any other value will result in the
    searchable bit being reset on the identity.

    Message parameters:

    - \a uparam : Is non-zero if the searchable bit is being set.  Zero
      otherwise.

    - \a vparam : Handle to the identity

    Return value:

    - KHM_ERROR_SUCCESS: The identity should be marked as searchable
    - Any other value : The identity should not be marked as default
 */
#define KMSG_IDENT_SET_SEARCHABLE       8

/*! \brief Get information about an identity

 */
#define KMSG_IDENT_GET_INFO             9

/*! \brief Enumerate known and accessible identities
 */
#define KMSG_IDENT_ENUM_KNOWN           10

/*! \brief Update information about an identity
 */
#define KMSG_IDENT_UPDATE               11

/*! \brief Retrieve the user interface callback function

    When obtaining new credentials, the user interface needs to obtain
    a callback function which will provide identity selection
    controls.

    Message parameters:

    - \a uparam : Not used

    - \a vparam : pointer to a ::khui_ident_new_creds_cb which will
         receive the call back.
 */
#define KMSG_IDENT_GET_UI_CALLBACK      12

/*! \brief Notification of the creation of an identity

    This should be considered just a notification.  The identit
    provider does not have an opportunity to veto the creation of an
    identity whose name has been found to be valid.  However, when
    handing this notification, the identity provider can:

    - Change the flags of the identity and/or marking the identity as
      invalid.

    - Change the default identity.

    Note that this notification is sent before the general :;KMSG_KCDB
    notification of the identity creation is sent.

    Message parameters:

    - \a uparam : Not used.

    - \p vparam : handle to the identity
 */
#define KMSG_IDENT_NOTIFY_CREATE        13

/*@}*/ /* /KMSG_IDENT subtypes */

/*@}*/ /* / message types */
/*@}*/ /* / kmq */

#endif
