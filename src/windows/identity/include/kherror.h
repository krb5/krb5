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

/* Exported */
#ifndef __KHIMAIRA_KHERROR_H
#define __KHIMAIRA_KHERROR_H

/*! \defgroup kherror NetIDMgr errors

@{*/
/*! \brief Base for error codes

    NetIDMgr errors range from \a KHM_ERROR_BASE to KHM_ERROR_BASE +
    KHM_ERROR_RANGE, with the exception of KHM_ERROR_SUCCESS and
    KHM_ERROR_NONE.
    */
#define KHM_ERROR_BASE 0x40000000L

/*! \brief Range for error codes

    NetIDMgr errors range from \a KHM_ERROR_BASE to
    KHM_ERROR_BASE + KHM_ERROR_RANGE.
*/
#define KHM_ERROR_RANGE 256L

/*! \defgroup kherror_codes Error codes
  @{*/

/*! \brief No error */
#define KHM_ERROR_NONE 0x00000000L

/*! \brief Success. Same as \a KHM_ERROR_NONE */
#define KHM_ERROR_SUCCESS KHM_ERROR_NONE

/*! \brief The supplied name was invalid */
#define KHM_ERROR_INVALID_NAME      (KHM_ERROR_BASE + 1)

/*! \brief Too much data

    A supplied buffer was invalid, was of insufficient size, or a
    buffer was of a larger size than expected
 */
#define KHM_ERROR_TOO_LONG          (KHM_ERROR_BASE + 2)

/*! \brief One or more parameters supplied to a function were invalid */
#define KHM_ERROR_INVALID_PARAM      (KHM_ERROR_BASE + 3)

/*! \brief A duplicate.

    Usually means that something that should have been unique was
    found to be not.
 */
#define KHM_ERROR_DUPLICATE         (KHM_ERROR_BASE + 4)

/*! \brief An object was not found

    An object referenced in a parameter was not found.
 */
#define KHM_ERROR_NOT_FOUND         (KHM_ERROR_BASE + 5)

/*! \brief The relevant subsystem is not ready

    Indicates that initialization has not been completed for a
    subsystem.
 */
#define KHM_ERROR_NOT_READY         (KHM_ERROR_BASE + 6)

/*! \brief No more resources

    A limited resource has been exhausted.
 */
#define KHM_ERROR_NO_RESOURCES      (KHM_ERROR_BASE + 7)

/*! \brief Type mismatch
 */
#define KHM_ERROR_TYPE_MISMATCH     (KHM_ERROR_BASE + 8)

/*! \brief Already exists

    Usually indicates that an exclusive create operation failed due to
    the existence of a similar object.  Subtly different from
    ::KHM_ERROR_DUPLICATE
 */
#define KHM_ERROR_EXISTS            (KHM_ERROR_BASE + 9)

/*! \brief Operation timed out
 */
#define KHM_ERROR_TIMEOUT           (KHM_ERROR_BASE + 10)

/*! \brief An EXIT message was received
 */
#define KHM_ERROR_EXIT              (KHM_ERROR_BASE + 11)

/*! \brief Unknown or unspecified error
 */
#define KHM_ERROR_UNKNOWN           (KHM_ERROR_BASE + 12)

/*! \brief General error
 */
#define KHM_ERROR_GENERAL           KHM_ERROR_UNKNOWN

/*! \brief An index was out of bounds
 */
#define KHM_ERROR_OUT_OF_BOUNDS     (KHM_ERROR_BASE + 13)

/*! \brief Object already deleted

    One or more objects that were referenced were found to have been
    already deleted.
 */
#define KHM_ERROR_DELETED           (KHM_ERROR_BASE + 14)

/*! \brief Invalid operation

    The operation was not permitted to continue for some reason.
    Usually because the necessary conditions for the operation haven't
    been met yet or the operation can only be performed at certain
    times during the execution of NetIDMgr.
 */
#define KHM_ERROR_INVALID_OPERATION (KHM_ERROR_BASE + 15)

/*! \brief Signature check failed
 */
#define KHM_ERROR_INVALID_SIGNATURE (KHM_ERROR_BASE + 16)

/*! \brief Not implemented yet

    The operation that was attempted involved invoking functionality
    that has not been implemented yet.
 */
#define KHM_ERROR_NOT_IMPLEMENTED   (KHM_ERROR_BASE + 17)

/*! \brief The objects were equivalent
 */
#define KHM_ERROR_EQUIVALENT        (KHM_ERROR_BASE + 18)

/*! \brief No provider exists to service the request
*/
#define KHM_ERROR_NO_PROVIDER       (KHM_ERROR_BASE + 19)

/*! \brief The operation succeeded, but with errors
*/
#define KHM_ERROR_PARTIAL           (KHM_ERROR_BASE + 20)

/*! \brief An incompatibility was found */
#define KHM_ERROR_INCOMPATIBLE      (KHM_ERROR_BASE + 21)

/*! \brief The operation was put on hold

    A request was put on hold or postponed. */
#define KHM_ERROR_HELD              (KHM_ERROR_BASE + 22)

/*@}*/ /*kherror_codes*/

/*! \brief Tests whether a return value indicates success */
#define KHM_SUCCEEDED(rv) ((rv)==KHM_ERROR_NONE)

/*! \brief Tests whether a return value indicates failure */
#define KHM_FAILED(rv) ((rv)!=KHM_ERROR_NONE)

/*@}*/
#endif
