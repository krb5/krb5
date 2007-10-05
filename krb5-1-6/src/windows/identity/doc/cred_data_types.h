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

/*! \page cred_data_types Data types in Network Identity Manager

    Network Identity Manager's Credentials Database supports several
    useful data types.  In addition, plug-ins can define custom data
    types.  Only a few operations are expected of these data types
    since the core KCDB delegates fine grained operations to other
    entities that understand the underlying format.

    A field in a credential can have any one of these data types, but
    it must have some data type.  Each value can be at most \a
    KCDB_TYPE_MAXCB bytes in length regardless of the data type.

    Some data types have a fixed size (such as \a Int32), while others
    are variable size.  The required memory for each field in a
    credential is allocated as needed.

    \section kcdb_pg_dt Data types

    Descriptions of individual data types are below.

    \subsection kcdb_pg_idt Individual data types

    \subsubsection kcdb_pg_idt_v Void

    Type identifier : ::KCDB_TYPE_VOID

    The Void data type is used to indicate that the associated object
    does not contain any data.

    \subsubsection kcdb_pg_idt_s String

    Type identifier : ::KCDB_TYPE_STRING

    A unicode string that is terminated with a unicode NULL (L'\\0').
    By default, the type has the following flags:

    \a KCDB_TYPE_FLAG_CB_AUTO

    This is because, as long as the string is terminated with a unicode NULL,
    the length of the string, and therefore it's size in bytes, can be inferred
    from the data itself.

    \subsubsection kcdb_pg_idt_d Date

    Type identifier : ::KCDB_TYPE_DATE

    Dates and times in Network Identity Manager are stored in \a
    FILETIME structures.  Utility functions are provided for
    converting from other formats such as \a time_t.

    \subsubsection kcdb_pg_idt_i Interval

    Type identifier : ::KCDB_TYPE_INTERVAL

    Stores an interval of time. Stored as a 64-bit signed integer. The
    string representation of this data type is different from the \a
    Date data type and designates an interval of time.

    The special value _I64_MAX (which is defined in limits.h as
    0x7fffffffffffffff, or in other words, the largest positive value
    that can be stored in a 64-bit signed integer) is used to
    represent an interval of unknown length.

    The string representations of a data value of Interval type are
    defined as follows for English (US):

    - "(Unknown)" if the value is _I64_MAX

    - "(Expired)" if the value is less than zero

    - "%d days %d hours" if the value is greater than 24 hours

    - "%d hours %d mins" if the value is greater than 1 hour

    - "%d mins %d secs" if the value is greater than 1 minute

    - "%d seconds" otherwise

    \subsubsection kcdb_pg_idt_i32 Int32

    Type identifier : ::KCDB_TYPE_INT32

    A signed 32-bit integer.

    \subsubsection kcdb_pg_idt_i64 Int64

    Type identifier : ::KCDB_TYPE_INT64

    A signed 64-bit integer.

    \subsubsection kcdb_pg_idt_da Data

    Type identifier : ::KCDB_TYPE_DATA

    Raw data.  Can contain a byte stream.  This data type can be used
    by plug-ins to associate raw data with a credential.  However,
    there is no built-in string representation for this data type.  As
    such, this is not meant to be used for storing anything that has
    to be displayed to the user verbatim.

    \section kcdb_pg_cust Custom data types

    \subsection kcdb_pg_cb Custom data type call backs

    Custom data types in the Network Identity Manager Credentials
    Database are defined using \a kcdb_type structures that must
    include several callback functions.  The expected behavior of
    these callback functions is documented below.

    \subsubsection kcdb_pg_cb_ts toString

    \code
      khm_int32   toString(
        const void * data,
        khm_int32 cb_data,
        wchar_t *buffer,
        khm_int32 *pcb_buffer,
        khm_int32 flags);
    \endcode

    Produce the localized string representation of the object pointed to by
    \a data.  The size of the data block is specified by the \a cb_data
    parameter.  If the data type specified the \a KCDB_TYPE_FLAG_CB_AUTO flag
    then \a cb_data can be \a KCDB_CBSIZE_AUTO, in which case the size of the
    data block is to be inferred.

    \a toString should assume that the block of data pointed to by \a data is
    valid for this data type.

    The \a pcb_buffer parameter is always a valid pointer to an \a khm_int32
    variable.

    The \a buffer parameter is a pointer to a \a wchar_t buffer which is to
    receive the unicode string representing the object.  \a buffer may be
    \a NULL, in which case the required size of the buffer should be returned
    in \a pcb_buffer.  In this case, the function should return
    \a KHM_ERROR_TOO_LONG.

    If the \a buffer parameter is not \a NULL and the \a pcb_buffer specifies
    that the buffer is large enough to hold the string representation, the
    function should copy the string representation to the buffer, set the
    \a pcb_buffer to the number of bytes that were copied including the
    terminating \a NULL, and return \a KHM_ERROR_SUCCESS.

    If the \a buffer parameter is not \a NULL and the \a pcb_buffer specifies
    a buffer that is not large enough, the function should set \a pcb_buffer
    to the required size (including the terminating \a NULL) and then return
    \a KHM_ERROR_TOO_LONG.

    \subsubsection kcdb_pg_cb_cmp comp

    \code
      khm_int32 comp(
        const void * data1,
        khm_int32 cb_data1,
        const void * data2,
        khm_int32 cb_d2);
    \endcode

    Compares two objects and returns a value indicating the relative ordering.

    Since the KCDB does not interpret any data type, it relies on a loose
    definition of what a relative ordering is.  It is left up to each data
    type callback to interpret what 'ascending' and 'descending' mean.

    The return value \a r should be as follows:

    \a r < 0 : if \a data1 < \a data2

    \a r > 0 : if \a data1 > \a data2

    \a r = 0 : if \a data1 = \a data2 or no relative ordering can be determined
    for the two objects \a data1 and \a data2.

    The function should assume that both objects are valid for this data type.

    The size specifiers \a cb_data1 and \a cb_data2 can (either or both) be
    \a KCDB_CBSIZE_AUTO if the data type specified \a KCDB_TYPE_FLAG_CB_AUTO
    flag.

    \subsubsection kcdb_pg_cb_dup dup

    \code
      khm_int32 dup(
        const void * d_src,
        khm_int32 cb_src,
        void * d_dst,
        khm_int32 * pcb_dst);
    \endcode

    Duplicate an object.  The object pointed to by \a d_src is to be copied to
    the buffer pointed to by \a d_dst.  The function is to assume that \a d_src
    object is valid.  The size specifier \a cb_src may be \a KCDB_CBSIZE_AUTO
    if \a KCDB_TYPE_FLAG_CB_AUTO was specified for the data type.

    If \a d_dst pointer is \a NULL, then the required buffer size should be
    returned in \a pcb_dst.  In this case, the function itself should return
    \a KHM_ERROR_TOO_LONG.  The same behavior should occur if \a d_dst is non
    \a NULL and \a pcb_dst indicates that the buffer is not sufficient.

    If \a d_dst is not \a NULL and \a pcb_dst indicates that the buffer is
    sufficient, then a copy of the object in \a d_src should be placed in
    \a d_dst.  The function shold return \a KHM_ERROR_SUCCESS and set
    \a pcb_dst to the number of bytes that were copied.

    This callback will only be called when the credentials database is
    retrieving objects from the outside.  Once it receives an object it may be
    copied or moved as required.  Hence the object should not assume to reside
    in a specific location of memory.  Also, \a dup is not intended to perform
    such functions as reference counting which require knowledge of a precise
    number of instances of an object, as the credentials database may copy
    the object simply by copying the block of memory.

    Note that whenever \a pcb_dst is to be set, it MUST be set to a valid byte
    count.  It can not be assigned \a KCDB_CBSIZE_AUTO even if the data type
    supports it.  The \a pcb_dst parameter is used internally to allocate
    memory for the object.
    
    \subsubsection kcdb_pg_cb_iv isValid

    \code
      khm_boolean isValid(
        const void * data,
        khm_int32 cb_data);
    \endcode

    Checks if the object pointed to by the \a data pointer is a valid object
    for this data type.  If the data type specified the \a KCDB_TYPE_CB_AUTO
    flag, then the \a cb_data parameter may be \a KCDB_CBSIZE_AUTO, in which
    the size of the object should be inferred from the data.

    The function should be able to determine the validity of the object and
    return \a TRUE if it is valid.  Return \a FALSE if it isn't, or if the
    size of the object can not be inferred from the given data, or if the
    inferred size exceeds \a KCDB_TYPE_MAXCB.

*/
