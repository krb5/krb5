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

#ifndef __KHIMAIRA_MSTRING_H
#define __KHIMAIRA_MSTRING_H

#include<khdefs.h>

/*! \addtogroup util
    @{ */

/*! \defgroup util_mstring Multi String and CSV functions
    @{*/

#define KHM_PREFIX 8

#define KHM_CASE_SENSITIVE 16

#define KHM_MAXCCH_STRING 16384

#define KHM_MAXCB_STRING (KHM_MAXCCH_STRING * sizeof(wchar_t))

/*! \brief Initialize a multi-string
 */
KHMEXP khm_int32 KHMAPI
multi_string_init(wchar_t * ms,
                  khm_size cb_ms);

/*! \brief Prepend a string to a multi string

    Adds the string \a str to the beginning of multi-string \a ms.

    \param[in,out] ms  The multi-string to be modified.

    \param[in,out] pcb_ms A pointer to the size of the multistring.
        On entry this specifies the size of the buffer pointed to by
        \a ms.  If the call is successful, on exit this will receive
        the new size of the multi string in bytes.  If the buffer is
        insufficient, the function will return KHM_ERROR_TOO_LONG and
        set this to the required size of the buffer in bytes.

    \param[in] str The string to prepend to \a ms.  This cannot be
        longer than KHM_MAXCCH_STRING in characters including the
        terminating NULL.
 */
KHMEXP khm_int32 KHMAPI 
multi_string_prepend(wchar_t * ms,
                     khm_size * pcb_ms,
                     const wchar_t * str);

/*! \brief Append a string to a multi-string

    Appends the string specified by \a str to the multi string
    specified by \a ms.  The size of the multi string in characters
    including terminating NULLs after appending \a str can not exceed
    KHM_MAXCCH_STRING.

    \param[in] ms The buffer containing the multi string

    \param[in,out] pcb_ms Points to a khm_int32 indicating the size of
        the buffer pointed to by \a ms.  On entry this contains the
        size (in bytes) of the buffer pointed to by \a ms.  On exit,
        contains the new size of the multi string in bytes.

    \param[in] str The string to append to the multi string.  This
        string cannot be NULL or an empty (zero length) string.  The
        length of \a str cannot exceed KHM_MAXCCH_STRING in
        characters including terminating NULL.

    \retval KHM_ERROR_SUCCESS The string was appended to the multi string

    \retval KHM_ERROR_TOO_LONG The buffer pointed to by \a ms was
        insufficient.  The required size of the buffer is in \a pcb_ms

    \retval KHM_ERROR_INVALID_PARAM One of more of the parameters were invalid.
 */
KHMEXP khm_int32 KHMAPI 
multi_string_append(wchar_t * ms,
                    khm_size * pcb_ms,
                    const wchar_t * str);

/*! \brief Deletes a string from a multi string

    Deletes the string specified by \a str from the multi string
    specified by \a ms.  How the string is matched to the strings in
    \a ms is determined by \a flags.  If more than one match is found,
    then only the first match is deleted.

    \param[in] ms The multi string to modify.  The length of the multi
        string in characters cannot exceed KHM_MAXCCH_STRING.
 
    \param[in] str The string to search for

    \param[in] flags How \a str is to be matched to existing strings
        in \a ms.  This could be a combination of KHM_PREFIX and
        KHM_CASE_SENSITIVE. If KHM_PREFIX is used, then \a ms is
        searched for a string that begins with \a str.  Otherwise, \a
        str must match the an entire string in the multi string.  If
        KHM_CASE_SENSITIVE is specified, then a case sensitive match
        is performed.  The defualt is to use a case insensitive
        search.

    \retval KHM_ERROR_SUCCESS A string was matched and deleted from \a ms

    \retval KHM_ERROR_NOT_FOUND No matches were found

    \retval KHM_ERROR_INVALID_PARAM One or more parameters were incorrect.

    \note The search for the existing string is done with
        multi_string_find()
 */
KHMEXP khm_int32 KHMAPI 
multi_string_delete(wchar_t * ms,
                    const wchar_t * str,
                    const khm_int32 flags);

/*! \brief Search a multi string for a string

    Searches the string specified by \a ms for a string that matches
    \a str.  How the match is performed is determined by \a flags.
    Returns a poitner to the start of the matched string in \a ms.  If
    more than one string in \a ms matches \a str, then only the first
    match is returned.

    \param[in] ms The multi string to search in.  The length of the
        multi string cannot exceed KHM_MAXCCH_STRING in characters.

    \param[in] str The string to search for

    \param[in] flags How \a str is to be matched to existing strings
        in \a ms.  This could be a combination of KHM_PREFIX and
        KHM_CASE_SENSITIVE. If KHM_PREFIX is used, then \a ms is
        searched for a string that begins with \a str.  Otherwise, \a
        str must match the an entire string in the multi string.  If
        KHM_CASE_SENSITIVE is specified, then a case sensitive match
        is performed.  The defualt is to use a case insensitive
        search.

    \return A pointer to the start of the first matched string or
        NULL if no matches were found.

 */
KHMEXP wchar_t * KHMAPI 
multi_string_find(const wchar_t * ms,
                  const wchar_t * str,
                  const khm_int32 flags);

/*! \brief Convert a multi string to CSV

    Converts a multi string to a comma separated value string based on
    the following rules.

    - Each string in the multi string is treated an individual field 

    - A field is quoted if it has double quotes or commas 

    - Double quotes within quoted fields are escaped by two
      consecutive double quotes.

    For example:

    \code
    multi_string = L"foo\0bar\0baz,quux\0ab\"cd\0";
    csv_string = L"foo,bar,\"baz,quux\",\"ab\"\"cd\"";
    \endcode

    If multi_string_to_csv() is called on \a multi_string above,
    you would obtain \a csv_string.

    \param[out] csvbuf The buffer to place the CSV string in.  Can be
        NULL if only teh size of the needed buffer is required.

    \param[in,out] pcb_csvbuf On entry, points to a khm_int32 that
        holds the size of the buffer pointed to by \a csvbuf.  On
        exit, gets the number of bytes writted to \a csvbuf or the
        required size of \a csvbuf if the buffer is too small or \a
        csvbuf is NULL.

    \param[in] ms The mutli string to convert to a CSV.

    \retval KHM_ERROR_SUCCESS The multi string was successfully
        converted to a CSV string.  The number of bytes written is in
        \a pcb_csvbuf.  The count includes the terminating NULL.

    \retval KHM_ERROR_TOO_LONG The buffer was too small or \a csvbuf
        was NULL.  The required number of bytes in the buffer is in \a
        pcb_csvbuf.

    \retval KHM_ERROR_INVALID_PARAM One or more parameters were ivnalid.

    \see csv_to_multi_string()
*/
KHMEXP khm_int32 KHMAPI 
multi_string_to_csv(wchar_t * csvbuf,
                    khm_size * pcb_csvbuf,
                    const wchar_t * ms);

/*! \brief Converts a CSV to a multi string

    Undoes what multi_string_to_csv() does.

    \param[out] ms The buffer that recieves the multi string.  This
        can be NULL if only the size of the buffer is requried.

    \param[in,out] pcb_ms On entry contains the number of bytes ni the
        buffer poitned to by \a ms.  On exit contains the number of
        bytes that were copied to \a ms including terminating NULLs,
        or if the buffer was too small or \a ms was NULL, holds the
        size in bytes of the requied buffer.

    \param[in] csv The CSV string.

    \retval KHM_ERROR_SUCCESS The CSV string was successfully
       converted.  The number of bytes written is in \a pcb_ms.

    \retval KHM_ERROR_TOO_LONG The provided buffer was too small or \a
        ms was NULL. The required size of the buffer in bytes is in \a
        pcb_ms.

    \retval KHM_ERROR_INVALID_PARAM One or more parameters were invalid.

 */
KHMEXP khm_int32 KHMAPI 
csv_to_multi_string(wchar_t * ms,
                    khm_size * pcb_ms,
                    const wchar_t * csv);

/*! \brief Get the next string in a multi string

    When \a str is pointing to a string that is in a multi string,
    this function returns a pointer to the next string in the multi
    string.

    Typically, one would start by having \a str point to the start of
    the multi string (which is the first string in the multi string),
    and then call this function repeatedly, until it returns NULL, at
    which point the end of the multi string has been reached.

    \param[in] str Pointer to a string in a multi string.  Each string
        in a multi string cannot exceed KHM_MAXCCH_STRING in charaters
        including the terminating NULL.

    \return A pointer to the start of the next string in the multi
        string or NULL if there is no more strings.
 */
KHMEXP wchar_t * KHMAPI 
multi_string_next(const wchar_t * str);

/*! \brief Get the length of a multi string in bytes

    The returned length includes the trailing double \a NULL and any
    other \a NULL inbetween.

    \param[in] str Pointer to a multi string.
    \param[in] max_cb Maximum size that the str can be.  This can not
        be larger than KHM_MAXCB_STRING.
    \param[out] len_cb The length of the string in bytes if the call
        is successful.

    \retval KHM_ERROR_SUCCESS The length of the string is in \a len_cb
    \retval KHM_ERROR_INVALID_PARAM One or more parameters were invalid
    \retval KHM_ERROR_TOO_LONG The multi string is longer than \a
        max_cb bytes.
 */
KHMEXP khm_int32 KHMAPI 
multi_string_length_cb(const wchar_t * str, 
                       khm_size max_cb, 
                       khm_size * len_cb);

/*! \brief Get the length of a multi string in characters

    The returned length includes the trailing double \a NULL and any
    other \a NULL inbetween.

    \param[in] str Pointer to a multi string.
    \param[in] max_cch Maximum size that the str can be.  This can not
        be larger than KHM_MAXCCH_STRING.
    \param[out] len_cch The length of the string in characters if the call
        is successful.

    \retval KHM_ERROR_SUCCESS The length of the string is in \a len_cch
    \retval KHM_ERROR_INVALID_PARAM One or more parameters were invalid
    \retval KHM_ERROR_TOO_LONG The multi string is longer than \a
        max_cch characters.
 */
KHMEXP khm_int32 KHMAPI 
multi_string_length_cch(const wchar_t * str, 
                        khm_size max_cch, 
                        khm_size * len_cch);

/*! \brief Get the number of strings in a multi string
 */
KHMEXP khm_size KHMAPI 
multi_string_length_n(const wchar_t * str);

/*! \brief Copy a multi string with byte counts

    Copy a multi string from one location to another.

    \param[out] s_dest Receives a copy of the multi string
    \param[in] max_cb_dest Number of bytes in the buffer pointed to by
        \a s_dest.
    \param[in] src The source multi string

    \retval KHM_ERROR_SUCCESS The multi string was copied successfully
    \retval KHM_ERROR_INVALID_PARAM One or more parameters were
        invalid.
    \retval KHM_ERROR_TOO_LONG The size of the destination buffer was
        insufficient.
 */
KHMEXP khm_int32 KHMAPI 
multi_string_copy_cb(wchar_t * s_dest, 
                     khm_size max_cb_dest, 
                     const wchar_t * src);

/*! \brief Copy a multi string with character count

    Copy a multi string from one location to another.

    \param[out] s_dest Receives a copy of the multi string
    \param[in] max_cb_dest Number of characters in the buffer pointed
        to by \a s_dest.
    \param[in] src The source multi string

    \retval KHM_ERROR_SUCCESS The multi string was copied successfully
    \retval KHM_ERROR_INVALID_PARAM One or more parameters were
        invalid.
    \retval KHM_ERROR_TOO_LONG The size of the destination buffer was
        insufficient.
 */
KHMEXP khm_int32 KHMAPI 
multi_string_copy_cch(wchar_t * s_dest, 
                      khm_size max_cch_dest, 
                      const wchar_t * src);

/*@}*/

#endif
