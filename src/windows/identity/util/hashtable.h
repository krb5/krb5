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

#ifndef __KHIMAIRA_HASHTABLE_H
#define __KHIMAIRA_HASHTABLE_H

/*! \addtogroup util
  @{ */

/*! \defgroup util_ht Hashtable
  @{*/

#include<khdefs.h>
#include<khlist.h>

/*! \brief A hash function

    The function should take a key as a parameter and return an
    khm_int32 that serves as the hash of the key.
 */
typedef khm_int32 (*hash_function_t)(const void *key);

/*! \brief A comparison function

    The function takes two keys and returns a value indicating the
    relative ordering of the two keys.

    The return value should be:
    - \b Zero if \a key1 == \a key2
    - \b Negative if \a key1 &lt; \a key2
    - \b Positive if \a key1 &gt; \a key2
 */
typedef khm_int32 (*comp_function_t)(const void *key1, const void *key2);

/*! \brief Add-reference function

    When an object is successfully added to a hashtable, this function
    will be called with the \a key and \a data used to add the object.
    The function is allowed to modify \a data, however, the
    modification should not alter the \a key or the relationship
    between \a key and \a data.
 */
typedef void (*add_ref_function_t)(const void *key, void *data);

/*! \brief Delete-reference function

    When an object is successfully removed from the hashtable, this
    function will be called.  As with the add-ref function, the object
    can be modified, but the \a key and the relationship between \a
    key and \a data should remain intact.

    An object is removed if it is explicitly removed from the
    hashtable or another object with the same \a key is added to the
    hashtable.  There should be a 1-1 correspondence with keys and
    objects in the hashtable.  The delete-reference function will be
    called on all the remaining objects in the hashtable when the
    hashtable is deleted.
 */
typedef void (*del_ref_function_t)(const void *key, void *data);

typedef struct tag_hash_bin {
    void * data;
    const void * key;

    LDCL(struct tag_hash_bin);
} hash_bin;

typedef struct hashtable_t {
    khm_int32 n;
    hash_function_t hash;
    comp_function_t comp;
    add_ref_function_t addr;
    del_ref_function_t delr;
    hash_bin ** bins;
} hashtable;

/*! \brief Create a new hashtable

    \param[in] n Number of bins in hashtable.
    \param[in] hash A hash function. Required.
    \param[in] comp A comparator.  Required.
    \param[in] addr An add-ref function.  Optional; can be NULL.
    \param[in] delr A del-ref function. Optional; can be NULL.

 */
KHMEXP hashtable * KHMAPI hash_new_hashtable(khm_int32 n, 
                               hash_function_t hash, 
                               comp_function_t comp,
                               add_ref_function_t addr,
                               del_ref_function_t delr);

/*! \brief Delete a hashtable

    \note Not thread-safe.  Applications must serialize calls that
        reference the same hashtable.
 */
KHMEXP void KHMAPI hash_del_hashtable(hashtable * h);

/*! \brief Add an object to a hashtable

    Creates an association between the \a key and \a data in the
    hashtable \a h.  If there is an add-ref function defined for the
    hashtable, it will be called with \a key and \data after the
    object is added.  If there is already an object with the same key
    in the hashtable, that object will be removed (and the del-ref
    function called, if appilcable) before adding the new object and
    before the add-ref function is called for the new object.

    Note that two keys \a key1 and \a key2 are equal (or same) in a
    hashtable if the comparator returns zero when called with \a key1
    and \a key2.

    Also note that all additions and removals to the hashtable are
    done by reference.  No data is copied.  Any objects pointed to are
    expected to exist for the duration that the object and key are
    contained in the hashtable.

    \param[in] h Hashtable
    \param[in] key A key.  If \a key points to a location in memory,
        it should be within the object pointed to by \a data, or be a
        constant. Can be NULL.
    \param[in] data Data. Cannot be NULL.

    \note Not thread-safe.  Applications must serialize calls that
        reference the same hashtable.
 */
KHMEXP void KHMAPI hash_add(hashtable * h, const void * key, void * data);

/*! \brief Delete an object from a hashtable

    Deletes the object in the hashtable \a h that is associated with
    key \a key.  An object is associated with key \a key if the key \a
    key_o that the object is associated with is the same as \a key as
    determined by the comparator.  If the del-ref function is defined
    for the hash-table, it will be called with the \a key_o and \a
    data that was used to add the object.

    \note Not thread-safe.  Applications must serialize calls that
        reference the same hashtable.
 */
KHMEXP void KHMAPI hash_del(hashtable * h, const void * key);

/*! \brief Resolve and association

    Return the object that is associated with key \a key in hashtable
    \a h.  An object \a data is associated with key \a key in \a h if
    the key \a key_o that was used to add \a data to \a h is equal to
    \a key as determined by the comparator.

    Returns NULL if no association is found.

    \note Not thread-safe.  Applications must serialize calls that
        reference the same hashtable.
 */
KHMEXP void * KHMAPI hash_lookup(hashtable * h, const void * key);

/*! \brief Check for the presence of an association

    Returns non-zero if there exists an association between key \a key
    and some object in hashtable \a h.  See hash_lookup() for
    definition of "association".

    Returns zero if there is no association.

    \note (hash_lookup(h,key) == NULL) iff (hash_exist(h,key)==0)

    \note Not thead-safe.  Application must serialize calls that
        reference the same hashtable.
 */
KHMEXP khm_boolean KHMAPI hash_exist(hashtable * h, const void * key);

/*! \brief Compute a hashvalue for a unicode string

    The hash value is computed using DJB with parameter 13331.

    This function is suitable for use as the hash function for a
    hashtable if the keys are NULL terminated safe unicode strings
    that are either part of the data objects or are constants.

    \param[in] str A pointer to a NULL terminated wchar_t string cast
        as (void *).

    \note This function does not check the length of the string \a
        str.  If the string is not \a NULL terminated, the behavior is
        undefined.
 */
KHMEXP khm_int32 hash_string(const void *str);

/*! \brief Compare two strings

    Compares two strings are returns a value that is in accordance
    with the comparator for a hashtable.

    \param[in] vs1 A pointer to a NULL terminated wchar_t string cast
        as (void *).
    \param[in] vs2 A pointer to a NULL terminated wchar_t string cast
        as (void *).

    \note This function does not check the length of the strings \a
        vs1 and \a vs2.  If the strings are not NULL terminated, the
        behavior is undefined.
 */
KHMEXP khm_int32 hash_string_comp(const void *vs1, const void *vs2);

/*@}*/
/*@}*/

#endif
