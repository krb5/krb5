/* Coding Buffer Specifications */
#ifndef __ASN1BUF_H__
#define __ASN1BUF_H__

#include "k5-int.h"
#include "krbasn1.h"

typedef struct code_buffer_rep {
  char *base, *bound, *next;
} asn1buf;

/*
  Overview 
    
    The coding buffer is an array of char (to match a krb5_data structure)
     with 3 reference pointers:
     1) base - The bottom of the octet array.  Used for memory management
               operations on the array (e.g. alloc, realloc, free).
     2) next - Points to the next available octet position in the array.
               During encoding, this is the next free position, and it
                 advances as octets are added to the array.
	       During decoding, this is the next unread position, and it
                 advances as octets are read from the array.
     3) bound - Points to the top of the array. Used for bounds-checking.
    
    All pointers to encoding buffers should be initalized to NULL.
    
  Operations

    asn1buf_create
    asn1buf_wrap_data
    asn1buf_destroy
    asn1buf_insert_octet
    asn1buf_insert_charstring
    asn1buf_remove_octet
    asn1buf_remove_charstring
    asn1buf_unparse
    asn1buf_hex_unparse
    asn12krb5_buf
    asn1buf_remains

    (asn1buf_size)
    (asn1buf_free)
    (asn1buf_ensure_space)
    (asn1buf_expand)
    (asn1buf_len)
*/

asn1_error_code asn1buf_create
	PROTOTYPE((asn1buf **buf));
/* effects   Creates a new encoding buffer pointed to by *buf.
             Returns ENOMEM if the buffer can't be created. */

asn1_error_code asn1buf_wrap_data
	PROTOTYPE((asn1buf *buf, const krb5_data *code));
/* requires  *buf has already been allocated
   effects   Turns *buf into a "wrapper" for *code.  i.e. *buf is set up
              such that its bottom is the beginning of *code, and its top
	      is the top of *code.
	     Returns ASN1_MISSING_FIELD if code is empty. */

asn1_error_code asn1buf_imbed
	PROTOTYPE((asn1buf *subbuf, const asn1buf *buf, const int length));
/* requires  *subbuf and *buf are allocated
   effects   *subbuf becomes a sub-buffer of *buf.  *subbuf begins
              at *buf's current position and is length octets long.
              (Unless this would exceed the bounds of *buf -- in
	      that case, ASN1_OVERRUN is returned)  *subbuf's current
	      position starts at the beginning of *subbuf. */

void asn1buf_sync
	PROTOTYPE((asn1buf *buf, asn1buf *subbuf));
/* requires  *subbuf is a sub-buffer of *buf, as created by asn1buf_imbed.
   effects   Synchronizes *buf's current position to match that of *subbuf. */

asn1_error_code asn1buf_destroy
	PROTOTYPE((asn1buf **buf));
/* effects   Deallocates **buf, sets *buf to NULL. */

asn1_error_code asn1buf_insert_octet
	PROTOTYPE((asn1buf *buf, const int o));
/* requires  *buf is allocated
   effects   Inserts o into the buffer *buf, expanding the buffer if
             necessary.  Returns ENOMEM memory is exhausted. */
#if __GNUC__ >= 2
#define asn1buf_insert_octet(BUF,O) 					\
  (asn1buf_ensure_space ((BUF),1)					\
   ? /* leave this empty -- gcc returns value of first operand */	\
   : (*(BUF)->next++ = (O), 0))
#endif

asn1_error_code asn1buf_insert_octetstring
	PROTOTYPE((asn1buf *buf, const int len, const asn1_octet *s));
/* requires  *buf is allocated
   modifies  *buf
   effects   Inserts the contents of s (an octet array of length len)
              into the buffer *buf, expanding the buffer if necessary.
	     Returns ENOMEM if memory is exhausted. */

asn1_error_code asn1buf_insert_charstring
	PROTOTYPE((asn1buf *buf, const int len, const char *s));
/* requires  *buf is allocated
   modifies  *buf
   effects   Inserts the contents of s (a character array of length len)
              into the buffer *buf, expanding the buffer if necessary.
	     Returns ENOMEM if memory is exhuasted. */

asn1_error_code asn1buf_remove_octet
	PROTOTYPE((asn1buf *buf, asn1_octet *o));
/* requires  *buf is allocated
   effects   Returns *buf's current octet in *o and advances to
              the next octet.
	     Returns ASN1_OVERRUN if *buf has already been exhuasted. */
#define asn1buf_remove_octet(buf,o) \
  (((buf)->next > (buf)->bound) \
   ? ASN1_OVERRUN \
   : ((*(o) = (asn1_octet)(*(((buf)->next)++))),0))

asn1_error_code asn1buf_remove_octetstring
	PROTOTYPE((asn1buf *buf, const int len, asn1_octet **s));
/* requires  *buf is allocated
   effects   Removes the next len octets of *buf and returns them in **s.
	     Returns ASN1_OVERRUN if there are fewer than len unread octets
	      left in *buf.
	     Returns ENOMEM if *s could not be allocated. */

asn1_error_code asn1buf_remove_charstring
	PROTOTYPE((asn1buf *buf, const int len,
					  char **s));
/* requires  *buf is allocated
   effects   Removes the next len octets of *buf and returns them in **s.
	     Returns ASN1_OVERRUN if there are fewer than len unread octets
	      left in *buf.
	     Returns ENOMEM if *s could not be allocated. */

asn1_error_code asn1buf_unparse
	PROTOTYPE((const asn1buf *buf, char **s));
/* modifies  *s
   effects   Returns a human-readable representation of *buf in *s,
             where each octet in *buf is represented by a character in *s. */

asn1_error_code asn1buf_hex_unparse
	PROTOTYPE((const asn1buf *buf, char **s));
/* modifies  *s
   effects   Returns a human-readable representation of *buf in *s,
             where each octet in *buf is represented by a 2-digit
	     hexadecimal number in *s. */

asn1_error_code asn12krb5_buf
	PROTOTYPE((const asn1buf *buf, krb5_data **code));
/* modifies  *code
   effects   Instantiates **code with the krb5_data representation of **buf. */


int asn1buf_remains
	PROTOTYPE((asn1buf *buf));
/* requires  *buf is a buffer containing an asn.1 structure or array
   modifies  *buf
   effects   Returns the number of unprocessed octets remaining in *buf. */

/**************** Private Procedures ****************/

int asn1buf_size
	PROTOTYPE((const asn1buf *buf));
/* requires  *buf has been created and not destroyed
   effects   Returns the total size 
	PROTOTYPE((in octets) of buf's octet buffer. */
#define asn1buf_size(buf) \
  (((buf) == NULL || (buf)->base == NULL) \
   ? 0 \
   : ((buf)->bound - (buf)->base + 1))

int asn1buf_free
	PROTOTYPE((const asn1buf *buf));
/* requires  *buf is allocated
   effects   Returns the number of unused, allocated octets in *buf. */
#define asn1buf_free(buf) \
  (((buf) == NULL || (buf)->base == NULL) \
   ? 0 \
   : ((buf)->bound - (buf)->next + 1))


asn1_error_code asn1buf_ensure_space
	PROTOTYPE((asn1buf *buf, const int amount));
/* requires  *buf is allocated
   modifies  *buf
   effects  If buf has less than amount octets of free space, then it is
            expanded to have at least amount octets of free space.
            Returns ENOMEM memory is exhausted. */
#define asn1buf_ensure_space(buf,amount) \
  ((asn1buf_free(buf) < (amount)) \
   ? (asn1buf_expand((buf), (amount)-asn1buf_free(buf))) \
   : 0)


asn1_error_code asn1buf_expand
	PROTOTYPE((asn1buf *buf, int inc));
/* requires  *buf is allocated
   modifies  *buf
   effects   Expands *buf by allocating space for inc more octets.
             Returns ENOMEM if memory is exhausted. */

int asn1buf_len
	PROTOTYPE((const asn1buf *buf));
/* requires  *buf is allocated
   effects   Returns the length of the encoding in *buf. */
#define asn1buf_len(buf)	((buf)->next - (buf)->base)

#endif
