#ifndef _SHS_DEFINED

#include <krb5.h>

#define _SHS_DEFINED

/* Some useful types */

typedef krb5_octet	BYTE;
typedef krb5_ui_4	LONG;

/* Exit status of functions. */

#define OK      0
#define ERROR   -1

/* Define the following to use the updated SHS implementation */

#define NEW_SHS         /**/

/* The SHS block size and message digest sizes, in bytes */

#define SHS_DATASIZE    64
#define SHS_DIGESTSIZE  20

/* The structure for storing SHS info */

typedef struct {
               LONG digest[ 5 ];            /* Message digest */
               LONG countLo, countHi;       /* 64-bit bit count */
               LONG data[ 16 ];             /* SHS data buffer */
               } SHS_INFO;

/* Message digest functions (shs.c) */
void shsInit
	KRB5_PROTOTYPE((SHS_INFO *shsInfo));
void shsUpdate
	KRB5_PROTOTYPE((SHS_INFO *shsInfo, BYTE *buffer, int count));
void shsFinal
	KRB5_PROTOTYPE((SHS_INFO *shsInfo));


/* Keyed Message digest functions (hmac_sha.c) */
krb5_error_code hmac_sha
	KRB5_PROTOTYPE((krb5_octet *text,
			int text_len,
			krb5_octet *key,
			int key_len,
			krb5_octet *digest));


#define NIST_SHA_CKSUM_LENGTH		SHS_DIGESTSIZE
#define HMAC_SHA_CKSUM_LENGTH		SHS_DIGESTSIZE


extern krb5_checksum_entry
    nist_sha_cksumtable_entry,
    hmac_sha_cksumtable_entry;

#endif /* _SHS_DEFINED */
