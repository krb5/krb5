#include <k5-int.h>
#include <kdb.h>

krb5_error_code asn1_encode_sequence_of_keys (krb5_key_data *key_data,
		krb5_int16 n_key_data,
		krb5_int32 mkvno,	/* Master key version number */
		krb5_data **code);

krb5_error_code asn1_decode_sequence_of_keys ( krb5_data *in,
		krb5_key_data **out,
		krb5_int16 *n_key_data,
		int *mkvno);

#include "krbasn1.h"
#include "asn1_encode.h"
#include "asn1_decode.h"
#include "asn1_make.h"
#include "asn1_get.h"

#define cleanup(err)							\
	{								\
		ret = err;						\
		goto last;						\
	}

#define checkerr							\
		if (ret != 0)						\
			goto last

/************************************************************************/
/* Encode the Principal's keys						*/
/************************************************************************/

static asn1_error_code asn1_encode_key(asn1buf *buf,
		krb5_key_data key_data,
		unsigned int *retlen) {
	asn1_error_code ret = 0;
	unsigned int length, sum = 0;

	// Encode the key type and value
	{
		unsigned int key_len = 0;
		// key value
		ret = asn1_encode_octetstring (buf,
				key_data.key_data_length[0],
				key_data.key_data_contents[0],
				&length); checkerr;
		key_len += length;
		ret = asn1_make_etag(buf, CONTEXT_SPECIFIC, 1, length, &length); checkerr;
		key_len += length;
		// key type
		ret = asn1_encode_integer (buf, key_data.key_data_type[0], &length);
		checkerr;
		key_len += length;
		ret = asn1_make_etag(buf, CONTEXT_SPECIFIC, 0, length, &length); checkerr;
		key_len += length;

		ret = asn1_make_sequence(buf, key_len, &length); checkerr;
		key_len += length;
		ret = asn1_make_etag(buf, CONTEXT_SPECIFIC, 1, key_len, &length); checkerr;
		key_len += length;

		sum += key_len;
	}
	// Encode the salt type and value (optional)
	if (key_data.key_data_ver > 1) {
		unsigned int salt_len = 0;
		// salt value (optional)
		if (key_data.key_data_length[1] > 0) {
			ret = asn1_encode_octetstring (buf,
					key_data.key_data_length[1],
					key_data.key_data_contents[1],
					&length); checkerr;
			salt_len += length;
			ret = asn1_make_etag(buf, CONTEXT_SPECIFIC, 1, length, &length);
			checkerr;
			salt_len += length;
		}
		// salt type
		ret = asn1_encode_integer (buf, key_data.key_data_type[1], &length);
		checkerr;
		salt_len += length;
		ret = asn1_make_etag(buf, CONTEXT_SPECIFIC, 0, length, &length); checkerr;
		salt_len += length;

		ret = asn1_make_sequence(buf, salt_len, &length); checkerr;
		salt_len += length;
		ret = asn1_make_etag(buf, CONTEXT_SPECIFIC, 1, salt_len, &length); checkerr;
		salt_len += length;

		sum += salt_len;
	}

	ret = asn1_make_sequence(buf, sum, &length); checkerr;
	sum += length;

	*retlen = sum;

last:
	return ret;
}

// Major version and minor version are both '1' - first version
//asn1_error_code asn1_encode_sequence_of_keys (krb5_key_data *key_data,
krb5_error_code asn1_encode_sequence_of_keys (krb5_key_data *key_data,
		krb5_int16 n_key_data,
		krb5_int32 mkvno,	/* Master key version number */
		krb5_data **code) {
	asn1_error_code ret = 0;
	asn1buf *buf = NULL;
	unsigned int length, sum = 0;

	*code = NULL;

	if(n_key_data == 0) cleanup (ASN1_MISSING_FIELD);

	// Allocate the buffer
	asn1buf_create(&buf);

	// Sequence of keys
	{
		int i;
		unsigned int seq_len = 0;

		for (i = n_key_data - 1; i >= 0; i--) {
			ret = asn1_encode_key (buf, key_data[i], &length); checkerr;
			seq_len += length;
		}
		ret = asn1_make_sequence(buf, seq_len, &length); checkerr;
		seq_len += length;
		ret = asn1_make_etag(buf, CONTEXT_SPECIFIC, 4, seq_len, &length); checkerr;
		seq_len += length;

		sum += seq_len;
	}

	// mkvno
	if (mkvno < 0)
		cleanup (ASN1_BAD_FORMAT);
	ret = asn1_encode_unsigned_integer (buf, (unsigned int)mkvno, &length); checkerr;
	sum += length;
	ret = asn1_make_etag(buf, CONTEXT_SPECIFIC, 3, length, &length); checkerr;
	sum += length;

	// kvno (assuming all keys in array have same version)
	if (key_data[0].key_data_kvno < 0)
		cleanup (ASN1_BAD_FORMAT);
	ret = asn1_encode_unsigned_integer (buf, (unsigned int)key_data[0].key_data_kvno, &length);
	checkerr;
	sum += length;
	ret = asn1_make_etag(buf, CONTEXT_SPECIFIC, 2, length, &length); checkerr;
	sum += length;

	// attribute-minor-vno == 1
	ret = asn1_encode_unsigned_integer (buf, 1, &length); checkerr;
	sum += length;
	ret = asn1_make_etag(buf, CONTEXT_SPECIFIC, 1, length, &length); checkerr;
	sum += length;

	// attribute-major-vno == 1
	ret = asn1_encode_unsigned_integer (buf, 1, &length); checkerr;
	sum += length;
	ret = asn1_make_etag(buf, CONTEXT_SPECIFIC, 0, length, &length); checkerr;
	sum += length;

	ret = asn1_make_sequence(buf, sum, &length); checkerr;
	sum += length;

	// The reverse encoding is straightened out here
	ret = asn12krb5_buf (buf, code); checkerr;

last:
	asn1buf_destroy (&buf);

	if (ret != 0 && *code != NULL)
		free (*code);

	return ret;
}

/************************************************************************/
/* Decode the Principal's keys						*/
/************************************************************************/

#define safe_syncbuf(outer,inner)					\
	if (! ((inner)->next == (inner)->bound + 1 &&			\
			(inner)->next == (outer)->next + buflen))		\
		cleanup (ASN1_BAD_LENGTH);				\
	asn1buf_sync(outer, inner, 0, 0, 0, 0, 0);

static asn1_error_code decode_tagged_integer (asn1buf *buf,
		int expectedtag,
		int *val) {
	int buflen;
	asn1_error_code ret = 0;
	asn1buf tmp, subbuf;
	taginfo t;

	// Work on a copy of 'buf'
	ret = asn1buf_imbed(&tmp, buf, 0, 1); checkerr;
	ret = asn1_get_tag_2(&tmp, &t); checkerr;
	if (t.tagnum != expectedtag)
		cleanup (ASN1_MISSING_FIELD);

	buflen = t.length;
	ret = asn1buf_imbed(&subbuf, &tmp, t.length, 0); checkerr;
	ret = asn1_decode_unsigned_integer(&subbuf, (long int *)val); checkerr;

	safe_syncbuf(&tmp, (&subbuf));
	*buf = tmp;

last:
	return ret;
}

static asn1_error_code decode_tagged_octetstring (asn1buf *buf,
		int expectedtag,
		int *len,
		asn1_octet **val) {
	int buflen;
	asn1_error_code ret = 0;
	asn1buf tmp, subbuf;
	taginfo t;

	*val = NULL;

	// Work on a copy of 'buf'
	ret = asn1buf_imbed(&tmp, buf, 0, 1); checkerr;
	ret = asn1_get_tag_2(&tmp, &t); checkerr;
	if (t.tagnum != expectedtag)
		cleanup (ASN1_MISSING_FIELD);

	buflen = t.length;
	ret = asn1buf_imbed(&subbuf, &tmp, t.length, 0); checkerr;
	ret = asn1_decode_octetstring (&subbuf, len, val); checkerr;

	safe_syncbuf(&tmp, (&subbuf));
	*buf = tmp;

last:
	if (ret != 0 && *val != NULL)
		free (*val);
	return ret;
}

static asn1_error_code asn1_decode_key(asn1buf *buf, krb5_key_data *key) {
	int buflen, seqindef;
	unsigned int length;
	asn1_error_code ret;
	asn1buf subbuf;
	taginfo t;

	key->key_data_contents[0] = NULL;
	key->key_data_contents[1] = NULL;

	ret = asn1_get_sequence(buf, &length, &seqindef); checkerr;
	buflen = length;
	ret = asn1buf_imbed(&subbuf, buf, length, seqindef); checkerr;

	asn1_get_tag_2(&subbuf, &t);
	// Salt
	if (t.tagnum == 0) {
		int buflen;
		asn1buf slt;

		key->key_data_ver = 2;
		asn1_get_sequence(&subbuf, &length, &seqindef);
		buflen = length;
		asn1buf_imbed(&slt, &subbuf, length, seqindef);

		ret = decode_tagged_integer (&slt, 0, (int *)&key->key_data_type[1]);
		checkerr;

		ret = decode_tagged_octetstring (&slt, 1,
				(int *)&key->key_data_length[1],
				&key->key_data_contents[1]); checkerr;

		safe_syncbuf ((&subbuf), (&slt));

		ret = asn1_get_tag_2(&subbuf, &t); checkerr;
	} else
		key->key_data_ver = 1;

	// Key
	{
		int buflen;
		asn1buf kbuf;
		if (t.tagnum != 1)
			cleanup (ASN1_MISSING_FIELD);

		ret = asn1_get_sequence(&subbuf, &length, &seqindef); checkerr;
		buflen = length;
		ret = asn1buf_imbed(&kbuf, &subbuf, length, seqindef); checkerr;

		ret = decode_tagged_integer (&kbuf, 0, (int *)&key->key_data_type[0]);
		checkerr;

		ret = decode_tagged_octetstring (&kbuf, 1,
				(int *)&key->key_data_length[0],
				&key->key_data_contents[0]); checkerr;

		safe_syncbuf (&subbuf, &kbuf);
	}

	safe_syncbuf (buf, &subbuf);

last:
	if (ret != 0) {
		if (key->key_data_contents[0] != NULL) {
			free (key->key_data_contents[0]);
			key->key_data_contents[0] = NULL;
		}
		if (key->key_data_contents[1] != NULL) {
			free (key->key_data_contents[1]);
			key->key_data_contents[1] = NULL;
		}
	}
	return ret;
}

//asn1_error_code asn1_decode_sequence_of_keys ( krb5_data *in,
krb5_error_code asn1_decode_sequence_of_keys ( krb5_data *in,
		krb5_key_data **out,
		krb5_int16 *n_key_data,
		int *mkvno) {
	asn1_error_code ret;
	asn1buf buf, subbuf;                                               \
	int seqindef;
	unsigned int length;
	taginfo t;
	int kvno, maj, min;

	*n_key_data = 0;
	*out = NULL;

	ret = asn1buf_wrap_data(&buf, in); checkerr;

	ret = asn1_get_sequence(&buf, &length, &seqindef); checkerr;
	ret = asn1buf_imbed(&subbuf, &buf, length, seqindef); checkerr;

	// attribute-major-vno
	ret = decode_tagged_integer (&subbuf, 0, &maj); checkerr;

	// attribute-minor-vno
	ret = decode_tagged_integer (&subbuf, 1, &min); checkerr;

	if (maj != 1 || min != 1)
		cleanup (ASN1_BAD_FORMAT);

	// kvno (assuming all keys in array have same version)
	ret = decode_tagged_integer (&subbuf, 2, &kvno); checkerr;

	// mkvno (optional)
	ret = decode_tagged_integer (&subbuf, 3, mkvno); checkerr;

	ret = asn1_get_tag_2(&subbuf, &t); checkerr;

	// Sequence of keys
	{
		int i, ret1, buflen;
		asn1buf keyseq;
		if (t.tagnum != 4)
			cleanup (ASN1_MISSING_FIELD);
		ret = asn1_get_sequence(&subbuf, &length, &seqindef); checkerr;
		buflen = length;
		ret = asn1buf_imbed(&keyseq, &subbuf, length, seqindef); checkerr;
		for (i = 1, *out = NULL; ; i++) {
			krb5_key_data *tmp;
			tmp = (krb5_key_data *) realloc (*out, i * sizeof (krb5_key_data));
			if (tmp == NULL)
				cleanup (ENOMEM);
			*out = tmp;
			(*out)[i - 1].key_data_kvno = kvno;
			ret1 = asn1_decode_key(&keyseq, &(*out)[i - 1]); checkerr;
			(*n_key_data)++;
			if (asn1buf_remains(&keyseq, 0) == 0)
				break; // Not freeing the last key structure
		}
		safe_syncbuf (&subbuf, &keyseq);
	}

last:
	if (ret != 0) {
		int i;
		for (i = 0; i < *n_key_data; i++) {
			if ((*out)[i].key_data_contents[0] != NULL)
				free ((*out)[i].key_data_contents[0]);
			if ((*out)[i].key_data_contents[1] != NULL)
				free ((*out)[i].key_data_contents[1]);
		}
		free (*out);
		*out = NULL;
	}

	return ret;
}
