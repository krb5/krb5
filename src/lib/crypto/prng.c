#include "k5-int.h"
#include "enc_provider.h"

/* This random number generator is a feedback generator based on a
   block cipher.  It uses DES by default, since it guaranteed to be
   present in the system, but can be changed.  As new seed data comes
   in, the old state is folded with the new seed into new state.  Each
   time random bytes are requested, the seed is used as a key and
   cblock, and the encryption is used as the output.  The output is
   fed back as new seed data, as described above. */

/* this can be replaced with another encryption provider, since
   everything below uses it abstractly */

struct krb5_enc_provider *enc = &krb5_enc_des;

/* XXX state.  Should it be in krb5_context? */

static int inited = 0;
static size_t blocksize, keybytes, keylength;
static int random_count;
/* keybytes | state-block | encblock | key | new-keybytes | new-state-block */
static unsigned char *random_state; 
#define STATE (random_state)
#define STATEKEY (STATE)
#define STATEBLOCK (STATEKEY+keybytes)
#define STATESIZE (keybytes+blocksize)
#define OUTPUT (STATE)
#define OUTPUTSIZE (STATESIZE+blocksize)
#define RANDBLOCK (STATEBLOCK+blocksize)
#define KEYCONTENTS (RANDBLOCK+blocksize)
#define NEWSTATE (KEYCONTENTS+keylength)
#define ALLSTATESIZE (keybytes+blocksize*2+keylength+keybytes+blocksize)

krb5_error_code
krb5_c_random_seed(krb5_context context, krb5_data *data)
{
    unsigned char *fold_input;

    if (inited == 0) {
	/* this does a bunch of malloc'ing up front, so that
	   generating random keys doesn't have to malloc, so it can't
	   fail.  seeding still malloc's, but that's less common. */

	enc->block_size(&blocksize);
	enc->keysize(&keybytes, &keylength);
	if ((random_state = (unsigned char *) malloc(ALLSTATESIZE)) == NULL)
	    return(ENOMEM);
	random_count = 0;
	inited = 1;

	krb5_nfold(data->length*8, data->data, STATESIZE*8, STATE);

	return(0);
    }

    if ((fold_input =
	 (unsigned char *) malloc(data->length+STATESIZE)) == NULL)
	return(ENOMEM);

    memcpy(fold_input, data->data, data->length);
    memcpy(fold_input+data->length, STATE, STATESIZE);

    krb5_nfold((data->length+STATESIZE)*8, fold_input,
	       STATESIZE*8, STATE);
    free(fold_input);
    return(0);
}

krb5_error_code
krb5_c_random_make_octets(krb5_context context, krb5_data *data)
{
    krb5_error_code ret;
    krb5_data data1, data2;
    krb5_keyblock key;
    int bytes;

    if (inited == 0) {
	/* i need some entropy.  I'd use the current time and pid, but
	   that could cause portability problems. */
	abort();
    }

    bytes = 0;

    while (bytes < data->length) {
	if (random_count == 0) {
	    /* set up random krb5_data, and key to be filled in */
	    data1.length = keybytes;
	    data1.data = STATEKEY;
	    key.length = keylength;
	    key.contents = KEYCONTENTS;

	    /* fill it in */
	    if (ret = ((*(enc->make_key))(&data1, &key)))
		return(ret);

	    /* encrypt the block */
	    data1.length = blocksize;
	    data1.data = STATEBLOCK;
	    data2.length = blocksize;
	    data2.data = RANDBLOCK;
	    if (ret = ((*(enc->encrypt))(&key, NULL, &data1, &data2)))
		return(ret);

	    /* fold the new output back into the state */

	    krb5_nfold(OUTPUTSIZE*8, OUTPUT, STATESIZE*8, NEWSTATE);
	    memcpy(STATE, NEWSTATE, STATESIZE);

	    random_count = blocksize;
	}

	if ((data->length - bytes) <= random_count) {
	    memcpy(data->data + bytes, RANDBLOCK+(blocksize-random_count),
		   data->length - bytes);
	    random_count -= (data->length - bytes);
	    break;
	}

	memcpy(data->data + bytes, RANDBLOCK+(blocksize - random_count),
	       random_count);

	bytes += random_count;
	random_count = 0;
    }

    return(0);
}
