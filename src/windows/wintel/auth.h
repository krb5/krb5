/*
 * Implements Kerberos 4 authentication and ecryption
 */

void auth_parse(
	kstream ks,
	unsigned char *parsedat,
	int end_sub);

int INTERFACE auth_init(
	kstream str,
	kstream_ptr data);

void INTERFACE auth_destroy(
	kstream str);

int INTERFACE auth_encrypt(
	struct kstream_data_block *out,
	struct kstream_data_block *in,
	kstream str);

int INTERFACE auth_decrypt(
	struct kstream_data_block *out,
	struct kstream_data_block *in,
	kstream str);
