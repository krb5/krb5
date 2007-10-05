#include "des_int.h"
#include "des.h"
#undef mit_des3_cbc_encrypt

/* These functions are exported on KfM for ABI compatibility with
 * older versions of the library.  They have been pulled from the headers
 * in the hope that someday we can remove them.
 * 
 * Do not change the ABIs of any of these functions!
 */

//int des_read_pw_string(char *, int, char *, int);
char *des_crypt(const char *, const char *);
char *des_fcrypt(const char *, const char *, char *);

int make_key_sched(des_cblock *, des_key_schedule);
int des_set_key(des_cblock *, des_key_schedule);

void des_3cbc_encrypt(des_cblock *, des_cblock *, long, 
                      des_key_schedule, des_key_schedule, des_key_schedule, 
                      des_cblock *, int);
void des_3ecb_encrypt(des_cblock *, des_cblock *, 
                      des_key_schedule, des_key_schedule, des_key_schedule, 
                      int);

void des_generate_random_block(des_cblock);
void des_set_random_generator_seed(des_cblock);
void des_set_sequence_number(des_cblock);

#pragma mark -

/* Why was this exported on KfM?  Who knows... */
int des_debug = 0;

char *des_crypt(const char *str, const char *salt)
{
    char afs_buf[16];

    return des_fcrypt(str, salt, afs_buf);
}


char *des_fcrypt(const char *str, const char *salt, char *buf)
{
    return mit_afs_crypt(str, salt, buf);
}


int make_key_sched(des_cblock *k, des_key_schedule schedule)
{
    return mit_des_key_sched((unsigned char *)k, schedule); /* YUCK! */
}


int des_set_key(des_cblock *key, des_key_schedule schedule)
{
    return make_key_sched(key, schedule);
}


void des_3cbc_encrypt(des_cblock *in, des_cblock *out, long length,
                      des_key_schedule ks1, des_key_schedule ks2, des_key_schedule ks3, 
                      des_cblock *iv, int enc)
{
    mit_des3_cbc_encrypt((const des_cblock *)in, out, (unsigned long)length,
			 ks1, ks2, ks3,
			 (const unsigned char *)iv, /* YUCK! */
			 enc);
}


void des_3ecb_encrypt(des_cblock *clear, des_cblock *cipher,
                      des_key_schedule ks1, des_key_schedule ks2, des_key_schedule ks3, 
                      int enc)
{
    static const des_cblock iv;

    mit_des3_cbc_encrypt((const des_cblock *)clear, cipher, 8, ks1, ks2, ks3, iv, enc);
}


void des_generate_random_block(des_cblock block)
{
    krb5_data data;

    data.length = sizeof(des_cblock);
    data.data = (char *)block;
    
    /* This function can return an error, however we must ignore it. */
    /* The worst that happens is that the resulting block is non-random */
    krb5_c_random_make_octets(/* XXX */ 0, &data);
}


void des_set_random_generator_seed(des_cblock block)
{
    des_init_random_number_generator(block); /* XXX */
}


void des_set_sequence_number(des_cblock block)
{
    des_init_random_number_generator(block); /* XXX */
}
