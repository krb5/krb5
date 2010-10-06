/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* prng_fortuna.c */
/*
 * prng_fortuna.c
 *
 *		Fortuna-like PRNG.
 *
 * Copyright (c) 2005 Marko Kreen
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in the
 *	  documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.	IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $PostgreSQL: pgsql/contrib/pgcrypto/fortuna.c,v 1.8 2006/10/04 00:29:46 momjian Exp $
 */
/*
 * Copyright (C) 2010 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 *  or implied warranty.
 */

#include "fortuna.h"
#include "k5-int.h"


#include "k5-thread.h"
k5_mutex_t fortuna_lock = K5_MUTEX_PARTIAL_INITIALIZER;

/*
 * Why Fortuna-like: There does not seem to be any definitive reference
 * on Fortuna in the net.  Instead this implementation is based on
 * following references:
 *
 * http://en.wikipedia.org/wiki/Fortuna_(PRNG)
 *	 - Wikipedia article
 * http://jlcooke.ca/random/
 *	 - Jean-Luc Cooke Fortuna-based /dev/random driver for Linux.
 */

/*
 * There is some confusion about whether and how to carry forward
 * the state of the pools.	Seems like original Fortuna does not
 * do it, resetting hash after each request.  I guess expecting
 * feeding to happen more often that requesting.   This is absolutely
 * unsuitable for pgcrypto, as nothing asynchronous happens here.
 *
 * J.L. Cooke fixed this by feeding previous hash to new re-initialized
 * hash context.
 *
 * Fortuna predecessor Yarrow requires ability to query intermediate
 * 'final result' from hash, without affecting it.
 *
 * This implementation uses the Yarrow method - asking intermediate
 * results, but continuing with old state.
 */

/*
 * Algorithm parameters
 */

#define NUM_POOLS 	32

/* in microseconds */
#define RESEED_INTERVAL 100000	/* 0.1 sec */

/* for one big request, reseed after this many bytes */
#define RESEED_BYTES	(1024*1024)

/*
 * Skip reseed if pool 0 has less than this many
 * bytes added since last reseed.
 */
#define POOL0_FILL		(256/8)

/* Entropy gathering */
int (*entropy_collector[])(krb5_context context, unsigned char buf[], int buflen) =
{
#ifndef TEST_FORTUNA
 /*   k5_entropy_dev_random, */
    k5_entropy_dev_urandom,
    k5_entropy_pid,
    k5_entropy_uid
#else
    test_entr
#endif
};

/*
 * Algorithm constants
 */

#define AES_BLOCK_SIZE 16
#define AES_MAXNR 14

#define AES_ENCRYPT 1
#define AES_DECRYPT 0

/* Both cipher key size and hash result size */
#define BLOCK			32

/* cipher block size */
#define CIPH_BLOCK		16

/* for internal wrappers */

#define MD_CTX			SHA256_CTX
#define CIPH_CTX		aes_ctx

/* Genarator - block cipher in CTR mode */
struct fortuna_state
{
    unsigned char	counter[CIPH_BLOCK];
    unsigned char	result[CIPH_BLOCK];
    unsigned char	key[BLOCK];
    MD_CTX		pool[NUM_POOLS];
    CIPH_CTX		ciph;
    unsigned		reseed_count;
    struct timeval	last_reseed_time;
    unsigned		pool0_bytes;
    unsigned		rnd_pos;
    int			tricks_done;
    pid_t		pid;
};
typedef struct fortuna_state FState;


/*
 * Use our own wrappers here.
 * - Need to get intermediate result from digest, without affecting it.
 * - Need re-set key on a cipher context.
 * - Algorithms are guaranteed to exist.
 * - No memory allocations.
 */

static void
ciph_init(CIPH_CTX * ctx /*out*/, const unsigned char *key, int klen)
{
    krb5int_aes_enc_key(key, klen, ctx);
}

static void
ciph_encrypt(CIPH_CTX *ctx, const unsigned char *in, unsigned char *out)
{
    aes_enc_blk(in, out, ctx);
}

static void
md_init(MD_CTX * ctx)
{
    sha2Init(ctx);
}

static void
md_update(MD_CTX * ctx, const unsigned char *data, int len)
{
    sha2Update(ctx, data, len);
}

static void
md_result(MD_CTX * ctx, unsigned char *dst)
{
    MD_CTX	tmp_ctx;

    memcpy(&tmp_ctx, ctx, sizeof(*ctx));
    sha2Final(dst, &tmp_ctx);
    memset(&tmp_ctx, 0, sizeof(tmp_ctx));
}

/*
 * initialize state
 */
static  krb5_error_code
init_state(FState * st)
{
    int	i;
    krb5_error_code ret = 0;

    ret = k5_mutex_finish_init(&fortuna_lock);
    if (ret)
        return ret;

    memset(st, 0, sizeof(*st));
    for (i = 0; i < NUM_POOLS; i++)
	md_init(&st->pool[i]);
    st->pid = getpid();

    return 0;
}

/*
 * Endianess does not matter.
 * It just needs to change without repeating.
 */
static void
inc_counter(FState * st)
{
    uint32_t   *val = (uint32_t *) st->counter;

    if (++val[0])
	return;
    if (++val[1])
	return;
    if (++val[2])
	return;
    ++val[3];
}

/*
 * This is called 'cipher in counter mode'.
 */
static void
encrypt_counter(FState * st, unsigned char *dst)
{
    ciph_encrypt(&st->ciph, st->counter, dst);
    inc_counter(st);
}


/*
 * The time between reseed must be at least RESEED_INTERVAL microseconds.
 */
static int
enough_time_passed(FState * st)
{
    int    ok = FORTUNA_FAIL;
    struct timeval tv;
    struct timeval *last = &st->last_reseed_time;

    gettimeofday(&tv, NULL);

    /* check how much time has passed */
    if (tv.tv_sec > last->tv_sec + 1)
	ok = FORTUNA_OK;
    else if (tv.tv_sec == last->tv_sec + 1) {
	if (1000000 + tv.tv_usec - last->tv_usec >= RESEED_INTERVAL)
	    ok = FORTUNA_OK;
    } else if (tv.tv_usec - last->tv_usec >= RESEED_INTERVAL)
	ok = FORTUNA_OK;

    /* reseed will happen, update last_reseed_time */
    if (ok)
	memcpy(last, &tv, sizeof(tv));

    memset(&tv, 0, sizeof(tv));

    return ok;
}

/*
 * generate new key from all the pools
 */
static void
reseed(FState * st)
{
    unsigned	k;
    unsigned	n;
    MD_CTX		key_md;
    unsigned char	buf[BLOCK];

    /* set pool as empty */
    st->pool0_bytes = 0;

    /*
     * Both #0 and #1 reseed would use only pool 0. Just skip #0 then.
     */
    n = ++st->reseed_count;

    /*
     * The goal: use k-th pool only 1/(2^k) of the time.
     */
    md_init(&key_md);
    for (k = 0; k < NUM_POOLS; k++) {
	md_result(&st->pool[k], buf);
	md_update(&key_md, buf, BLOCK);

	if (n & 1 || !n)
	    break;
	n >>= 1;
    }
    /* add old key into mix too */
    md_update(&key_md, st->key, BLOCK);

#ifndef TEST_FORTUNA
    /* add pid to make output diverse after fork() */
    md_update(&key_md, (const unsigned char *)&st->pid, sizeof(st->pid));
#endif

    /* now we have new key */
    md_result(&key_md, st->key);
    /* use new key */
    ciph_init(&st->ciph, st->key, BLOCK);

    memset(&key_md, 0, sizeof(key_md));
    memset(buf, 0, BLOCK);
}

/*
 * Pick a random pool.	This uses key bytes as random source.
 */
static unsigned
get_rand_pool(FState * st)
{
    unsigned	rnd;

    /*
     * This slightly prefers lower pools - thats OK.
     */
    rnd = st->key[st->rnd_pos] % NUM_POOLS;

    st->rnd_pos++;
    if (st->rnd_pos >= BLOCK)
	st->rnd_pos = 0;

    return rnd;
}

/*
 * update pools
 */
static void
add_entropy(FState * st, const unsigned char data[], unsigned len)
{
    unsigned		pos;
    unsigned char	hash[BLOCK];
    MD_CTX		md;

    /* hash given data */
    md_init(&md);
    md_update(&md, data, len);
    md_result(&md, hash);

    /*
     * Make sure the pool 0 is initialized, then update randomly.
     */
    if (st->reseed_count == 0)
	pos = 0;
    else
	pos = get_rand_pool(st);
    md_update(&st->pool[pos], hash, BLOCK);

    if (pos == 0)
	st->pool0_bytes += len;

    memset(hash, 0, BLOCK);
    memset(&md, 0, sizeof(md));
}

/*
 * Just take 2 next blocks as new key
 */
static void
rekey(FState * st)
{
    encrypt_counter(st, st->key);
    encrypt_counter(st, st->key + CIPH_BLOCK);
    ciph_init(&st->ciph, st->key, BLOCK);
}

/*
 * Hide public constants. (counter, pools > 0)
 *
 * This can also be viewed as spreading the startup
 * entropy over all of the components.
 */
static void
startup_tricks(FState * st)
{
    int			i;
    unsigned char	buf[BLOCK];

    /* Use next block as counter. */
    encrypt_counter(st, st->counter);

    /* Now shuffle pools, excluding #0 */
    for (i = 1; i < NUM_POOLS; i++) {
	encrypt_counter(st, buf);
	encrypt_counter(st, buf + CIPH_BLOCK);
	md_update(&st->pool[i], buf, BLOCK);
    }
    memset(buf, 0, BLOCK);

    /* Hide the key. */
    rekey(st);

    /* This can be done only once. */
    st->tricks_done = 1;
}

static void
extract_data(FState * st, unsigned count, unsigned char *dst)
{
    unsigned	n;
    unsigned	block_nr = 0;
    pid_t	pid = getpid();

    /* Should we reseed? */
    if (st->pool0_bytes >= POOL0_FILL || st->reseed_count == 0)
	if (enough_time_passed(st))
	    reseed(st);

    /* Do some randomization on first call */
    if (!st->tricks_done)
	startup_tricks(st);

    /* If we forked, force a reseed again */
    if (pid != st->pid) {
	st->pid = pid;
	reseed(st);
    }
    while (count > 0) {
	/* produce bytes */
	encrypt_counter(st, st->result);

	/* copy result */
	if (count > CIPH_BLOCK)
	    n = CIPH_BLOCK;
	else
	    n = count;
	memcpy(dst, st->result, n);
	dst += n;
	count -= n;

	/* must not give out too many bytes with one key */
	block_nr++;
	if (block_nr > (RESEED_BYTES / CIPH_BLOCK)) {
	    rekey(st);
	    block_nr = 0;
	}
    }
    /* Set new key for next request. */
    rekey(st);
}

/*
 * public interface
 */

static FState	main_state;
static int	init_done;
static int	have_entropy;
static int      resend_bytes;

#define FORTUNA_RESEED_BYTE	10000

/*
 * Try our best to do an inital seed
 */
#define INIT_BYTES	128

static int
fortuna_reseed(void)
{
    int entropy_p = 0;
    krb5_context ctx;
    unsigned char buf[ENTROPY_BUFSIZE];
    int num = sizeof(entropy_collector)/sizeof(entropy_collector[0]);

    if (!init_done)
	abort();
    
    while(num > 0){
        entropy_collector[num-1](ctx, buf, ENTROPY_BUFSIZE);
        add_entropy(&main_state, buf, sizeof(buf));
        num--;
    }
    memset (buf,0,ENTROPY_BUFSIZE);
    entropy_p = 1; 

    return entropy_p;
}

static int
fortuna_init(void)
{
    krb5_error_code ret = 0;

    if (!init_done) {
        ret = init_state(&main_state);
        if (ret == 0)
            init_done = 1;
    }
    if (!have_entropy)
	have_entropy = fortuna_reseed();
    return (init_done && have_entropy);
}

static  krb5_error_code
fortuna_seed(const unsigned char *indata, int size)
{
    krb5_error_code ret = 0;

    fortuna_init();

    ret = k5_mutex_lock(&fortuna_lock);
    if (ret)
        return FORTUNA_LOCKING;

    add_entropy(&main_state, indata, size);
    if (size >= INIT_BYTES)
	have_entropy = 1;

    k5_mutex_unlock(&fortuna_lock);

    return FORTUNA_OK;
}

static int
fortuna_bytes(unsigned char *outdata, int size)
{
    krb5_error_code ret = 0;

    if (!fortuna_init()){
	return FORTUNA_FAIL;
    }

    ret = k5_mutex_lock(&fortuna_lock);
    if (ret)
        return FORTUNA_LOCKING;

    resend_bytes += size;
    if (resend_bytes > FORTUNA_RESEED_BYTE || resend_bytes < size) {
	resend_bytes = 0;
	fortuna_reseed();
    }
    extract_data(&main_state, size, outdata);

    k5_mutex_unlock(&fortuna_lock);

    return FORTUNA_OK;
}

static void
fortuna_cleanup(void)
{
    krb5_error_code ret = 0;

    ret = k5_mutex_lock(&fortuna_lock);

    init_done = 0;
    have_entropy = 0;
    memset(&main_state, 0, sizeof(main_state));

    if (!ret)
        k5_mutex_unlock(&fortuna_lock);

    k5_mutex_destroy(&fortuna_lock);

}

static krb5_error_code
fortuna_add_entropy(krb5_context context, unsigned int randsource,
                          const krb5_data *indata)
{
    krb5_error_code ret = 0;
    ret = fortuna_seed((const unsigned char *)indata->data, indata->length);
    if (ret != FORTUNA_OK)
        return KRB5_CRYPTO_INTERNAL;
    return 0;
}

static krb5_error_code
fortuna_make_octets(krb5_context context, krb5_data *outdata)
{
    krb5_error_code ret = 0;
    ret = fortuna_bytes((unsigned char *)outdata->data, outdata->length);
    if (ret != FORTUNA_OK)
        return KRB5_CRYPTO_INTERNAL;
    return 0;
}

const struct krb5_prng_provider krb5int_prng_fortuna = {
    "fortuna",
    fortuna_make_octets,
    fortuna_add_entropy,
    fortuna_init,
    fortuna_cleanup
};

