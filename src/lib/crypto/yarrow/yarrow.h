/* -*- Mode: C; c-file-style: "bsd" -*- */

#ifndef YARROW_H
#define YARROW_H

#ifdef HAVE_UNISTD_H
#define YARROW_DETECT_FORK
#include <unistd.h>
#endif
#define YARROW_NO_MATHLIB

#include "ytypes.h"
#include "yhash.h"
#include "ycipher.h"

/* These error codes are returned by the functions below. */

#define YARROW_OK                1  /* All is well */
#define YARROW_FAIL              0  /* generic failure */
#define YARROW_NOT_INIT         -1  /* YarrowInit hasn't been called */
#define YARROW_ALREADY_INIT     -2  /* YarrowInit has already been called */
#define YARROW_NO_DRIVER        -3  /* driver doesn't exist */
#define YARROW_CANT_OPEN        -4  /* can't open driver */
#define YARROW_BAD_SOURCE       -5  /* invalid source id */
#define YARROW_TOO_MANY_SOURCES -6  /* can't create any more source ids */
#define YARROW_BAD_ARG          -7  /* invalid argument */
#define YARROW_ACCESS           -8  /* insufficient privileges */
#define YARROW_NOMEM            -9  /* out of memory */
#define YARROW_NORSRC          -10  /* a resource is exhausted */
#define YARROW_NOT_SEEDED      -11  /* not enough entropy to generate output */
#define YARROW_LOCKING         -12  /* locking error */
#define YARROW_NO_STATE        -13  /* there is no state to load */
#define YARROW_STATE_ERROR     -14  /* error with state load or save */
#define YARROW_NOT_IMPL        -15  /* not implemented */

#ifdef __cplusplus
extern "C" {
#endif

/* Yarrow implementation and configuration parameters */

/* pool identification */
#define YARROW_FAST_POOL 0
#define YARROW_SLOW_POOL 1

#define YARROW_MAX_SOURCES 20
#define YARROW_ENTROPY_MULTIPLIER 0.5

#define YARROW_POOL_SIZE (HASH_DIGEST_SIZE*8)

#define YARROW_OUTPUTS_PER_GATE 10   /* Pg */
#define YARROW_FAST_PT 10
#define YARROW_SLOW_PT 100

/* thresholds to use once seeded */

#define YARROW_FAST_THRESH 100
#define YARROW_SLOW_THRESH 160
#define YARROW_K_OF_N_THRESH 2

/* The Yarrow paper does not specify when the initial seed should be
   considered complete. Use the same conditions as a slow reseed */

#define YARROW_FAST_INIT_THRESH YARROW_FAST_THRESH
#define YARROW_SLOW_INIT_THRESH YARROW_SLOW_THRESH
#define YARROW_K_OF_N_INIT_THRESH YARROW_K_OF_N_THRESH

/* sanity checks */

#if YARROW_FAST_THRESH > YARROW_POOL_SIZE
error "can't have higher YARROW_FAST_THRESH than pool size"
#endif

#if YARROW_SLOW_THRESH > YARROW_POOL_SIZE
error "can't have higher YARROW_SLOW_THRESH than pool size"
#endif

#if YARROW_FAST_INIT_THRESH > YARROW_POOL_SIZE
error "can't have higher YARROW_FAST_INIT_THRESH than pool size"
#endif

#if YARROW_SLOW_INIT_THRESH > YARROW_POOL_SIZE
error "can't have higher YARROW_SLOW_INIT_THRESH than pool size"
#endif

typedef size_t estimator_fn(const void* sample, size_t size);

typedef struct
{
    int pool;
    size_t entropy[2];
    int reached_slow_thresh;
    estimator_fn* estimator;
} Source;

typedef struct
{
    /* state */
    int seeded;
    int saved;
#if defined( YARROW_DETECT_FORK )
    int pid;
#endif
    Source source[YARROW_MAX_SOURCES];
    unsigned num_sources;
    HASH_CTX pool[2];
    byte out[CIPHER_BLOCK_SIZE];
    unsigned out_left;
    COUNTER out_count;
    COUNTER gate_count;
    COUNTER gates_limit;
    byte C[CIPHER_BLOCK_SIZE];
    CIPHER_CTX cipher;
    byte K[CIPHER_KEY_SIZE];

    const char *entropyfile;

    /* parameters */
    COUNTER Pt[2];
    COUNTER Pg;
    int slow_k_of_n;

    /* current thresholds */
    int slow_thresh;
    int fast_thresh;
    int slow_k_of_n_thresh;
} Yarrow_CTX;

#   define YARROW_DLL


YARROW_DLL
int krb5int_yarrow_init( Yarrow_CTX* y, const char *filename );


YARROW_DLL
int krb5int_yarrow_input( Yarrow_CTX* y, unsigned source_id,
		  const void* sample, 
		  size_t size, size_t entropy_bits );

YARROW_DLL
int krb5int_yarrow_status( Yarrow_CTX* y, int *num_sources, unsigned *source_id,
		   size_t *entropy_bits, size_t *entropy_max );

YARROW_DLL
int krb5int_yarrow_output( Yarrow_CTX* y, void* out, size_t size );

YARROW_DLL
int krb5int_yarrow_new_source( Yarrow_CTX* y, unsigned* source_id );

YARROW_DLL
int krb5int_yarrow_register_source_estimator( Yarrow_CTX* y, unsigned source_id, 
				      estimator_fn* fptr );

YARROW_DLL
int krb5int_yarrow_stretch( const byte* m, size_t size, byte* out, size_t out_size );

YARROW_DLL
int krb5int_yarrow_reseed( Yarrow_CTX* y, int pool );

YARROW_DLL
int krb5int_yarrow_gate( Yarrow_CTX* y );

YARROW_DLL
int krb5int_yarrow_final( Yarrow_CTX* y );

YARROW_DLL
const char* krb5int_yarrow_str_error( int );


#   define mem_zero(p, n)       memset((p), 0, (n))
#   define mem_copy(d, s, n)    memcpy((d), (s), (n))


#if !defined(WIN32)
#   define min(x, y) ((x) < (y) ? (x) : (y))
#   define max(x, y) ((x) > (y) ? (x) : (y))
#endif



#ifdef __cplusplus
}
#endif

#endif /* YARROW_H */
