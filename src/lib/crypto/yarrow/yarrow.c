/* -*- Mode: C; c-file-style: "bsd" -*- */

/*
 * Yarrow - Cryptographic Pseudo-Random Number Generator
 * Copyright (c) 2000 Zero-Knowledge Systems, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appear in all copies and that
 * both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of Zero-Knowledge Systems,
 * Inc. not be used in advertising or publicity pertaining to
 * distribution of the software without specific, written prior
 * permission.  Zero-Knowledge Systems, Inc. makes no representations
 * about the suitability of this software for any purpose.  It is
 * provided "as is" without express or implied warranty.
 * 
 * See the accompanying LICENSE file for more information.
 */

#include "k5-int.h"

#include <string.h>
#include <limits.h>
#ifdef _WIN32
#include "port-sockets.h"
#else
#   include <unistd.h>
#   if defined(macintosh)
#       include <Memory.h>
#   else
#       include <netinet/in.h>
#   endif
#endif
#if !defined(YARROW_NO_MATHLIB)
#include <math.h>
#endif

#define YARROW_IMPL
#include "yarrow.h"
#include "yhash.h"
#include "ycipher.h"
#include "ylock.h"
#include "ystate.h"
#include "yexcep.h"

#if defined( YARROW_DEBUG ) || defined( YARROW_TRACE )
#   include <stdio.h>
#endif

#if defined( YARROW_TRACE )
extern int yarrow_verbose;
#define TRACE( x ) do { if (yarrow_verbose) { x } } while (0)
#else
#define TRACE( x ) 
#endif

#if defined(macintosh)
#   define make_big_endian32(x) (x)
#else
#   define make_big_endian32(x) htonl(x)
#endif

#if defined( YARROW_DEBUG )
static void hex_print(FILE* f, const char* var, void* data, size_t size);
#endif

static void block_increment( void* block, const int sz );
#if defined( YARROW_SAVE_STATE )
static int Yarrow_Load_State( Yarrow_CTX *y );
static int Yarrow_Save_State( Yarrow_CTX *y );
#endif

static int yarrow_gate_locked(Yarrow_CTX* y);

static const byte zero_block[CIPHER_BLOCK_SIZE] = { 0, };

static const char* const yarrow_str_error[] = {
    "ok",
    "failed",
    "failed: uninitialized",
    "failed: already initialized",
    "failed: no driver",
    "failed: can't open driver",
    "failed: invalid source id",
    "failed: no more source ids available",
    "failed: invalid argument",
    "failed: insufficient privileges",
    "failed: out of memory",
    "failed: resource exhausted",
    "failed: not enough entropy to generate output",
    "failed: locking error",
    "failed: no state to load",
    "failed: state load or save failed",
    "failed: not implemented"
};

/* calculate limits after initialization */

static void krb5int_yarrow_init_Limits(Yarrow_CTX* y)
{
    double tmp1, tmp2, limit;
    /* max number of gates between reseeds -> exceed this, do forced reseed */

    /* #oututs <= min(2^n, 2^(k/3).Pg) */

    /* => #gates <= min(2^n/Pg, 2^(k/3)) */

    tmp1 = POW_CIPHER_BLOCK_SIZE / y->Pg;
    tmp2 = POW_CIPHER_KEY_SIZE;
    limit = min(tmp1, tmp2);
    if (limit < COUNTER_MAX)
    {
	y->gates_limit = limit;
    }
    else
    {
	y->gates_limit = COUNTER_MAX;
    }
}

static int yarrow_reseed_locked( Yarrow_CTX* y, int pool );

/* if the program was forked, the child must not operate on the same
   PRNG state */
#ifdef YARROW_DETECT_FORK

static int
yarrow_input_locked( Yarrow_CTX* y, unsigned source_id,
		     const void *sample,
		     size_t size, size_t entropy_bits );

static int Yarrow_detect_fork(Yarrow_CTX *y)
{
    pid_t newpid;
    EXCEP_DECL;

    /* this does not work for multi-threaded apps if threads have different
     * pids */
       newpid = getpid();
    if ( y->pid != newpid )
    {
	/* we input the pid twice, so it will get into the fast pool at least once
	 * Then we reseed.  This doesn't really increase entropy, but does make the
	 * streams distinct assuming we already have good entropy*/
	y->pid = newpid;
	TRY (yarrow_input_locked (y, 0, &newpid,
				  sizeof (newpid), 0));
	TRY (yarrow_input_locked (y, 0, &newpid,
				  sizeof (newpid), 0));
	TRY (yarrow_reseed_locked (y, YARROW_FAST_POOL));
    }

 CATCH:
    EXCEP_RET;
}

#else

#define Yarrow_detect_fork(x) (YARROW_OK)

#endif

static void Yarrow_Make_Seeded( Yarrow_CTX* y )
{
    TRACE( printf( "SEEDED," ); );
    y->seeded = 1;

    /* now we are seeded switch to _THRESH values */

    y->slow_thresh = YARROW_SLOW_THRESH;
    y->fast_thresh = YARROW_FAST_THRESH;
    y->slow_k_of_n_thresh = YARROW_K_OF_N_THRESH;
}

YARROW_DLL
int krb5int_yarrow_init(Yarrow_CTX* y, const char *filename)
{
    EXCEP_DECL;
    int locked = 0;

    if (!y) { THROW( YARROW_BAD_ARG ); }
    TRY( LOCK() );
    locked = 1;

    y->seeded = 0;
    y->saved = 0;

#if defined( YARROW_DETECT_FORK )
    y->pid = getpid();
#endif

    y->entropyfile = filename;
    y->num_sources = 0;
    mem_zero(y->C, sizeof(y->C));
    HASH_Init(&y->pool[YARROW_FAST_POOL]);
    HASH_Init(&y->pool[YARROW_SLOW_POOL]);

    mem_zero(y->K, sizeof(y->K));

    mem_zero(&y->cipher, sizeof(y->cipher));

    TRY (krb5int_yarrow_cipher_init(&y->cipher, y->K));
    y->out_left = 0;
    y->out_count = 0;
    y->gate_count = 0;
    y->Pg = YARROW_OUTPUTS_PER_GATE;
    y->Pt[YARROW_FAST_POOL] = YARROW_FAST_PT;
    y->Pt[YARROW_SLOW_POOL] = YARROW_SLOW_PT;
    y->slow_k_of_n = 0;

    /* start with INIT_THRESH values, after seeded, switch to THRESH values */

    y->slow_thresh = YARROW_SLOW_INIT_THRESH;
    y->fast_thresh = YARROW_FAST_INIT_THRESH;
    y->slow_k_of_n_thresh = YARROW_K_OF_N_INIT_THRESH;

    krb5int_yarrow_init_Limits(y);

#if defined( YARROW_SAVE_STATE )
    if ( y->entropyfile != NULL )
    {
	int ret = Yarrow_Load_State( y );
	if ( ret != YARROW_OK && ret != YARROW_NO_STATE )
	{
	    THROW( ret );
	}

	/*  if load suceeded then write new state back immediately
	 */

	/*  Also check that it's not already saved, because the reseed in
	 *  Yarrow_Load_State may trigger a save
	 */

	if ( ret == YARROW_OK && !y->saved )
	{
	    TRY( Yarrow_Save_State( y ) );
	}
    }
#endif

    if ( !y->seeded )
    {
	THROW( YARROW_NOT_SEEDED );
    }

 CATCH:
    if ( locked ) { TRY( UNLOCK() ); }
    EXCEP_RET;
}

static
int yarrow_input_maybe_locking( Yarrow_CTX* y, unsigned source_id, 
				const void* sample, 
				size_t size, size_t entropy_bits,
				int do_lock )
{
    EXCEP_DECL;
    int ret;
    int locked = 0;
    Source* source;
    size_t new_entropy;
    size_t estimate;

    if (!y) { THROW( YARROW_BAD_ARG ); }

    if (source_id >= y->num_sources) { THROW( YARROW_BAD_SOURCE ); }
  
    source = &y->source[source_id];
  
    if(source->pool != YARROW_FAST_POOL && source->pool != YARROW_SLOW_POOL)
    {
	THROW( YARROW_BAD_SOURCE );
    }

    if (do_lock) {
	    TRY( LOCK() );
	    locked = 1;
    }

    /* hash in the sample */

    HASH_Update(&y->pool[source->pool], (const void*)sample, size);
  
    /* only update entropy estimate if pool is not full */

    if ( (source->pool == YARROW_FAST_POOL && 
	  source->entropy[source->pool] < y->fast_thresh) ||
	 (source->pool == YARROW_SLOW_POOL &&
	  source->entropy[source->pool] < y->slow_thresh) )
    {
	new_entropy = min(entropy_bits, size * 8 * YARROW_ENTROPY_MULTIPLIER);
	if (source->estimator)
	{
	    estimate = source->estimator(sample, size);
	    new_entropy = min(new_entropy, estimate);
	}
	source->entropy[source->pool] += new_entropy;
	if ( source->entropy[source->pool] > YARROW_POOL_SIZE )
	{
	    source->entropy[source->pool] = YARROW_POOL_SIZE;
	}

	if (source->pool == YARROW_FAST_POOL)
	{
	    if (source->entropy[YARROW_FAST_POOL] >= y->fast_thresh)
	    {
		ret = yarrow_reseed_locked(y, YARROW_FAST_POOL);
		if ( ret != YARROW_OK && ret != YARROW_NOT_SEEDED )
		{
		    THROW( ret );
		}
	    }
	}
	else
	{
	    if (!source->reached_slow_thresh && 
		source->entropy[YARROW_SLOW_POOL] >= y->slow_thresh)
	    {
		source->reached_slow_thresh = 1;
		y->slow_k_of_n++;
		if (y->slow_k_of_n >= y->slow_k_of_n_thresh)
		{
		    y->slow_k_of_n = 0;
		    ret = yarrow_reseed_locked(y, YARROW_SLOW_POOL);
		    if ( ret != YARROW_OK && ret != YARROW_NOT_SEEDED )
		    {
			THROW( ret );
		    }
		}
	    }
	}
    }
  
    /* put samples in alternate pools */

    source->pool = (source->pool + 1) % 2;
  
 CATCH:
    if ( locked ) { TRY( UNLOCK() ); }
    EXCEP_RET;
}

YARROW_DLL
int krb5int_yarrow_input( Yarrow_CTX* y, unsigned source_id, 
		  const void* sample, 
		  size_t size, size_t entropy_bits )
{
    return yarrow_input_maybe_locking(y, source_id, sample, size,
				      entropy_bits, 1);
}

static int
yarrow_input_locked( Yarrow_CTX* y, unsigned source_id,
		     const void *sample,
		     size_t size, size_t entropy_bits )
{
    return yarrow_input_maybe_locking(y, source_id, sample, size,
				      entropy_bits, 0);
}

YARROW_DLL
int krb5int_yarrow_new_source(Yarrow_CTX* y, unsigned* source_id)
{
    EXCEP_DECL;
    int locked = 0;
    Source* source;

    if (!y) { THROW( YARROW_BAD_ARG ); }

    TRY( LOCK() );
    locked = 1;

    if (y->num_sources + 1 > YARROW_MAX_SOURCES)
    {
	THROW( YARROW_TOO_MANY_SOURCES );
    }

    *source_id = y->num_sources;

    source = &y->source[*source_id];

    source->pool = YARROW_FAST_POOL;
    source->entropy[YARROW_FAST_POOL] = 0;
    source->entropy[YARROW_SLOW_POOL] = 0;
    source->reached_slow_thresh = 0;
    source->estimator = 0;

    y->num_sources++;
CATCH:
    if ( locked ) { TRY( UNLOCK() ); }
    EXCEP_RET;
}

int krb5int_yarrow_register_source_estimator(Yarrow_CTX* y, unsigned source_id, 
                                     estimator_fn* fptr)
{
    EXCEP_DECL;
    Source* source;

    if (!y) { THROW( YARROW_BAD_ARG ); }
    if (source_id >= y->num_sources) { THROW( YARROW_BAD_SOURCE ); }

    source = &y->source[source_id];

    source->estimator = fptr;
  
 CATCH:
    EXCEP_RET;
}

static int krb5int_yarrow_output_Block( Yarrow_CTX* y, void* out )
{
    EXCEP_DECL;

    if (!y || !out) { THROW( YARROW_BAD_ARG ); }

    TRACE( printf( "OUT," ); );

    /* perform a gate function after Pg outputs */

    y->out_count++;
    if (y->out_count >= y->Pg)
    {
	y->out_count = 0;
	TRY( yarrow_gate_locked( y ) );

	/* require new seed after reaching gates_limit */

	y->gate_count++;
	if ( y->gate_count >= y->gates_limit )
	{
	    y->gate_count = 0;
	    
	    /* not defined whether to do slow or fast reseed */ 
	    
	    TRACE( printf( "OUTPUT LIMIT REACHED," ); );

	    TRY( yarrow_reseed_locked( y, YARROW_SLOW_POOL ) );
	}
    }
  
    /* C <- (C + 1) mod 2^n */

    block_increment( y->C, CIPHER_BLOCK_SIZE );

    /* R <- E_k(C) */

    TRY ( krb5int_yarrow_cipher_encrypt_block ( &y->cipher, y->C, out ));

#if defined(YARROW_DEBUG)
    printf("===\n");
    hex_print( stdout, "output: C", y->C, CIPHER_BLOCK_SIZE );
    hex_print( stdout, "output: K", y->K, CIPHER_KEY_SIZE );
    hex_print( stdout, "output: O", out, CIPHER_BLOCK_SIZE );
#endif
 CATCH:
    EXCEP_RET;
}

YARROW_DLL
int krb5int_yarrow_status( Yarrow_CTX* y, int *num_sources, unsigned *source_id,
		   size_t *entropy_bits, size_t *entropy_max )
{
    EXCEP_DECL;
    int num = y->slow_k_of_n_thresh;
    int source = -1;
    int emax = y->slow_thresh;
    size_t entropy = 0;
    unsigned i;

    if (!y) { THROW( YARROW_BAD_ARG ); }
    TRY( Yarrow_detect_fork( y ) );

    if (num_sources) { *num_sources = num; }
    if (source_id) { *source_id = -1; }
    if (entropy_bits) { *entropy_bits = 0; }
    if (entropy_max) { *entropy_max = emax; }

    if (y->seeded)
    {
	if (num_sources) { *num_sources = 0; }
	if (entropy_bits) { *entropy_bits = emax; }
	THROW( YARROW_OK );
    }

    for (i = 0; i < y->num_sources; i++)
    {
	if (y->source[i].entropy[YARROW_SLOW_POOL] >= y->slow_thresh)
	{
	    num--;
	}
	else if (y->source[i].entropy[YARROW_SLOW_POOL] > entropy)
	{
	    source = i;
	    entropy = y->source[i].entropy[YARROW_SLOW_POOL];
	}
    }

    if (num_sources) { *num_sources = num; }
    if (source_id) { *source_id = source; }
    if (entropy_bits) { *entropy_bits = entropy; }
    THROW( YARROW_NOT_SEEDED );

 CATCH:
    EXCEP_RET;
}

static int yarrow_output_locked(Yarrow_CTX*, void*, size_t);

YARROW_DLL
int krb5int_yarrow_output( Yarrow_CTX* y, void* out, size_t size )
{
    EXCEP_DECL;
    TRY( LOCK() );
    TRY( yarrow_output_locked(y, out, size));
CATCH:
    UNLOCK();
    EXCEP_RET;
}

static
int yarrow_output_locked( Yarrow_CTX* y, void* out, size_t size )
{
    EXCEP_DECL;
    size_t left;
    char* outp;
    size_t use;

    if (!y || !out) { THROW( YARROW_BAD_ARG ); }
    TRY( Yarrow_detect_fork( y ) );

    if (!y->seeded) { THROW( YARROW_NOT_SEEDED ); }

    left = size;
    outp = out;

    if (y->out_left > 0)
    {
	use = min(left, y->out_left);
	mem_copy(outp, y->out + CIPHER_BLOCK_SIZE - y->out_left, use);
	left -= use;
	y->out_left -= use;
	outp += use;
    }

    for ( ; 
	  left >= CIPHER_BLOCK_SIZE;
	  left -= CIPHER_BLOCK_SIZE, outp += CIPHER_BLOCK_SIZE)
    {
	TRY( krb5int_yarrow_output_Block(y, outp) );
    }

    if (left > 0)
    {
	TRY( krb5int_yarrow_output_Block(y, y->out) );
	mem_copy(outp, y->out, left);
	y->out_left = CIPHER_BLOCK_SIZE - left;
    }

 CATCH:
    EXCEP_RET;
}

static int yarrow_gate_locked(Yarrow_CTX* y)
{
    EXCEP_DECL;
    byte new_K[CIPHER_KEY_SIZE];

    if (!y) { THROW( YARROW_BAD_ARG ); }
  
    TRACE( printf( "GATE[" ); );

    /* K <- Next k bits of PRNG output */

    TRY( yarrow_output_locked(y, new_K, CIPHER_KEY_SIZE) );
    mem_copy(y->K, new_K, CIPHER_KEY_SIZE);

    /* need to resetup the key schedule as the key has changed */

    TRY (krb5int_yarrow_cipher_init(&y->cipher, y->K));

 CATCH:
    TRACE( printf( "]," ); );
    mem_zero(new_K, sizeof(new_K));
    EXCEP_RET;
}

int krb5int_yarrow_gate(Yarrow_CTX* y)
{
    EXCEP_DECL;
    byte new_K[CIPHER_KEY_SIZE];

    if (!y) { THROW( YARROW_BAD_ARG ); }
  
    TRACE( printf( "GATE[" ); );

    /* K <- Next k bits of PRNG output */

    TRY( krb5int_yarrow_output(y, new_K, CIPHER_KEY_SIZE) );
    mem_copy(y->K, new_K, CIPHER_KEY_SIZE);

    /* need to resetup the key schedule as the key has changed */

    TRY (krb5int_yarrow_cipher_init(&y->cipher, y->K));

 CATCH:
    TRACE( printf( "]," ); );
    mem_zero(new_K, sizeof(new_K));
    EXCEP_RET;
}

#if defined( YARROW_SAVE_STATE )
static int Yarrow_Load_State( Yarrow_CTX *y )
{
    EXCEP_DECL;
    Yarrow_STATE state;
    
    if ( !y ) { THROW( YARROW_BAD_ARG ); }

    if ( y->entropyfile )
    {
	TRY( STATE_Load(y->entropyfile, &state) );
	TRACE( printf( "LOAD STATE," ); );

#if defined( YARROW_DEBUG )
	hex_print( stderr, "state.load", state.seed, sizeof(state.seed));
#endif
    
	/* what to do here is not defined by the Yarrow paper */
	/* this is a place holder until we get some clarification */
    
	HASH_Update( &y->pool[YARROW_FAST_POOL], 
		     state.seed, sizeof(state.seed) );

	Yarrow_Make_Seeded( y );

	TRY( krb5int_yarrow_reseed(y, YARROW_FAST_POOL) );
    }
 CATCH:
    mem_zero(state.seed, sizeof(state.seed));
    EXCEP_RET;
}

static int Yarrow_Save_State( Yarrow_CTX *y )
{
    EXCEP_DECL;
    Yarrow_STATE state;
    
    if ( !y ) { THROW( YARROW_BAD_ARG ); }

    if ( y->entropyfile && y->seeded ) 
    {
	TRACE( printf( "SAVE STATE[" ); );
	TRY( krb5int_yarrow_output( y, state.seed, sizeof(state.seed) ) );
	TRY( STATE_Save(y->entropyfile, &state) );
    }
    y->saved = 1;
# if defined(YARROW_DEBUG)
    hex_print(stdout, "state.save", state.seed, sizeof(state.seed));
# endif

 CATCH:
    TRACE( printf( "]," ); );
    mem_zero(state.seed, sizeof(state.seed));
    EXCEP_RET;
}

#endif

static int yarrow_reseed_locked(Yarrow_CTX* y, int pool)
{
    EXCEP_DECL;
    HASH_CTX* fast_pool = &y->pool[YARROW_FAST_POOL];
    HASH_CTX* slow_pool = &y->pool[YARROW_SLOW_POOL];
    byte digest[HASH_DIGEST_SIZE];
    HASH_CTX hash;
    byte v_0[HASH_DIGEST_SIZE];
    byte v_i[HASH_DIGEST_SIZE];
    krb5_ui_4 big_endian_int32;
    COUNTER i;

    if (!y) { THROW( YARROW_BAD_ARG ); }
    if( pool != YARROW_FAST_POOL && pool != YARROW_SLOW_POOL )
    {
	THROW( YARROW_BAD_ARG );
    }
  
    TRACE( printf( "%s RESEED,", 
		   pool == YARROW_SLOW_POOL ? "SLOW" : "FAST" ); );

    if (pool == YARROW_SLOW_POOL)
    {
	/* SLOW RESEED */

	/* feed hash of slow pool into the fast pool */


	HASH_Final(slow_pool, digest);

	/*  Each pool contains the running hash of all inputs fed into it
	 *  since it was last used to carry out a reseed -- this implies
	 *  that the pool must be reinitialized after a reseed
	 */

	HASH_Init(slow_pool);    /* reinitialize slow pool */
	HASH_Update(fast_pool, digest, sizeof(digest));

	if (y->seeded == 0)
	{
	    Yarrow_Make_Seeded( y );
	}
    }

    /* step 1. v_0 <- hash of all inputs into fast pool */

    HASH_Final(fast_pool, &v_0);
    HASH_Init(fast_pool);    /* reinitialize fast pool */ 

    /* v_i <- v_0 */

    mem_copy( v_i, v_0, sizeof(v_0) );

    /* step 2. v_i = h(v_{i-1}|v_0|i) for i = 1,..,Pt */

    /* note: this code has to work for Pt = 0 also */

    for ( i = 0; i < y->Pt[pool]; i++ )
    {
	HASH_Init(&hash);
	HASH_Update(&hash, v_i, sizeof(v_i));
	HASH_Update(&hash, v_0, sizeof(v_0));
	big_endian_int32 = make_big_endian32(0); /* MS word */
	HASH_Update(&hash, &big_endian_int32, sizeof(krb5_ui_4));
	big_endian_int32 = make_big_endian32(i & 0xFFFFFFFF); /* LS word */
	HASH_Update(&hash, &big_endian_int32, sizeof(krb5_ui_4));
	HASH_Final(&hash, &v_i);
    }

    /* step3. K = h'(h(v_Pt|K)) */

    /* t = h(v_Pt|K) */

    HASH_Init(&hash);
    HASH_Update(&hash, v_i, sizeof(v_i));
    HASH_Update(&hash, y->K, sizeof(y->K));
    HASH_Final(&hash, v_i);

#if defined(YARROW_DEBUG)
    hex_print(stdout, "old K", y->K, sizeof(y->K));
#endif
    /* K <- h'(t) */

    TRY( krb5int_yarrow_stretch(v_i, HASH_DIGEST_SIZE, y->K, CIPHER_KEY_SIZE) );

    /* need to resetup the key schedule as the key has changed */

    TRY(krb5int_yarrow_cipher_init(&y->cipher, y->K));

#if defined(YARROW_DEBUG)
    hex_print(stdout, "new K", y->K, sizeof(y->K));
#endif

    /* step 4. C <- E_k(0) */

#if defined(YARROW_DEBUG)
    hex_print(stdout, "old C", y->C, sizeof(y->C));
#endif
    TRY (krb5int_yarrow_cipher_encrypt_block (&y->cipher, zero_block, y->C));
#if defined(YARROW_DEBUG)
    hex_print(stdout, "new C", y->C, sizeof(y->C));
#endif

    /* discard part output from previous key */
  
    y->out_left = 0;

    /*   step 5. Reset all entropy estimate accumulators of the entropy
     *   accumulator to zero
     */

    for (i = 0; i < y->num_sources; i++)
    {
	y->source[i].entropy[pool] = 0;
	if (pool == YARROW_SLOW_POOL)
	{
    /*   if this is a slow reseed, reset the fast pool entropy
     *   accumulator also
     */
	    y->source[i].entropy[YARROW_FAST_POOL] = 0;
	    y->source[i].reached_slow_thresh = 0;
	}
    }

    /*  step 7. If a seed file is in use, the next 2k bits of output
     *  are written to the seed file
     */

#if defined( YARROW_SAVE_STATE )
    if ( y->seeded && y->entropyfile )
    {
	TRY( Yarrow_Save_State( y ) );
    }
#endif

 CATCH:
    /*   step 6. Wipe the memory of all intermediate values
     *
     */

    mem_zero( digest, sizeof(digest) );
    mem_zero( &hash, sizeof(hash) );
    mem_zero( v_0, sizeof(v_0) );
    mem_zero( v_i, sizeof(v_i) );

    EXCEP_RET;
}
int krb5int_yarrow_reseed(Yarrow_CTX* y, int pool)
{
	int r;
	LOCK();
	r = yarrow_reseed_locked(y, pool);
	UNLOCK();
	return r;
}

int krb5int_yarrow_stretch(const byte* m, size_t size, byte* out, size_t out_size)
{
    EXCEP_DECL;
    const byte* s_i;
    byte* outp;
    int left;
    unsigned int use;
    HASH_CTX hash, save;
    byte digest[HASH_DIGEST_SIZE];
  
    if (m == NULL || size == 0 || out == NULL || out_size == 0)
    {
	THROW( YARROW_BAD_ARG );
    }
  
    /* 
     *   s_0 = m
     *   s_1 = h(s_0 | ... | s_{i-1})
     *
     *   h'(m, k) = first k bits of (s_0 | s_1 | ...)
     *
     */

    outp = out;
    left = out_size;
  
    use = min(out_size, size);
    mem_copy(outp, m, use);    /* get k bits or as many as available */

    s_i = (const byte*)m;            /* pointer to s0 = m */
    outp += use;
    left -= use;

    HASH_Init(&hash);
    for ( ;
	  left > 0;
	  left -= HASH_DIGEST_SIZE)
    {
	HASH_Update(&hash, s_i, use);
    
	/* have to save hash state to one side as HASH_final changes state */

	mem_copy(&save, &hash, sizeof(hash));
	HASH_Final(&hash, digest);

	use = min(HASH_DIGEST_SIZE, left);
	mem_copy(outp, digest, use);

	/* put state back for next time */

	mem_copy(&hash, &save, sizeof(hash));

	s_i = outp;            /* retain pointer to s_i */
	outp += use;
    }
  
 CATCH:
    mem_zero(&hash, sizeof(hash));
    mem_zero(digest, sizeof(digest));

    EXCEP_RET;
}

static void block_increment(void* block, const int sz)
{
    byte* b = block;
    int i;
  
    for (i = sz-1; (++b[i]) == 0 && i > 0; i--)
    {
	; /* nothing */
    }
}

YARROW_DLL
int krb5int_yarrow_final(Yarrow_CTX* y)
{
    EXCEP_DECL;
    int locked = 0;

    if (!y) { THROW( YARROW_BAD_ARG ); }
    TRY( LOCK() );
    locked = 1;

#if defined( YARROW_SAVE_STATE )
    if ( y->seeded && y->entropyfile )
    {
	TRY( Yarrow_Save_State( y ) );
    }
#endif

 CATCH:
    krb5int_yarrow_cipher_final(&y->cipher);
    mem_zero( y, sizeof(Yarrow_CTX) );
    if ( locked ) { TRY( UNLOCK() ); }
    EXCEP_RET;
}

YARROW_DLL
const char* krb5int_yarrow_str_error( int err )
{
    err = 1-err;
    if ( err < 0 || err >= sizeof( yarrow_str_error ) / sizeof( char* ) )
    {
	err = 1-YARROW_FAIL;
    } 
    return yarrow_str_error[ err ];
}

#if defined(YARROW_DEBUG)
static void hex_print(FILE* f, const char* var, void* data, size_t size)
{
    const char* conv = "0123456789abcdef";
    size_t i;
    char* p = (char*) data;
    char c, d;

    fprintf(f, var);
    fprintf(f, " = ");
    for (i = 0; i < size; i++)
    {
	c = conv[(p[i] >> 4) & 0xf];
	d = conv[p[i] & 0xf];
	fprintf(f, "%c%c", c, d);
    }
    fprintf(f, "\n");
}
#endif
