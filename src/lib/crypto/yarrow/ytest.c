/* -*- Mode: C; c-file-style: "bsd" -*- */
/*
 * Yarrow - Cryptographic Pseudo-Random Number Generator
 * Copyright (c) 2000 Zero-Knowledge Systems, Inc.
 *
 * See the accompanying LICENSE file for license information.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "yarrow.h"
#include "yexcep.h"

void hex_print( FILE* f, const char* var, void* data, size_t size );
void dump_yarrow_state( FILE* f, Yarrow_CTX* y );

#define YARROW_SEED_FILE "seed"

static void print_yarrow_status( Yarrow_CTX *y )
{
    int sid, pool;
    Source* source;

    for ( pool = 0; pool < 2; pool++ )
    {
	printf( " %s: ", pool == YARROW_SLOW_POOL ? "slow" : "fast" );
	for ( sid = 0; sid < y->num_sources; sid++ )
	{
	    source = &y->source[ sid ];
	    printf( "#%d=%d/%d, ", sid, source->entropy[pool], 
		    pool == YARROW_SLOW_POOL ? 
		    y->slow_thresh : y->fast_thresh );
	}
    }
    printf( "\n" );
}

int yarrow_verbose = 0;
#define VERBOSE( x ) if ( yarrow_verbose ) { x }

int Instrumented_krb5int_yarrow_input( Yarrow_CTX* y, int sid, void* sample,
			       size_t size, int entropy )
{
    int ret;

    VERBOSE( printf( "krb5int_yarrow_input( #%d, %d bits, %s ) = [", sid, entropy, 
		     y->source[sid].pool == 
		     YARROW_SLOW_POOL ? "slow" : "fast" ); );
    ret = krb5int_yarrow_input( y, sid, sample, size, entropy );

    VERBOSE( printf( "%s]\n", krb5int_yarrow_str_error( ret ) ); );
    VERBOSE( print_yarrow_status( y ); );
    return (ret);
}

typedef int (*test_fn)( void );

int test_1( void );
int test_2( void );
int test_3( void );
int test_4( void );

test_fn test_func[] =
{
    test_1, test_2, test_3, test_4
};

#define num_tests ( sizeof(test_func) / sizeof(test_fn) )

int do_test( int t )
{
    EXCEP_DECL;
    int ret;

    printf( "doing test %d ... ", t ); fflush( stdout );
    ret = test_func[ t-1 ]();
    VERBOSE( printf( "\ndone test %d ", t ); );
    printf( "[%s]\n", krb5int_yarrow_str_error( ret ) ); fflush( stdout );
    THROW( ret );

 CATCH:
    THROW( EXCEP_BOOL );
    EXCEP_RET;
}

int main( int argc, char* argv[] )
{
    EXCEP_DECL;
    int test = 0;
    char** argvp;
    char* arg;
    char* conv_ok = NULL;
    int ok = YARROW_OK;
    int done_some_tests = 0;
    int i;
    int ret;

#if defined(__MWERKS__) && defined(macintosh)
    argc = ccommand(&argv);
#endif
    
    for ( argvp = argv+1, i = 1; i < argc; i++, argvp++ )
    {
	arg = *argvp;
	if ( arg[0] == '-' ) 
	{
	    switch ( arg[1] )
	    {
	    case 'v': yarrow_verbose = 1; continue; 
	    default: fprintf( stderr, "usage: test [-v] [[test] ... ]\n" );
		THROW( YARROW_FAIL );
	    }
	}
	conv_ok = NULL;
	test = strtoul( arg, &conv_ok, 10 );
	if ( !conv_ok || test < 1 || test > num_tests )
	{
	    fprintf( stderr, "usage: test [-v] [[test] ... ]\n" );
	    THROW( YARROW_FAIL );
	}
	else
	{
	    ret = do_test( test );
	    if ( ok ) { ok = ret; }
	    done_some_tests = 1;
	}
    }

    if ( !done_some_tests )
    {
	for ( i = 1; i <= num_tests; i++ )
	{
	    ret = do_test( i );
	    if ( ok ) { ok = ret; }
	}
    }
    THROW( ok );

 CATCH:
    switch (EXCEPTION)
    {
    case YARROW_OK:
	exit (EXIT_SUCCESS);
    default:
	exit (EXIT_FAILURE);
    }
}

int test_1( void )
{
    EXCEP_DECL;

#if defined(YARROW_HASH_SHA1)
    VERBOSE( printf( "\nsha1 test\n\n" ); );
    THROW( YARROW_NOT_IMPL );
#elif defined(YARROW_MD5)
    VERBOSE( printf( "\nmd5 test\n\n" ); );
    THROW( YARROW_NOT_IMPL );
#else
    VERBOSE( printf( "\nunknown hash function\n\n" ); );
    THROW( YARROW_NOT_IMPL );
#endif
 CATCH:
    EXCEP_RET;
}

int test_2( void )
{
    EXCEP_DECL;

#if defined(YARROW_CIPHER_3DES)
    VERBOSE( printf( "\n3des test\n\n" ); );
    THROW( YARROW_NOT_IMPL );
#elif defined(YARROW_CIPHER_BLOWFISH)
    VERBOSE( printf( "\nblowfish test\n\n" ); );
    THROW( YARROW_NOT_IMPL );
#elif defined(YARROW_CIPHER_IDEA)
    VERBOSE( printf( "\nidea test\n\n" ); );
    THROW( YARROW_NOT_IMPL );
#else
    VERBOSE( printf( "\nunknown encryption function\n\n" ); );
    THROW( YARROW_NOT_IMPL );
#endif
 CATCH:
    EXCEP_RET;
}

int test_3( void )
{
    EXCEP_DECL;

#if !defined(YARROW_CIPHER_3DES) || !defined(YARROW_HASH_SHA1)
    VERBOSE( printf( "\nnot Yarrow-SHA1-3DES (aka Yarrow-160)\n\n" ); );
    THROW( YARROW_NOT_IMPL );
#endif

    VERBOSE( printf( "\nkrb5int_yarrow_stretch\n\n" ); );
    THROW( YARROW_NOT_IMPL );
    
 CATCH:
    EXCEP_RET;
}

int test_4( void )
{
    EXCEP_DECL;
    Yarrow_CTX yarrow;
    int initialized = 0;
    unsigned user, mouse, keyboard;
    int i, ret;
    byte user_sample[ 20 ];
    byte mouse_sample[ 4 ];
    byte keyboard_sample[ 2 ];
    byte random[ 30 ];
    byte junk[ 48 ];

    memset( user_sample,     3, sizeof( user_sample ) );
    memset( mouse_sample,    1, sizeof( mouse_sample ) );
    memset( keyboard_sample, 2, sizeof( keyboard_sample ) );

    VERBOSE( printf( "\nGeneral workout test\n\n" ); )

    VERBOSE( printf( "krb5int_yarrow_init() = [" ); );
    ret = krb5int_yarrow_init( &yarrow, YARROW_SEED_FILE );
    VERBOSE( printf( "%s]\n", krb5int_yarrow_str_error( ret ) ); );

    if ( ret != YARROW_OK && ret != YARROW_NOT_SEEDED ) { THROW( ret ); }
    initialized = 1;

#if defined( YARROW_DEBUG )
    dump_yarrow_state( stdout, &yarrow );
#endif

    ret = krb5int_yarrow_new_source( &yarrow, &user );
    VERBOSE( printf( "krb5int_yarrow_new_source() = [%s]\n",
		     krb5int_yarrow_str_error( ret ) ); );
    if ( ret != YARROW_OK ) { THROW( ret ); }
  
    VERBOSE( printf( "Yarrow_Poll( #%d ) = [", user ); );
    ret = Yarrow_Poll( &yarrow, user );
    VERBOSE( printf( "%s]\n", krb5int_yarrow_str_error( ret ) ); );

    ret = krb5int_yarrow_new_source( &yarrow, &mouse );
    VERBOSE( printf( "krb5int_yarrow_new_source() = [%s]\n", 
		     krb5int_yarrow_str_error( ret ) ); );
    if ( ret != YARROW_OK ) { THROW( ret ); }

    ret = krb5int_yarrow_new_source( &yarrow, &keyboard );
    VERBOSE( printf( "krb5int_yarrow_new_source() = [%s]\n", 
		     krb5int_yarrow_str_error( ret ) ); );
    if ( ret != YARROW_OK ) { THROW( ret ); }

/*  prematurely try to draw output, to check failure when no
 *  seed file, or state saving turned off
 */

    VERBOSE( printf( "krb5int_yarrow_output( %d ) = [", sizeof( random ) ); );
    ret = krb5int_yarrow_output( &yarrow, random, sizeof( random ) );
    VERBOSE( printf( "%s]\n", krb5int_yarrow_str_error( ret ) ); );

/*   do it twice so that we some slow samples 
 *   (first sample goes to fast pool, and then samples alternate)
 */

    for ( i = 0; i < 2; i++ )
    {
	TRY( Instrumented_krb5int_yarrow_input( &yarrow, mouse, mouse_sample, 
					sizeof( mouse_sample ), 2 ) );
	
	TRY( Instrumented_krb5int_yarrow_input( &yarrow, keyboard, keyboard_sample, 
					sizeof( keyboard_sample ), 2 ) );

	TRY( Instrumented_krb5int_yarrow_input( &yarrow, user, user_sample, 
					sizeof( user_sample ), 2 ) );
    }
	
#if defined( YARROW_DEBUG )
    dump_yarrow_state( stdout, &yarrow );
#endif

    VERBOSE( printf( "\nInduce user source (#%d) to reach "
		     "slow threshold\n\n", user ); );

    /* induce fast reseed */

    for ( i = 0; i < 7; i++ )
    {
	TRY( Instrumented_krb5int_yarrow_input( &yarrow, user, user_sample, 
					sizeof( user_sample ), 
					sizeof( user_sample ) * 3 ) );
    }

    VERBOSE( printf( "\nInduce mouse source (#%d) to reach "
		     "slow threshold reseed\n\n", mouse ); );

    /* induce slow reseed, by triggering a second source to reach it's
       threshold */

    for ( i = 0; i < 40; i++ )
    {
	TRY( Instrumented_krb5int_yarrow_input( &yarrow, mouse, mouse_sample, 
					sizeof( mouse_sample ), 
					sizeof( mouse_sample )*2 ) );
    }

    VERBOSE( printf( "\nProduce some output\n\n" ); );

    for ( i = 0; i < 30; i++ )
    {
	VERBOSE( printf( "krb5int_yarrow_output( %d ) = [", sizeof( junk ) ); );
	ret = krb5int_yarrow_output( &yarrow, junk, sizeof( junk ) );
	VERBOSE( printf( "%s]\n", krb5int_yarrow_str_error( ret ) ); );
	if ( ret != YARROW_OK ) { THROW( ret );	}
    }

    memset( junk, 0, sizeof( junk ) );

    VERBOSE( printf( "\nTrigger some fast and slow reseeds\n\n" ); );

    for ( i = 0; i < 30; i++ )
    {
	/* odd input to a different source so there are some slow reseeds */

	if ( i % 16 == 0 )
	{
	    TRY( Instrumented_krb5int_yarrow_input( &yarrow, mouse, junk, 
					    sizeof( junk ), 
					    sizeof( junk ) * 3 ) );
	}
	else
	{
	    TRY( Instrumented_krb5int_yarrow_input( &yarrow, user, junk, 
					    sizeof( junk ), 
					    sizeof( junk ) * 3 ) );
	}
    }

    VERBOSE( printf( "\nPrint some random output\n\n" ); );
    
    VERBOSE( printf( "krb5int_yarrow_output( %d ) = [", sizeof( random ) ); );
    ret = krb5int_yarrow_output( &yarrow, random, sizeof( random ) );
    VERBOSE( printf( "%s]\n", krb5int_yarrow_str_error( ret ) ); );
    if ( ret != YARROW_OK )
    {
	THROW( ret );
    }
    else
    {
	VERBOSE( hex_print( stdout, "random", random, sizeof( random ) ); );
    }

    VERBOSE( printf( "\nClose down Yarrow\n\n" ); );

 CATCH:
    if ( initialized )
    {
	VERBOSE( printf( "krb5int_yarrow_final() = [" ); );
	ret = krb5int_yarrow_final( &yarrow );
	VERBOSE( printf( "%s]\n", krb5int_yarrow_str_error( ret ) ); );
	THROW( ret );
    }
    EXCEP_RET;
}

void hex_print( FILE* f, const char* var, void* data, size_t size )
{
    const char* conv = "0123456789abcdef";
    size_t i;
    char* p = (char*) data;
    char c, d;
    
    fprintf( f, var );
    fprintf( f, " = " );
    for ( i = 0; i < size; i++ )
    {
	c = conv[ (p[ i ] >> 4) & 0xf ];
	d = conv[ p[ i ] & 0xf ];
	fprintf( f, "%c%c", c, d );
    }
    fprintf( f, "\n" );
}

void dump_yarrow_state( FILE* f, Yarrow_CTX* y )
{
    fprintf( f, "===Yarrow State===\n" );
    hex_print( f, "C", y->C, sizeof( y->C ) );
    hex_print( f, "K", y->K, sizeof( y->K ) );
}
