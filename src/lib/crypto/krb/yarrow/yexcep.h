/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#ifndef YEXCEP_H
#define YEXCEP_H

/*   yes, macros with gotos in them, but in the interests of
 *   avoiding repetition of code, and having less error prone
 *   error handling
 *
 *   EXCEP_DECL - declares the return value and local state variables
 *                needed by the exception macros
 *
 *   THROW( x ) - set return value to x and goto function cleanup
 *                section (CATCH: block).  In the catch block, THROW
 *                does not goto catch label to avoid loops, and instead
 *                falls through to the next statement.
 *
 *   EXCEP_OK   - success return value (=1)
 *
 *   EXCEP_FAIL - failure return value (=0), other user exceptions are
 *                given negative values (<0)
 *
 *   TRY( x )   - if code returns value <= 0 TRY sets return value to
 *                that value and goes to function cleanup section
 *                (CATCH: block).  In the catch block, TRY does not goto
 *                the catch label to avoid loops, and instead
 *                falls through to the next statement.  The
 *                return value is set to the first non success value
 *                returned by a TRY, unless this is overridden by a THROW.
 *
 *   CATCH:     - start of catch block, also switches behavior of
 *                TRY and THROW to not goto CATCH: inside the catch
 *                block to avoid loops
 *
 *   EXCEP_RET  - return the current return value from the function
 *                equivlanet to return (EXCEPTION)
 *
 *   EXCEPTION  - current return value, is set to EXCEP_OK by EXCEP_DECL
 *
 *   EXCEP_BOOL - convert current return value to EXCEP_OK, or EXCEP_FAIL
 *                (EXCEP_FAIL is anything other than EXCEP_OK)
 *
 */

/* example usage */

/*
 *
 * #define EXCEP_OK_COMMENT 2
 * #define EXCEP_NULL_PTR -1
 * #define EXCEP_OUT_OF_MEM -2
 *
 * int bar( char *c )
 * {
 *     EXCEP_DECL;
 *
 *     if ( !c ) { THROW( EXCEP_NULL_PTR ); }
 *     if ( *c == '\0' ) { THROW( EXCEP_FAIL ); );
 *     if ( *c == '#' ) { SET( EXCEP_COMMENT ); }
 *  CATCH:
 *     EXCEP_RET;
 * }
 *
 * int foo( char *c )
 * {
 *     EXCEP_DECL;
 *     int *p = NULL;
 *
 *     if ( !c ) { THROW( EXCEP_NULL_PTR ); }
 *     TRY( bar( c ) );
 *     if ( RETURN == EXCEP_COMMENT ) { print( "comment\n" ); }
 *     p = strdup( c );
 *     if ( !p ) { THROW( EXCEP_OUT_OF_MEM ); }
 *
 *  CATCH:
 *     if ( p ) { TRY( bar( p ) ); free( p ); }
 *     THROW( EXCEP_BOOL );
 *     if ( EXCEPTION == EXCEP_OK ) { printf( "success\n" ); }
 *     EXCEP_RET;
 * }
 *
 */

#define EXCEP_FAIL 0
#define EXCEP_OK 1
#define EXCEP_DECL int _thr = 0, _ret2 = 0, _ret = _ret2+EXCEP_OK

#define THROW( x )                              \
    do {                                        \
        _ret = (x);                             \
        if( !_thr ) { goto _catch; }            \
    } while ( 0 )

#define TRY( x )                                                \
    do {                                                        \
        _ret2 = (x);                                            \
        if ( _ret > 0 && _ret2 <= 0 ) { THROW( _ret2 ); }       \
    } while ( 0 )

#define SET( x ) (_ret = (x))
#define EXCEP_RET return( _ret )
#define EXCEPTION _ret
#define RETURN _ret2
#define CATCH _catch: _thr = 1; if ( 0 ) { goto _foo; } _foo
#define EXCEP_BOOL ( _ret > 0 ? EXCEP_OK : EXCEP_FAIL )

#endif
