/* -*- Mode: C; c-file-style: "bsd" -*- */
/*
 * Yarrow - Cryptographic Pseudo-Random Number Generator
 * Copyright (c) 2000 Zero-Knowledge Systems, Inc.
 *
 * See the accompanying LICENSE file for license information.
 */

#include <stdio.h>
#include <errno.h>
#if !defined(macintosh)
# include <sys/types.h>
# include <sys/stat.h>
# include <fcntl.h>
#endif
#include "yarrow.h"
#include "ystate.h"
#include "yexcep.h"

#ifdef YARROW_SAVE_STATE

#if defined(macintosh) && YARROW_DRIVER

/* Mac OS -- driver environment */

#  include "YarrowDriverCore.h"

int STATE_Save(const char *filename, const struct Yarrow_STATE* state)
{
# pragma unused(filename)
  
    return (PerformStateWrite(state) ? YARROW_OK : YARROW_STATE_ERROR);
}

int STATE_Load(const char *filename, struct Yarrow_STATE* state)
{
# pragma unused(filename)
  
    return (PerformStateRead(state) ? YARROW_OK : YARROW_STATE_ERROR);
}

#else

/* Other platforms */

int STATE_Save(const char *filename, const struct Yarrow_STATE* state)
{
    EXCEP_DECL;
    FILE* fp = NULL;

#ifndef WIN32
    int fd = open( filename, O_CREAT | O_RDWR, 0600 );
    if ( fd < 0 ) { THROW( YARROW_STATE_ERROR ); }
    fp = fdopen(fd, "wb");
#endif
    if ( !fp )
    {
	fp = fopen(filename,"wb");
    }
    if ( !fp ) { THROW( YARROW_STATE_ERROR ); }
#ifndef WIN32
    if ( chmod(filename, 0600) != 0 ) {	THROW( YARROW_STATE_ERROR ); }
#endif

    if ( fwrite(state, sizeof(*state), 1, fp) != 1 ) 
    { 
	THROW( YARROW_STATE_ERROR ); 
    }

 CATCH:
    if ( fp ) 
    {
	if ( fclose(fp) != 0 ) { THROW( YARROW_STATE_ERROR ); }
    }    
    EXCEP_RET;
}

int STATE_Load(const char *filename, struct Yarrow_STATE* state)
{
    EXCEP_DECL;
    FILE* fp;

    fp = fopen(filename, "rb");
    if ( !fp ) 
    { 
	if ( errno == ENOENT )	/* file doesn't exist */
	{
	    THROW( YARROW_NO_STATE );
	}
	else			/* something else went wrong */
	{
	    THROW( YARROW_STATE_ERROR ); 
	}
    }
    if ( fread(state, sizeof(*state), 1, fp) != 1 ) 
    { 
	THROW( YARROW_STATE_ERROR );
    }

 CATCH:
    if ( fp )
    {
	if ( fclose(fp) != 0 ) { THROW( YARROW_STATE_ERROR ); }
    }    
    EXCEP_RET;
}

#endif    /* platform */
#endif    /* YARROW_SAVE_STATE */
