/*
 * Copyright (c) 2007 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "prng.h"
#include "fortuna.h"
#include <k5-int.h>

#define LEN_TEST_BUF 1024
static int len = LEN_TEST_BUF;

static void hex_print( FILE* f, const char* var, void* data, size_t size );

int
main(int argc, char **argv)
{
    char buffer[LEN_TEST_BUF];
    krb5_data data = {0, LEN_TEST_BUF, (char*)buffer};
    int i;

    for (i = 0; i < LEN_TEST_BUF; i++)
         buffer[i] = 0;

    krb5_c_random_make_octets(NULL, &data);

    hex_print( stdout, "random1", data.data, data.length );

    /* To target FORTUNA_RESEED_BYTE */
    i = 0;
    while (i++ < 11){
        krb5_c_random_make_octets(NULL, &data);
    }

    hex_print( stdout, "random2", data.data, data.length );

    return 0;
}
static void
hex_print( FILE* f, const char* var, void* data, size_t size )
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

