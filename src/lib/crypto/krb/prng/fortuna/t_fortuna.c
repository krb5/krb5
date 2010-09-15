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


#define LEN_TEST_BUF 1024 * 1024
static int len = LEN_TEST_BUF;

int
main(int argc, char **argv)
{
    char buffer[LEN_TEST_BUF];
    krb5_data data = {0, LEN_TEST_BUF, (char*)buffer};
    int bit, i;
    double res;
    int bits[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

    if (len < 100000) 
        return 0;

    for (i = 0; i < LEN_TEST_BUF; i++)
         buffer[i] = 0;

    /* head vs tail */
    krb5_c_random_make_octets(NULL, &data);
    for (i = 0; i < len; i++) {
        unsigned char c = ((unsigned char *)buffer)[i];
        for (bit = 0; bit < 8 && c; bit++) {
            if (c & 1)
                bits[bit]++;
            c = c >> 1;
        }
    }
    
    for (bit = 0; bit < 8; bit++) {

        res = ((double)abs(len - bits[bit] * 2)) / (double)len;
        if (res > 0.005){
            printf("head %d vs tail %d > 0.5%%%% %lf == %d vs %d\n",
                 bit, bit, res, len, bits[bit]);
            return 1;
        }

        printf("head vs tails bit %d is %lf\n", bit, res);
    }

    return 0;
}
