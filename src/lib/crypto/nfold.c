#include "k5-int.h"
#include <memory.h>

/*
n-fold(k-bits):
  l = lcm(n,k)
  r = l/k
  s = k-bits | k-bits rot 13 | k-bits rot 13*2 | ... | k-bits rot 13*(r-1)
  compute the 1's complement sum:
	n-fold = s[0..n-1]+s[n..2n-1]+s[2n..3n-1]+..+s[(k-1)*n..k*n-1]
*/

/* representation: msb first, assume n and k are multiples of 8, and
   that k>=16.  this is the case of all the cryptosystems which are
   likely to be used.  this function can be replaced if that
   assumption ever fails.  */

/* input length is in bits */

void
krb5_nfold(inbits, in, outbits, out)
     int inbits;
     krb5_const unsigned char *in;
     int outbits;
     unsigned char *out;
{
    int a,b,c,gcd,lcm;
    int reps;
    int byte, i, msbit;

    /* the code below is more readable if I make these bytes
       instead of bits */

    inbits >>= 3;
    outbits >>= 3;

    /* first compute lcm(n,k) */

    a = outbits;
    b = inbits;

    while(b != 0) {
	c = b;
	b = a%b;
	a = c;
    }

    lcm = outbits*inbits/a;

    /* now do the real work */

    memset(out, 0, outbits);
    byte = 0;

    /* this will end up cycling through k lcm(k,n)/k times, which
       is correct */
    for (i=lcm-1; i>=0; i--) {
	/* compute the msbit in k which gets added into this byte */
	msbit = (/* first, start with the msbit in the first, unrotated
		    byte */
		 ((inbits<<3)-1)
		 /* then, for each byte, shift to the right for each
		    repetition */
		 +(((inbits<<3)+13)*(i/inbits))
		 /* last, pick out the correct byte within that
		    shifted repetition */
		 +((inbits-(i%inbits))<<3)
		 )%(inbits<<3);

	/* pull out the byte value itself */
	byte += (((in[((inbits-1)-(msbit>>3))%inbits]<<8)|
		  (in[((inbits)-(msbit>>3))%inbits]))
		 >>((msbit&7)+1))&0xff;

	/* do the addition */
	byte += out[i%outbits];
	out[i%outbits] = byte&0xff;

#if 0
	printf("msbit[%d] = %d\tbyte = %02x\tsum = %03x\n", i, msbit,
	       (((in[((inbits-1)-(msbit>>3))%inbits]<<8)|
		 (in[((inbits)-(msbit>>3))%inbits]))
		>>((msbit&7)+1))&0xff, byte);
#endif

	/* keep around the carry bit, if any */
	byte >>= 8;

#if 0
	printf("carry=%d\n", byte);
#endif
    }

    /* if there's a carry bit left over, add it back in */
    if (byte) {
	for (i=outbits-1; i>=0; i--) {
	    /* do the addition */
	    byte += out[i];
	    out[i] = byte&0xff;

	    /* keep around the carry bit, if any */
	    byte >>= 8;
	}
    }
}

