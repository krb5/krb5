/*
 * Copyright 1991-1994 by The University of Texas at Austin
 * All rights reserved.
 *
 * For infomation contact:
 * Rick Watson
 * University of Texas
 * Computation Center, COM 1
 * Austin, TX 78712
 * r.watson@utexas.edu
 * 512-471-3241
 */

#pragma parameter __D0 getA5
long getA5 () = {
	0x200d					/* move.l a5, d0 */
};

#pragma parameter setD0(__D0)
void setD0 () = {
	0x4e71					/* nop */
};

/*
 * getA0
 * returns the current value of register A0
 */
#pragma parameter _D0 getA0()
long getA0 () = {
	0x2008					// move.l a0, d0
};

/*
 * swap bytes in a long
 */
#pragma parameter __D0 swapl(__A0)
unsigned long swapl (unsigned long target) = {
	0x2008,							// move.l a0, d0
	0xe058,							// ror.w d0, 8
	0x4840,							// swap d0
	0xe058							// ror.w d0, 8
};

#pragma parameter __D0 swapA4(__D0)
long swapA4(long);
long swapA4 () = {
	0xc18c					/* exg d0, a4 */
};
