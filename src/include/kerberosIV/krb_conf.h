/*
 *	$Source$
 *	$Header$
 *
 *	This file contains configuration information for the Kerberos
 *	library which is machine specific; currently, this file contains
 *	configuration information for the vax, the "ibm032" (RT),
 *      and the "PC8086" (IBM PC).
 *
 *      Note:  cross-compiled targets must appear BEFORE their
 *      corresponding cross-compiler host.  Otherwise, both will
 *      be defined when running the native compiler on the programs that
 *      construct cross-compiled sources.
 */

#ifndef KRB_CONF_DEFS
#define KRB_CONF_DEFS

/* Byte ordering */
extern int	krbONE;
#define		HOST_BYTE_ORDER	(* (char *) &krbONE)
#define		MSB_FIRST		0	/*  68000, IBM RT/PC */
#define		LSB_FIRST		1	/*  Vax, PC8086 */

#ifdef PC8086
#define IBMPC
#define BITS16
/*#define BIG*/
#define CROSSMSDOS
#define LSBFIRST

#else

#ifdef vax
#define VAX
#define VAXASM
#define BITS32
#define BIG
#define BSDUNIX
#define LSBFIRST

#else

#ifdef ibm032
#define IBMWS
#define IBMWSASM
#define BITS32
#define BIG
#define BSDUNIX
#define MSBFIRST
#define MUSTALIGN

#else

Please put a description of your machine here.

#endif ibm032
#endif vax
#endif pc8086

#endif KRB_CONF_DEFS
