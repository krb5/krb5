/*
 *	$Source$
 *	$Author$
 *	$Id$
 */

/*
 * md4driver.c from RFC1186
 *
 * $Log$
 * Revision 5.1  1990/11/08 11:33:37  jtkohl
 * fix indentation to remove extra space from documentation file
 * use kerberos include files
 * add missing double quotes in printf statements
 * only use "rb" if this is ANSI C
 *
 * Revision 5.0  90/11/07  14:12:29  jtkohl
 * Initial code from RFC
 * 
 */

/*
** ********************************************************************
** md4driver.c -- sample routines to test                            **
** MD4 message digest algorithm.                                     **
** Updated: 2/16/90 by Ronald L. Rivest                              **
** (C) 1990 RSA Data Security, Inc.                                  **
** ********************************************************************
*/

#include <stdio.h>
#include <krb5/krb5.h>
#include <krb5/rsa-md4.h>

/* MDtimetrial()
** A time trial routine, to measure the speed of MD4.
** Measures speed for 1M blocks = 64M bytes.
*/
MDtimetrial()
{ unsigned int X[16];
  MDstruct MD;
  int i;
  double t;
  for (i=0;i<16;i++) X[i] = 0x01234567 + i;
  printf
  ("MD4 time trial. Processing 1 million 64-character blocks...\n");
  clock();
  MDbegin(&MD);
  for (i=0;i<1000000;i++) MDupdate(&MD,X,512);
  MDupdate(&MD,X,0);
  t = (double) clock(); /* in microseconds */
  MDprint(&MD); printf(" is digest of 64M byte test input.\n");
  printf("Seconds to process test input:   %g\n",t/1e6);
  printf("Characters processed per second: %ld.\n",(int)(64e12/t));
}

/* MDstring(s)
** Computes the message digest for string s.
** Prints out message digest, a space, the string (in quotes) and a
** carriage return.
*/
MDstring(s)
unsigned char *s;
{ unsigned int i, len = strlen(s);
  MDstruct MD;
  MDbegin(&MD);
  for (i=0;i+64<=len;i=i+64) MDupdate(&MD,s+i,512);
  MDupdate(&MD,s+i,(len-i)*8);
  MDprint(&MD);
  printf(" \"%s\"\n",s);
}

/* MDfile(filename)
** Computes the message digest for a specified file.
** Prints out message digest, a space, the file name, and a
** carriage return.
*/
MDfile(filename)
char *filename;
{ 
#ifdef __STDC__
  FILE *f = fopen(filename,"rb");
#else
  FILE *f = fopen(filename,"r");
#endif
  unsigned char X[64];
  MDstruct MD;
  int b;
  if (f == NULL)
     { printf("%s can't be opened.\n",filename); return; }
  MDbegin(&MD);
  while ((b=fread(X,1,64,f))!=0) MDupdate(&MD,X,b*8);

  MDupdate(&MD,X,0);
  MDprint(&MD);
  printf(" %s\n",filename);
  fclose(f);
}

/* MDfilter()
** Writes the message digest of the data from stdin onto stdout,
** followed by a carriage return.
*/
MDfilter()
{ unsigned char X[64];
  MDstruct MD;
  int b;
  MDbegin(&MD);
  while ((b=fread(X,1,64,stdin))!=0) MDupdate(&MD,X,b*8);
  MDupdate(&MD,X,0);
  MDprint(&MD);
  printf("\n");
}

/* MDtestsuite()
** Run a standard suite of test data.
*/
MDtestsuite()
{
  printf("MD4 test suite results:\n");
  MDstring("");
  MDstring("a");
  MDstring("abc");
  MDstring("message digest");
  MDstring("abcdefghijklmnopqrstuvwxyz");
  MDstring
  ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
  MDfile("foo"); /* Contents of file foo are "abc" */
}

main(argc,argv)
int argc;
char *argv[];
{ int i;
  /* For each command line argument in turn:
  ** filename          -- prints message digest and name of file
  ** -sstring          -- prints message digest and contents of string
  ** -t                -- prints time trial statistics for 64M bytes
  ** -x                -- execute a standard suite of test data
  ** (no args)         -- writes messages digest of stdin onto stdout
  */

  if (argc==1) MDfilter();
  else
    for (i=1;i<argc;i++)
      if (argv[i][0]=='-' && argv[i][1]=='s') MDstring(argv[i]+2);
      else if (strcmp(argv[i],"-t")==0)       MDtimetrial();
      else if (strcmp(argv[i],"-x")==0)       MDtestsuite();
      else                                    MDfile(argv[i]);
}

/*
** end of md4driver.c
*/
