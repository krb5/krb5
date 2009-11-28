/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* MDDRIVER.C - test driver for MD2, MD4 and MD5
 */

/* Copyright (C) 1990-2, RSA Data Security, Inc. Created 1990. All
   rights reserved.

   RSA Data Security, Inc. makes no representations concerning either
   the merchantability of this software or the suitability of this
   software for any particular purpose. It is provided "as is"
   without express or implied warranty of any kind.

   These notices must be retained in any copies of any part of this
   documentation and/or software.
*/

/* The following makes MD default to MD5 if it has not already been
   defined with C compiler flags.
*/
#ifndef MD
#define MD 5
#endif

#include "k5-int.h"

#if MD == 2
#include "md2.h"
#endif
#if MD == 4
#include "rsa-md4.h"
#endif
#if MD == 5
#include "rsa-md5.h"
#endif

/* Length of test block, number of test blocks.
 */
#define TEST_BLOCK_LEN 1000
#define TEST_BLOCK_COUNT 1000

static void MDString (char *);
static void MDTimeTrial (void);
static void MDTestSuite (void);
static void MDFile (char *);
static void MDFilter (void);
static void MDPrint (unsigned char [16]);

struct md_test_entry {
    char *string;
    unsigned char digest[16];
};

#if MD == 2
#define MD_CTX krb5_MD2_CTX
#define MDInit krb5_MD2Init
#define MDUpdate krb5_MD2Update
#define MDFinal krb5_MD2Final
#endif

#if MD == 4
#define MD_CTX krb5_MD4_CTX
#define MDInit krb5int_MD4Init
#define MDUpdate krb5int_MD4Update
#define MDFinal krb5int_MD4Final

#define HAVE_TEST_SUITE
/* Test suite from RFC 1320 */

struct md_test_entry md_test_suite[] = {
    { "",
      {0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31,
       0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0 }},
    { "a",
      {0xbd, 0xe5, 0x2c, 0xb3, 0x1d, 0xe3, 0x3e, 0x46,
       0x24, 0x5e, 0x05, 0xfb, 0xdb, 0xd6, 0xfb, 0x24 }},
    { "abc",
      {0xa4, 0x48, 0x01, 0x7a, 0xaf, 0x21, 0xd8, 0x52,
       0x5f, 0xc1, 0x0a, 0xe8, 0x7a, 0xa6, 0x72, 0x9d }},
    { "message digest",
      {0xd9, 0x13, 0x0a, 0x81, 0x64, 0x54, 0x9f, 0xe8,
       0x18, 0x87, 0x48, 0x06, 0xe1, 0xc7, 0x01, 0x4b }},
    { "abcdefghijklmnopqrstuvwxyz",
      {0xd7, 0x9e, 0x1c, 0x30, 0x8a, 0xa5, 0xbb, 0xcd,
       0xee, 0xa8, 0xed, 0x63, 0xdf, 0x41, 0x2d, 0xa9 }},
    { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
      {0x04, 0x3f, 0x85, 0x82, 0xf2, 0x41, 0xdb, 0x35,
       0x1c, 0xe6, 0x27, 0xe1, 0x53, 0xe7, 0xf0, 0xe4 }},
    { "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
      {0xe3, 0x3b, 0x4d, 0xdc, 0x9c, 0x38, 0xf2, 0x19,
       0x9c, 0x3e, 0x7b, 0x16, 0x4f, 0xcc, 0x05, 0x36 }},
    {0, {0}}
};

#endif

#if MD == 5
#define MD_CTX krb5_MD5_CTX
#define MDInit krb5int_MD5Init
#define MDUpdate krb5int_MD5Update
#define MDFinal krb5int_MD5Final

#define HAVE_TEST_SUITE
/* Test suite from RFC 1321 */

struct md_test_entry md_test_suite[] = {
    { "",
      {0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
       0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e }},
    { "a",
      {0x0c, 0xc1, 0x75, 0xb9, 0xc0, 0xf1, 0xb6, 0xa8,
       0x31, 0xc3, 0x99, 0xe2, 0x69, 0x77, 0x26, 0x61 }},
    { "abc",
      {0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
       0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72 }},
    { "message digest",
      {0xf9, 0x6b, 0x69, 0x7d, 0x7c, 0xb7, 0x93, 0x8d,
       0x52, 0x5a, 0x2f, 0x31, 0xaa, 0xf1, 0x61, 0xd0 }},
    { "abcdefghijklmnopqrstuvwxyz",
      {0xc3, 0xfc, 0xd3, 0xd7, 0x61, 0x92, 0xe4, 0x00,
       0x7d, 0xfb, 0x49, 0x6c, 0xca, 0x67, 0xe1, 0x3b }},
    { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
      {0xd1, 0x74, 0xab, 0x98, 0xd2, 0x77, 0xd9, 0xf5,
       0xa5, 0x61, 0x1c, 0x2c, 0x9f, 0x41, 0x9d, 0x9f }},
    { "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
      {0x57, 0xed, 0xf4, 0xa2, 0x2b, 0xe3, 0xc9, 0x55,
       0xac, 0x49, 0xda, 0x2e, 0x21, 0x07, 0xb6, 0x7a }},
    { 0, {0} }
};

#endif

/* Main driver.

   Arguments (may be any combination):
   -sstring - digests string
   -t       - runs time trial
   -x       - runs test script
   filename - digests file
   (none)   - digests standard input
*/
int main (argc, argv)
    int argc;
    char *argv[];
{
    int i;

    if (argc > 1)
        for (i = 1; i < argc; i++)
            if (argv[i][0] == '-' && argv[i][1] == 's')
                MDString (argv[i] + 2);
            else if (strcmp (argv[i], "-t") == 0)
                MDTimeTrial ();
            else if (strcmp (argv[i], "-x") == 0)
                MDTestSuite ();
            else
                MDFile (argv[i]);
    else
        MDFilter ();

    return (0);
}

/* Digests a string and prints the result.
 */
static void MDString (string)
    char *string;
{
    MD_CTX context;
    unsigned int len = strlen (string);

    MDInit (&context);
    MDUpdate (&context, (unsigned char *) string, len);
    MDFinal (&context);

    printf ("MD%d (\"%s\") = ", MD, string);
    MDPrint (context.digest);
    printf ("\n");
}

/* Measures the time to digest TEST_BLOCK_COUNT TEST_BLOCK_LEN-byte
   blocks.
*/
static void MDTimeTrial ()
{
    MD_CTX context;
    time_t endTime, startTime;
    unsigned char block[TEST_BLOCK_LEN];
    unsigned int i;

    printf("MD%d time trial. Digesting %d %d-byte blocks ...", MD,
           TEST_BLOCK_LEN, TEST_BLOCK_COUNT);

    /* Initialize block */
    for (i = 0; i < TEST_BLOCK_LEN; i++)
        block[i] = (unsigned char)(i & 0xff);

    /* Start timer */
    time (&startTime);

    /* Digest blocks */
    MDInit (&context);
    for (i = 0; i < TEST_BLOCK_COUNT; i++)
        MDUpdate (&context, block, TEST_BLOCK_LEN);
    MDFinal (&context);

    /* Stop timer */
    time (&endTime);

    printf (" done\n");
    printf ("Digest = ");
    MDPrint (context.digest);
    printf ("\nTime = %ld seconds\n", (long)(endTime-startTime));
    printf
        ("Speed = %ld bytes/second\n",
         (long)TEST_BLOCK_LEN * (long)TEST_BLOCK_COUNT/(endTime-startTime));
}

/* Digests a reference suite of strings and prints the results.
 */
static void MDTestSuite ()
{
#ifdef HAVE_TEST_SUITE
    MD_CTX context;
    struct md_test_entry *entry;
    int i, num_tests = 0, num_failed = 0;

    printf ("MD%d test suite:\n\n", MD);
    for (entry = md_test_suite; entry->string; entry++) {
        unsigned int len = strlen (entry->string);

        MDInit (&context);
        MDUpdate (&context, (unsigned char *) entry->string, len);
        MDFinal (&context);

        printf ("MD%d (\"%s\") = ", MD, entry->string);
        MDPrint (context.digest);
        printf ("\n");
        for (i=0; i < 16; i++) {
            if (context.digest[i] != entry->digest[i]) {
                printf("\tIncorrect MD%d digest!  Should have been:\n\t\t ",
                       MD);
                MDPrint(entry->digest);
                printf("\n");
                num_failed++;
            }
        }
        num_tests++;
    }
    if (num_failed) {
        printf("%d out of %d tests failed for MD%d!!!\n", num_failed,
               num_tests, MD);
        exit(1);
    } else {
        printf ("%d tests passed successfully for MD%d.\n", num_tests, MD);
        exit(0);
    }
#else

    printf ("MD%d test suite:\n", MD);
    MDString ("");
    MDString ("a");
    MDString ("abc");
    MDString ("message digest");
    MDString ("abcdefghijklmnopqrstuvwxyz");
    MDString
        ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    MDString
        ("12345678901234567890123456789012345678901234567890123456789012345678901234567890");
#endif
}

/* Digests a file and prints the result. */

static void MDFile (filename)
    char *filename;
{
    FILE *file;
    MD_CTX context;
    int len;
    unsigned char buffer[1024];

    if ((file = fopen (filename, "rb")) == NULL)
        printf ("%s can't be opened\n", filename);
    else {
        MDInit (&context);
        while ((len = fread (buffer, 1, 1024, file)) != 0)
            MDUpdate (&context, buffer, len);
        MDFinal (&context);

        fclose (file);

        printf ("MD%d (%s) = ", MD, filename);
        MDPrint (context.digest);
        printf ("\n");
    }
}

/* Digests the standard input and prints the result.
 */
static void MDFilter ()
{
    MD_CTX context;
    int len;
    unsigned char buffer[16];

    MDInit (&context);
    while ((len = fread (buffer, 1, 16, stdin)) != 0)
        MDUpdate (&context, buffer, len);
    MDFinal (&context);

    MDPrint (context.digest);
    printf ("\n");
}

/* Prints a message digest in hexadecimal.
 */
static void MDPrint (digest)
    unsigned char digest[16];
{
    unsigned int i;

    for (i = 0; i < 16; i++)
        printf ("%02x", digest[i]);
}
