/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Cryptosystem configurations
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_cryptoconf_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/config.h>
#include <krb5/osconf.h>
#include <krb5/krb5.h>

#if defined(PROVIDE_DES_CBC_CRC) || defined(PROVIDE_LUCIFER_CRC) || defined(PROVIDE_CRC32)
#include <krb5/crc-32.h>
#define CRC32_CKENTRY &crc32_cksumtable_entry
#else
#define CRC32_CKENTRY 0
#endif

#ifdef PROVIDE_SNEFRU
#define XEROX_CKENTRY &snefru_cksumtable_entry
#else
#define XEROX_CKENTRY 0
#endif

#ifdef PROVIDE_DES_CBC_CKSUM
#include <krb5/mit-des.h>
#define DES_CBC_CKENTRY &mit_des_cbc_cksumtable_entry
#else
#define DES_CBC_CKENTRY 0
#endif

#ifdef PROVIDE_DES_CBC_CRC
#include <krb5/mit-des.h>
static krb5_cs_table_entry mit_des_cbc_crc_csentry = {
    &mit_des_cryptosystem_entry, 0 };
#define DES_CBC_CRC_CSENTRY &mit_des_cbc_crc_csentry
#else
#define DES_CBC_CRC_CSENTRY 0
#endif

#ifdef PROVIDE_LUCIFER_CRC
static krb5_cs_table_entry lucifer_crc_csentry = {
    &lucifer_cryptosystem_entry, 0 };
#define LUCIFER_CRC_CSENTRY &lucifer_crc_csentry
#else
#define LUCIFER_CRC_CSENTRY 0
#endif

krb5_cs_table_entry *krb5_csarray[] = {
    0,
    DES_CBC_CRC_CSENTRY,
    LUCIFER_CRC_CSENTRY,
};

int krb5_max_cryptosystem = sizeof(krb5_csarray)/sizeof(krb5_csarray[0]) - 1;

krb5_cs_table_entry *krb5_keytype_array[] = {
    0,
    DES_CBC_CRC_CSENTRY,
    LUCIFER_CRC_CSENTRY,
};

int krb5_max_keytype = sizeof(krb5_keytype_array)/sizeof(krb5_keytype_array[0]) - 1;

krb5_checksum_entry *krb5_cksumarray[] = {
    0,
    CRC32_CKENTRY,
    XEROX_CKENTRY,
    DES_CBC_CKENTRY,
};

int krb5_max_cksum = sizeof(krb5_cksumarray)/sizeof(krb5_cksumarray[0]);
