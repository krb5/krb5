/*
 * src/lib/krb5/asn.1/asn1_get.c
 * 
 * Copyright 1994 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#include "asn1_get.h"

asn1_error_code
asn1_get_tag_indef(buf, class, construction, tagnum, retlen, indef)
     asn1buf * buf;
     asn1_class * class;
     asn1_construction * construction;
     asn1_tagnum * tagnum;
     int * retlen;
     int * indef;
{
  asn1_error_code retval;
  
  if (buf == NULL || buf->base == NULL ||
      buf->bound - buf->next + 1 <= 0) {
      *tagnum = ASN1_TAGNUM_CEILING;
      return 0;
  }
  /* Allow for the indefinite encoding */
  if ( !*(buf->next) && !*(buf->next + 1)) {
    buf->next += 2;
    *tagnum = ASN1_TAGNUM_CEILING;
    return 0;
  }
  retval = asn1_get_id(buf,class,construction,tagnum);
  if(retval) return retval;
  retval = asn1_get_length(buf,retlen,indef);
  if(retval) return retval;
  return 0;
}

asn1_error_code
asn1_get_tag(buf, class, construction, tagnum, retlen)
     asn1buf *buf;
     asn1_class *class;
     asn1_construction *construction;
     asn1_tagnum *tagnum;
     int *retlen;
{
  asn1_error_code retval;
  int indef;

  return asn1_get_tag_indef(buf, class, construction, tagnum, retlen, &indef);
}

asn1_error_code asn1_get_sequence(buf, retlen, indef)
     asn1buf * buf;
     int * retlen;
     int * indef;
{
  asn1_error_code retval;
  asn1_class class;
  asn1_construction construction;
  asn1_tagnum tagnum;

  retval = asn1_get_tag_indef(buf,&class,&construction,&tagnum,retlen,indef);
  if(retval) return retval;
  if(retval) return (krb5_error_code)retval;
  if(class != UNIVERSAL || construction != CONSTRUCTED ||
     tagnum != ASN1_SEQUENCE) return ASN1_BAD_ID;
  return 0;
}

/****************************************************************/
/* Private Procedures */

asn1_error_code asn1_get_id(buf, class, construction, tagnum)
     asn1buf * buf;
     asn1_class * class;
     asn1_construction * construction;
     asn1_tagnum * tagnum;
{
  asn1_error_code retval;
  asn1_tagnum tn=0;
  asn1_octet o;

#define ASN1_CLASS_MASK 0xC0
#define ASN1_CONSTRUCTION_MASK 0x20
#define ASN1_TAG_NUMBER_MASK 0x1F

  retval = asn1buf_remove_octet(buf,&o);
  if(retval) return retval;

  if(class != NULL)
    *class = (asn1_class)(o&ASN1_CLASS_MASK);
  if(construction != NULL)
    *construction = (asn1_construction)(o&ASN1_CONSTRUCTION_MASK);
  if((o&ASN1_TAG_NUMBER_MASK) != ASN1_TAG_NUMBER_MASK){
    /* low-tag-number form */
    if(tagnum != NULL) *tagnum = (asn1_tagnum)(o&ASN1_TAG_NUMBER_MASK);
  }else{
    /* high-tag-number form */
    do{
      retval = asn1buf_remove_octet(buf,&o);
      if(retval) return retval;
      tn = (tn<<7) + (asn1_tagnum)(o&0x7F);
    }while(tn&0x80);
    if(tagnum != NULL) *tagnum = tn;
  }
  return 0;
}

asn1_error_code asn1_get_length(buf, retlen, indef)
     asn1buf * buf;
     int * retlen;
     int * indef;
{
  asn1_error_code retval;
  asn1_octet o;

  if (indef != NULL)
    *indef = 0;
  retval = asn1buf_remove_octet(buf,&o);
  if(retval) return retval;
  if((o&0x80) == 0){
    if(retlen != NULL) *retlen = (int)(o&0x7F);
  }else{
    int num;
    int len=0;
    
    for(num = (int)(o&0x7F); num>0; num--){
      retval = asn1buf_remove_octet(buf,&o);
      if(retval) return retval;
      len = (len<<8) + (int)o;
    }
    if (indef != NULL && !len)
      *indef = 1;
    if(retlen != NULL) *retlen = len;
  }
  return 0;
}
