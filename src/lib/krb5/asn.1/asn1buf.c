/* Coding Buffer Implementation */

/*
  Implementation

    Encoding mode

    The encoding buffer is filled from bottom (lowest address) to top
    (highest address).  This makes it easier to expand the buffer,
    since realloc preserves the existing portion of the buffer.

    Note: Since ASN.1 encoding must be done in reverse, this means
    that you can't simply memcpy out the buffer data, since it will be
    backwards.  You need to reverse-iterate through it, instead.

    ***This decision may have been a mistake.  In practice, the
    implementation will probably be tuned such that reallocation is
    rarely necessary.  Also, the realloc probably has recopy the
    buffer itself, so we don't really gain that much by avoiding an
    explicit copy of the buffer.  --Keep this in mind for future reference.


    Decoding mode

    The decoding buffer is in normal order and is created by wrapping
    an asn1buf around a krb5_data structure.
  */

/* Abstraction Function

   Programs should use just pointers to asn1buf's (e.g. asn1buf *mybuf).
   These pointers must always point to a valid, allocated asn1buf
   structure or be NULL.

   The contents of the asn1buf represent an octet string.  This string
   begins at base and continues to the octet immediately preceding next.
   If next == base or mybuf == NULL, then the asn1buf represents an empty
   octet string. */

/* Representation Invariant

   Pointers to asn1buf's must always point to a valid, allocated
   asn1buf structure or be NULL.

   base points to a valid, allocated octet array or is NULL
   next >= base
   next <= bound+2  (i.e. next should be able to step just past the bound,
                     but no further.  (The bound should move out in response
		     to being crossed by next.)) */

#define ASN1BUF_OMIT_INLINE_FUNCS
#include "asn1buf.h"
#undef ASN1BUF_OMIT_INLINE_FUNCS
#include <stdio.h>
#include "asn1_get.h"

asn1_error_code asn1buf_create(buf)
     asn1buf ** buf;
{
  *buf = (asn1buf*)malloc(sizeof(asn1buf));
  if (*buf == NULL) return ENOMEM;
  (*buf)->base = NULL;
  (*buf)->bound = NULL;
  (*buf)->next = NULL;
  return 0;
}

asn1_error_code asn1buf_wrap_data(buf, code)
     asn1buf * buf;
     const krb5_data * code;
{
  if(code == NULL || code->data == NULL) return ASN1_MISSING_FIELD;
  buf->next = buf->base = code->data;
  buf->bound = code->data + code->length - 1;
  return 0;
}

asn1_error_code asn1buf_imbed(subbuf, buf, length)
     asn1buf * subbuf;
     const asn1buf * buf;
     const int length;
{
  subbuf->base = subbuf->next = buf->next;
  if (length > 0 ) {
      subbuf->bound = subbuf->base + length - 1;
      if (subbuf->bound > buf->bound)
	  return ASN1_OVERRUN;
  } else /* constructed indefinite */
      subbuf->bound = buf->bound;
  return 0;
}

asn1_error_code asn1buf_sync(buf, subbuf, lasttag, length)
     asn1buf * buf;
     asn1buf * subbuf;
     const asn1_tagnum lasttag;
     const int length;
{
  asn1_error_code retval;

  if (length) {
    buf->next = subbuf->bound + 1;
  } else {
    /*
     * indefinite length:
     *
     * Note that asn1_get_tag() returns ASN1_TAGNUM_CEILING
     * for an EOC encoding.
     */
    if (lasttag != ASN1_TAGNUM_CEILING) {
      retval = asn1buf_skiptail(subbuf);
      if (retval) return retval;
    }
    buf->next = subbuf->next;
  }
  return 0;
}

asn1_error_code asn1buf_skiptail(buf)
     asn1buf *buf;
{
  asn1_error_code retval;
  asn1_class class;
  asn1_construction construction;
  asn1_tagnum tagnum;
  int taglen;
  int nestlevel;

  nestlevel = 1;
  while (nestlevel > 0) {
    retval = asn1_get_tag(buf, &class, &construction, &tagnum, &taglen);
    if (retval) return retval;
    if (construction == CONSTRUCTED && taglen == 0)
      nestlevel++;
    if (tagnum == ASN1_TAGNUM_CEILING)
      nestlevel--;
  }
  return 0;
}

asn1_error_code asn1buf_destroy(buf)
     asn1buf ** buf;
{
  if (*buf != NULL) {
    if ((*buf)->base != NULL) free((*buf)->base);
    free(*buf);
    *buf = NULL;
  }
  return 0;
}

#ifdef asn1buf_insert_octet
#undef asn1buf_insert_octet
#endif
asn1_error_code asn1buf_insert_octet(buf, o)
     asn1buf * buf;
     const int o;
{
  asn1_error_code retval;

  retval = asn1buf_ensure_space(buf,1);
  if(retval) return retval;
  *(buf->next) = (char)o;
  (buf->next)++;
  return 0;
}

asn1_error_code asn1buf_insert_octetstring(buf, len, s)
     asn1buf * buf;
     const int len;
     const krb5_octet * s;
{
  asn1_error_code retval;
  int length;

  retval = asn1buf_ensure_space(buf,len);
  if(retval) return retval;
  for(length=1; length<=len; length++,(buf->next)++)
    *(buf->next) = (char)(s[len-length]);
  return 0;
}

asn1_error_code asn1buf_insert_charstring(buf, len, s)
     asn1buf * buf;
     const int len;
     const char * s;
{
  asn1_error_code retval;
  int length;

  retval = asn1buf_ensure_space(buf,len);
  if(retval) return retval;
  for(length=1; length<=len; length++,(buf->next)++)
    *(buf->next) = (char)(s[len-length]);
  return 0;
}

#undef asn1buf_remove_octet
asn1_error_code asn1buf_remove_octet(buf, o)
     asn1buf * buf;
     asn1_octet * o;
{
  if(buf->next > buf->bound) return ASN1_OVERRUN;
  *o = (asn1_octet)(*((buf->next)++));
  return 0;
}

asn1_error_code asn1buf_remove_octetstring(buf, len, s)
     asn1buf * buf;
     const int len;
     asn1_octet ** s;
{
  int i;

  if(buf->next + len - 1 > buf->bound) return ASN1_OVERRUN;
  if (len == 0) {
      *s = 0;
      return 0;
  }
  *s = (asn1_octet*)malloc(len*sizeof(asn1_octet));
  if (*s == NULL)
      return ENOMEM;
  for(i=0; i<len; i++)
    (*s)[i] = (asn1_octet)(buf->next)[i];
  buf->next += len;
  return 0;
}

asn1_error_code asn1buf_remove_charstring(buf, len, s)
     asn1buf * buf;
     const int len;
     char ** s;
{
  int i;

  if (buf->next + len - 1 > buf->bound) return ASN1_OVERRUN;
  if (len == 0) {
      *s = 0;
      return 0;
  }
  *s = (char*)malloc(len*sizeof(char));
  if (*s == NULL) return ENOMEM;
  for(i=0; i<len; i++)
    (*s)[i] = (char)(buf->next)[i];
  buf->next += len;
  return 0;
}

int asn1buf_remains(buf)
    asn1buf *buf;
{
  int remain;
  if(buf == NULL || buf->base == NULL) return 0;
  remain = buf->bound - buf->next +1;
  if (remain <= 0) return remain;
  /*
   * Two 0 octets means the end of an indefinite encoding.
   * 
   * XXX  Do we need to test to make sure we'er actually doing an
   * indefinite encoding here?
   */
  if ( !*(buf->next) && !*(buf->next + 1)) {
   /* buf->bound = buf->next + 1;  */
      buf->next += 2;
      return 0;
  }
  else return remain;
}

asn1_error_code asn12krb5_buf(buf, code)
     const asn1buf * buf;
     krb5_data ** code;
{
  int i;
  *code = (krb5_data*)calloc(1,sizeof(krb5_data));
  if(*code == NULL) return ENOMEM;
  (*code)->magic = KV5M_DATA;
  (*code)->data = NULL;
  (*code)->length = 0;
  (*code)->length = asn1buf_len(buf);
  (*code)->data = (char*)malloc((((*code)->length)+1)*sizeof(char));
  if ((*code)->data == NULL) {
    free(*code);
    return ENOMEM;
  }
  for(i=0; i < (*code)->length; i++)
    ((*code)->data)[i] = (buf->base)[((*code)->length)-i-1];
  ((*code)->data)[(*code)->length] = '\0';
  return 0;
}



/* These parse and unparse procedures should be moved out. They're
   useful only for debugging and superfluous in the production version. */

asn1_error_code asn1buf_unparse(buf, s)
     const asn1buf * buf;
     char ** s;
{
  if(*s != NULL) free(*s);
  if(buf == NULL){
    *s = malloc(sizeof("<NULL>"));
    if(*s == NULL) return ENOMEM;
    strcpy(*s,"<NULL>");
  }else if(buf->base == NULL){
    *s = malloc(sizeof("<EMPTY>"));
    if(*s == NULL) return ENOMEM;
    strcpy(*s,"<EMPTY>");
  }else{
    int length = asn1buf_len(buf);
    int i;

    *s = calloc(length+1, sizeof(char));
    if(*s == NULL) return ENOMEM;
    (*s)[length] = '\0';
    for(i=0; i<length; i++) ;
/*      OLDDECLARG( (*s)[i] = , (buf->base)[length-i-1]) */
  }
  return 0;
}

asn1_error_code asn1buf_hex_unparse(buf, s)
     const asn1buf * buf;
     char ** s;
{
#define hexchar(d) ((d)<=9 ? ('0'+(d)) :\
		    ((d)<=15 ? ('A'+(d)-10) :\
		    'X'))

  if(*s != NULL) free(*s);

  if(buf == NULL){
    *s = malloc(sizeof("<NULL>"));
    if(*s == NULL) return ENOMEM;
    strcpy(*s,"<NULL>");
  }else if(buf->base == NULL){
    *s = malloc(sizeof("<EMPTY>"));
    if(*s == NULL) return ENOMEM;
    strcpy(*s,"<EMPTY>");
  }else{
    int length = asn1buf_len(buf);
    int i;

    *s = malloc(3*length);
    if(*s == NULL) return ENOMEM;
    for(i = length-1; i >= 0; i--){
      (*s)[3*(length-i-1)] = hexchar(((buf->base)[i]&0xF0)>>4);
      (*s)[3*(length-i-1)+1] = hexchar((buf->base)[i]&0x0F);
      (*s)[3*(length-i-1)+2] = ' ';
    }
    (*s)[3*length-1] = '\0';
  }
  return 0;
}

/****************************************************************/
/* Private Procedures */

#undef asn1buf_size
int asn1buf_size(buf)
     const asn1buf * buf;
{
  if(buf == NULL || buf->base == NULL) return 0;
  return buf->bound - buf->base + 1;
}

#undef asn1buf_free
int asn1buf_free(buf)
     const asn1buf * buf;
{
  if(buf == NULL || buf->base == NULL) return 0;
  else return buf->bound - buf->next + 1;
}

#undef asn1buf_ensure_space
asn1_error_code asn1buf_ensure_space(buf, amount)
     asn1buf * buf;
     const int amount;
{
  int free = asn1buf_free(buf);
  if(free < amount){
    asn1_error_code retval = asn1buf_expand(buf, amount-free);
    if(retval) return retval;
  }
  return 0;
}

asn1_error_code asn1buf_expand(buf, inc)
     asn1buf * buf;
     int inc;
{
#define STANDARD_INCREMENT 200
  int next_offset = buf->next - buf->base;
  int bound_offset;
  if(buf->base == NULL) bound_offset = -1;
  else bound_offset = buf->bound - buf->base;

  if (inc < STANDARD_INCREMENT)
    inc = STANDARD_INCREMENT;

  if (buf->base == NULL)
    buf->base = malloc((asn1buf_size(buf)+inc) * sizeof(asn1_octet));
  else
    buf->base = realloc(buf->base,
			(asn1buf_size(buf)+inc) * sizeof(asn1_octet));
  if(buf->base == NULL) return ENOMEM;
  buf->bound = (buf->base) + bound_offset + inc;
  buf->next = (buf->base) + next_offset;
  return 0;
}

#undef asn1buf_len
int asn1buf_len(buf)
     const asn1buf * buf;
{
  return buf->next - buf->base;
}
