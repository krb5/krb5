#include "utility.h"
#include "krb5.h"
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

char hexchar (const unsigned int digit);

asn1_error_code asn1_krb5_data_unparse(code, s)
     const krb5_data * code;
     char ** s;
{
  if(*s != NULL) free(*s);
  
  if(code==NULL){
    *s = (char*)calloc(strlen("<NULL>")+1, sizeof(char));
    if(*s == NULL) return ENOMEM;
    strcpy(*s,"<NULL>");
  }else if(code->data == NULL || ((int) code->length) <= 0){
    *s = (char*)calloc(strlen("<EMPTY>")+1, sizeof(char));
    if(*s==NULL) return ENOMEM;
    strcpy(*s,"<EMPTY>");
  }else{
    int i;

    *s = (char*)calloc((size_t) 3*(code->length), sizeof(char));
    if(*s == NULL) return ENOMEM;
    for(i = 0; i < code->length; i++){
      (*s)[3*i] = hexchar((unsigned char) (((code->data)[i]&0xF0)>>4));
      (*s)[3*i+1] = hexchar((unsigned char) ((code->data)[i]&0x0F));
      (*s)[3*i+2] = ' ';
    }
    (*s)[3*(code->length)-1] = '\0';
  }
  return 0;
}

char hexchar(digit)
     const unsigned int digit;
{
  if(digit<=9)
    return '0'+digit;
  else if(digit<=15)
    return 'A'+digit-10;
  else
    return 'X';
}

krb5_error_code krb5_data_parse(d, s)
     krb5_data * d;
     const char * s;
{
  /*if(d->data != NULL){
    free(d->data);
    d->length = 0;
  }*/
  d->data = (char*)calloc(strlen(s),sizeof(char));
  if(d->data == NULL) return ENOMEM;
  d->length = strlen(s);
  memcpy(d->data,s,strlen(s));
  return 0;
}

krb5_error_code krb5_data_hex_parse(krb5_data *d, const char *s)
{
    int lo;
    long v;
    const char *cp;
    char *dp;
    char buf[2];

    d->data = calloc((strlen(s) / 2 + 1), 1);
    if (d->data == NULL)
	return ENOMEM;
    d->length = 0;
    buf[1] = '\0';
    for (lo = 0, dp = d->data, cp = s; *cp; cp++) {
	if (*cp < 0)
	    return ASN1_PARSE_ERROR;
	else if (isspace((unsigned char) *cp))
	    continue;
	else if (isxdigit((unsigned char) *cp)) {
	    buf[0] = *cp;
	    v = strtol(buf, NULL, 16);
	} else
	    return ASN1_PARSE_ERROR;
	if (lo) {
	    *dp++ |= v;
	    lo = 0;
	} else {
	    *dp = v << 4;
	    lo = 1;
	}
    }

    d->length = dp - d->data;
    return 0;
}

#if 0
void asn1buf_print(buf)
     const asn1buf * buf;
{
  asn1buf bufcopy;
  char *s=NULL;
  int length;
  int i;
  
  bufcopy.base = bufcopy.next = buf->next;
  bufcopy.bound = buf->bound;
  length = asn1buf_len(&bufcopy);

  s = calloc(3*length, sizeof(char));
  if(s == NULL) return;
  for(i=0; i<length; i++){
    s[3*i] = hexchar(((bufcopy.base)[i]&0xF0)>>4);
    s[3*i+1] = hexchar((bufcopy.base)[i]&0x0F);
    s[3*i+2] = ' ';
  }
  s[3*length-1] = '\0';

  printf("%s\n",s);
  free(s);
}
#endif
