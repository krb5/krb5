#include "krb5.h"
#include "utility.h"
#include <stdlib.h>
#include <stdio.h>

char hexchar PROTOTYPE((const unsigned int digit));

asn1_error_code asn1_krb5_data_unparse(code, s)
     const krb5_data * code;
     char ** s;
{
  if(*s != NULL) free(*s);
  
  if(code==NULL){
    *s = (char*)calloc(strlen("<NULL>")+1, sizeof(char));
    if(*s == NULL) return ENOMEM;
    strcpy(*s,"<NULL>");
  }else if(code->data == NULL || code->length <= 0){
    *s = (char*)calloc(strlen("<EMPTY>")+1, sizeof(char));
    if(*s==NULL) return ENOMEM;
    strcpy(*s,"<EMPTY>");
  }else{
    int i;

    *s = (char*)calloc(3*(code->length), sizeof(char));
    if(*s == NULL) return ENOMEM;
    for(i = 0; i < code->length; i++){
      (*s)[3*i] = hexchar(((code->data)[i]&0xF0)>>4);
      (*s)[3*i+1] = hexchar((code->data)[i]&0x0F);
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

krb5_error_code krb5_data_hex_parse(d, s)
     krb5_data * d;
     const char * s;
{
  int i, digit;
  char *copy; 
  char *pos;

    /* 
     * Do a strdup() and use that, because some systems can't handle non
     * writeable strings being passed to sscanf() --proven.
     */
    copy = strdup(s);
  d->data = (char*)calloc((strlen(copy)+1)/3,sizeof(char));
  if(d->data == NULL) return ENOMEM;
  d->length = (strlen(copy)+1)/3;
  for(i=0,pos=(char*)copy; i<d->length; i++,pos+=3){
    if(!sscanf(pos,"%x",&digit)) {
#ifdef KRB5_USE_ISODE
	    return EINVAL;
#else
	    return ASN1_PARSE_ERROR;
#endif
    }
    d->data[i] = (char)digit;
  }
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
