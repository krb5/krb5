#include<stdio.h>
#include<kconfig.h>
#include<strsafe.h>

struct string_pair {
  wchar_t * ms;
  wchar_t * csv;
};

struct string_pair strings[] = {
  {L"foo\0bar\0baz,quux\0ab\"cd\0", L"foo,bar,\"baz,quux\",\"ab\"\"cd\""},
  {L"a\0b\0c\0d\0e\0", L"a,b,c,d,e"},
  {L"1\0", L"1"},
  {L"\0", L""},
  {L"b\0a\0", L"b,a"},
  {L"c\0a\0b\0", L"c,a,b"},
  {L"c\0a\0B\0", L"c,a,B"},
  {L"sdf\0Bar\0Foo\0BBB\0", L"sdf,Bar,Foo,BBB"}
};

int n_strings = ARRAYLENGTH(strings);

void print_ms(wchar_t * ms) {
  wchar_t * s;
  size_t cch;

  s = ms;
  while(*s) {
    printf("%S\\0", s);
    StringCchLength(s, 512, &cch);
    s += cch + 1;
  }
}

int ms_to_csv_test(void) {
  wchar_t wbuf[512];
  int i;
  khm_int32 code = 0;
  size_t cbbuf;
  size_t cbr;
  size_t cbnull;

  printf("khc_multi_string_to_csv() test:\n");

  for(i=0; i<n_strings; i++) {
    cbbuf = sizeof(wbuf);
    printf("Multi string:[");
    print_ms(strings[i].ms);
    printf("]->");
    code = khc_multi_string_to_csv(NULL, &cbnull, strings[i].ms);
    code = khc_multi_string_to_csv(wbuf, &cbbuf, strings[i].ms);
    if(code) {
      printf(" returned %d\n", code);
      return code;
    }
    printf("CSV[%S]", wbuf);
    if(wcscmp(wbuf, strings[i].csv)) {
      printf(" MISMATCH!");
      return 1;
    }

    StringCbLength(wbuf, sizeof(wbuf), &cbr);
    cbr+= sizeof(wchar_t);

    if(cbr != cbbuf) {
      printf(" Length mismatch");
      return 1;
    }

    if(cbnull != cbr) {
      printf(" NULL length mismatch");
      return 1;
    }

    printf("\n");
  }

  return code;
}

int csv_to_ms_test(void) {
  wchar_t wbuf[512];
  int i;
  khm_int32 code = 0;
  size_t cbbuf;
  size_t cbr;
  size_t cbnull;

  printf("khc_csv_to_multi_string() test:\n");

  for(i=0; i<n_strings; i++) {
    cbbuf = sizeof(wbuf);
    printf("CSV:[%S]->", strings[i].csv);
    code = khc_csv_to_multi_string(NULL, &cbnull, strings[i].csv);
    code = khc_csv_to_multi_string(wbuf, &cbbuf, strings[i].csv);
    if(code) {
      printf(" returned %d\n", code);
      return code;
    }
    printf("MS[");
    print_ms(wbuf);
    printf("]");

    if(cbnull != cbbuf) {
      printf(" NULL length mismatch");
      return 1;
    }

    printf("\n");

    printf("  Byte length:%d\n", cbbuf);
  }

  return code;
}

int ms_append_test(void)
{
  wchar_t wbuf[512];
  size_t cbbuf;
  khm_int32 code;
  int i;

  printf("khc_multi_string_append() test:\n");

  for(i=0; i<n_strings; i++) {
    cbbuf = sizeof(wbuf);
    khc_csv_to_multi_string(wbuf, &cbbuf, strings[i].csv);

    printf("MS[");
    print_ms(wbuf);
    printf("] + [foo]=[");
  
    cbbuf = sizeof(wbuf);
    code = khc_multi_string_append(wbuf, &cbbuf, L"foo");

    if(code) {
      printf(" returned %d\n", code);
      return code;
    }

    print_ms(wbuf);
    printf("]\n");

    printf("  byte length: %d\n", cbbuf);
  }
  return code;
}

int ms_delete_test(void)
{
  int code = 0;
  wchar_t wbuf[512];
  int i;
  size_t cbs;

  printf("khc_multi_string_delete() test:\n");
  for(i=0; i<n_strings; i++) {
    cbs = sizeof(wbuf);
    khc_csv_to_multi_string(wbuf, &cbs, strings[i].csv);

    printf("MS[");
    print_ms(wbuf);
    printf("] - [b]=[");

    printf("cs:");
    code = khc_multi_string_delete(wbuf, L"b", KHC_CASE_SENSITIVE);
    if(code) {
      printf("ci:");
      code = khc_multi_string_delete(wbuf, L"b", 0);
    }
    if(code) {
      printf("pcs:");
      code = khc_multi_string_delete(wbuf, L"b", KHC_CASE_SENSITIVE | KHC_PREFIX);
    }
    if(code) {
      printf("pci:");
      code = khc_multi_string_delete(wbuf, L"b", KHC_PREFIX);
    }

    if(!code)
      print_ms(wbuf);
    else
      printf(" returned %d\n", code);

    printf("]\n");
  }

  return code;
}

int main(int argc, char ** argv) {

  if(ms_to_csv_test())
    return 1;

  if(csv_to_ms_test())
    return 1;

  if(ms_append_test())
    return 1;

  if(ms_delete_test())
    return 1;

  return 0;
}
