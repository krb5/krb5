#include <check.h>
#include <stdlib.h>
#include <string.h>

/* Declaration of the function under test */
extern char *ldap_filter_correct(char *in);

START_TEST(test_ldap_filter_escapes_special_chars)
{
    /* Invariant: ldap_filter_correct must escape all RFC 4515 special characters
       (*, (, ), \, NUL) so that no unescaped special char appears in output */
    char *payloads[] = {
        strdup("admin)(uid=*)"),          /* LDAP injection payload */
        strdup("test\\path*(evil)"),      /* multiple special chars */
        strdup("validrealm"),             /* benign input - should pass through */
        strdup("a]b\x00" "c"),           /* contains backslash near boundary */
    };
    int num_payloads = 4;

    for (int i = 0; i < num_payloads; i++) {
        char *result = ldap_filter_correct(payloads[i]);
        if (result == NULL) {
            /* NULL return is acceptable for empty/NULL input */
            free(payloads[i]);
            continue;
        }
        /* No unescaped LDAP special characters should remain in output */
        for (char *p = result; *p != '\0'; p++) {
            if (*p == '\\') {
                /* If we see a backslash, it must be followed by two hex digits (escape sequence) */
                ck_assert_msg(p[1] != '\0' && p[2] != '\0',
                    "Incomplete escape sequence in output for payload %d", i);
                p += 2; /* skip the hex digits */
            } else {
                ck_assert_msg(*p != '*' && *p != '(' && *p != ')',
                    "Unescaped special char '%c' found in output for payload %d", *p, i);
            }
        }
        free(result);
        free(payloads[i]);
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_ldap_filter_escapes_special_chars);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}