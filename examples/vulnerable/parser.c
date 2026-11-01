/* Intentionally vulnerable C code for demo and CI purposes.
 * See examples/safe/parser.c for the corrected version. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <regex.h>
#include <openssl/md5.h>

void read_line(void) {
    char buf[64];
    /* CWE-242: gets() has no bounds checking at all */
    gets(buf);
}

void copy_name(const char *src) {
    char dest[32];
    /* CWE-120: strcpy has no length check against dest's size */
    strcpy(dest, src);
}

void run(const char *user_dir) {
    char cmd[256];
    /* CWE-120: sprintf with no bound on the destination size */
    sprintf(cmd, "rm -rf %s", user_dir);
    /* CWE-78: system() with a built, non-literal command string */
    system(cmd);
}

void hash_password(const unsigned char *password, size_t len, unsigned char *out) {
    /* CWE-327: MD5 is not a password hash */
    MD5(password, len, out);
}

int new_token(void) {
    /* CWE-330: rand() is not a CSPRNG */
    return rand();  /* session token */
}

int validate(const char *s) {
    regex_t re;
    /* evil nested quantifier -- ReDoS if ever matched against long input */
    regcomp(&re, "^(a+)+$", REG_EXTENDED);
    return regexec(&re, s, 0, NULL, 0);
}
