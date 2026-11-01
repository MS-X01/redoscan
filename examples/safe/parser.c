/* Hardened version of examples/vulnerable/parser.c. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <regex.h>
#include <sodium.h>

void read_line(void) {
    char buf[64];
    /* fgets takes an explicit bound; it can never overrun buf. */
    if (fgets(buf, sizeof(buf), stdin) == NULL) {
        return;
    }
}

void copy_name(const char *src) {
    char dest[32];
    /* snprintf truncates instead of overrunning the buffer. */
    snprintf(dest, sizeof(dest), "%s", src);
}

void run(const char *user_dir) {
    /* No shell involved: execv with a fixed program and argument array. */
    char *argv[] = {"/bin/rm", "-rf", "--", (char *)user_dir, NULL};
    execv("/bin/rm", argv);
}

void hash_password(const char *password, char *out, size_t out_len) {
    /* libsodium's crypto_pwhash is a deliberately slow, salted KDF. */
    crypto_pwhash_str(out, password, strlen(password),
                       crypto_pwhash_OPSLIMIT_INTERACTIVE,
                       crypto_pwhash_MEMLIMIT_INTERACTIVE);
}

int new_token(void) {
    /* randombytes_random() is seeded from the OS CSPRNG. */
    return randombytes_random();
}

int validate(const char *s) {
    regex_t re;
    /* Single unbounded group, no nesting -- nothing ambiguous. */
    regcomp(&re, "^a+$", REG_EXTENDED);
    return regexec(&re, s, 0, NULL, 0);
}
