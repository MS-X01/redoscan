#!/usr/bin/env bash
# Hardened version of examples/vulnerable/backup.sh.

validate() {
    # Single unbounded group, no nesting -- nothing ambiguous to backtrack on.
    if [[ $1 =~ ^a+$ ]]; then
        echo "matched"
    fi
}

run_backup() {
    # No eval, no shell re-parsing: the path is passed as a single argument.
    tar -czf backup.tar.gz -- "$USER_PATH"
}

hash_file() {
    # Password hashing belongs in the application layer (bcrypt/argon2), not
    # a shell script; if a shell check is genuinely needed, use sha256sum at
    # minimum and compare against a salted, stored value.
    sha256sum "$password_file"
}

validate "$1"
run_backup
hash_file
