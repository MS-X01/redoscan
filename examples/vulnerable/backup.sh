#!/usr/bin/env bash
# Intentionally vulnerable Bash script for demo and CI purposes.
# See examples/safe/backup.sh for the corrected version.

validate() {
    # CWE-1333 (ReDoS risk if this pattern were ever more complex); shown
    # here mainly so redoscan's regex extraction has something to find in
    # a shell script too.
    if [[ $1 =~ ^(a+)+$ ]]; then
        echo "matched"
    fi
}

run_backup() {
    # CWE-78: eval on an expanded, attacker-influenced variable
    eval "tar -czf backup.tar.gz $USER_PATH"
}

hash_file() {
    # CWE-327: MD5 is not appropriate for a password/secret check
    md5sum "$password"
}

validate "$1"
run_backup
hash_file
