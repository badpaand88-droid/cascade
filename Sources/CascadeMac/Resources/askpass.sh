#!/bin/sh
# Secret exists only in the environment of this short-lived SSH process.
case "$1" in
  *assword*|*assphrase*) printf '%s\n' "$CASCADE_SSH_SECRET" ;;
  *) exit 1 ;;
esac
