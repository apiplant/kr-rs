#!/bin/sh
# cc-style linker shim: translates gcc-driver arguments to rust-lld (ld.lld
# flavor) for the libc-free static aarch64 build (no cross gcc needed).
LLD=$(ls "$(rustc --print sysroot)"/lib/rustlib/*/bin/rust-lld | head -1)
n=$#
while [ "$n" -gt 0 ]; do
  a=$1; shift; n=$((n - 1))
  case "$a" in
    -nostartfiles|-nostdlib|-static|-no-pie|-pie|-fuse-ld=*|-m64) ;;
    -Wl,*) IFS=,; set -- "$@" ${a#-Wl,}; unset IFS ;;
    *) set -- "$@" "$a" ;;
  esac
done
# -Wl splitting appended extra words to the end; ordering is irrelevant for options.
exec "$LLD" -flavor gnu -static "$@"
