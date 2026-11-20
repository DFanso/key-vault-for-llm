#!/bin/sh
# The linker for kv's macOS release builds, set by .github/build-setup.yml.
#
# It links with the system cc, as cargo would, and then signs the kv
# executable again, ad hoc, with the hardened runtime: macOS then ignores
# DYLD_* variables for it (so no library can be injected with
# DYLD_INSERT_LIBRARIES) and refuses to let a debugger attach. It needs no
# entitlements. The build turns off rustc's stripping (CARGO_PROFILE_DIST_STRIP
# =none), which on macOS rewrites the binary after the link and would undo the
# signature; this script strips debug symbols itself, as rustc would, before it
# signs. Build scripts and proc macros are linked as usual.
set -eu

cc "$@"

# The output is the argument after -o, on the command line or in an
# @response file that rustc uses when the command line is too long.
out=
prev=
for arg in "$@"; do
    case "$arg" in
        @*)
            file=${arg#@}
            while IFS= read -r line || [ -n "$line" ]; do
                [ "$prev" = "-o" ] && out=$line
                prev=$line
            done < "$file"
            ;;
        *)
            [ "$prev" = "-o" ] && out=$arg
            prev=$arg
            ;;
    esac
done

case "$(basename "$out")" in
    kv | kv-*) ;;
    *) exit 0 ;;
esac

/usr/bin/strip -S "$out"
/usr/bin/codesign --force --options runtime --sign - "$out"
/usr/bin/codesign --verify --strict "$out"
flags=$(/usr/bin/codesign --display --verbose=2 "$out" 2>&1 |
    sed -n 's/^CodeDirectory .*flags=0x[0-9a-f]*(\([^)]*\)).*/\1/p')
case ",$flags," in
    *,runtime,*) echo "signed $out ad hoc with the hardened runtime ($flags)" >&2 ;;
    *)
        echo "error: $out is not signed with the hardened runtime (flags: $flags)" >&2
        exit 1
        ;;
esac
