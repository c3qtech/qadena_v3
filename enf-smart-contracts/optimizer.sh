#!/bin/zsh
#
# THIS FILE HAD NO SHEBANG, and the bare ":" that stood in for one is a no-op.  Without a shebang the
# kernel refuses the exec and the calling shell falls back to /bin/sh -- which on Ubuntu is dash, and
# dash has no ${var/pattern/replacement}.  Line 9 below then dies with "Bad substitution" and nothing
# is built.  It worked on macOS only because /bin/sh there is not dash.
#
# zsh, to match the rest of this repo's scripts.

U="cosmwasm"
V="0.16.0"

M=$(uname -m)
#M="x86_64" # Force Intel arch

A="linux/${M/x86_64/amd64}"
S=${M#x86_64}
S=${S:+-$S}

docker run --platform $A --rm -v "$(pwd)":/code \
  --mount type=volume,source="$(basename "$(pwd)")_cache",target=/target \
  --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
  $U/optimizer$S:$V
