#!/bin/zsh
#
# Is this machine's protobuf generator the one this project pins?
#
# WHAT ACTUALLY DECIDES THE OUTPUT, established by experiment after two wrong answers:
#
#   NOT the PATH plugin.  buf.gen.gogo.yaml names `gocosmos`, but hiding that binary entirely and
#   running `ignite generate proto-go` still SUCCEEDS -- ignite supplies its own.
#   NOT the ignite binary version alone.  Aligning M1 to the Mac's module v29.7.0 left it still
#   rewriting nine .pb.go files.
#   THE CACHE.  ignite keeps its generation tooling under ~/.ignite (93 MB on M1), and swapping the
#   binary does not touch it.  Clearing it made M1 regenerate byte-identical to the committed tree.
#
# So the version checks below are hygiene -- they catch a machine nobody provisioned, and `@latest`
# behind an existence test was a real defect -- but the STALENESS check at the end is the one that
# catches the failure that actually happened.
#
# WHAT IT COSTS, and why it is worth a preflight rather than a comment: gogoproto v1.4.12 emits an
# extra `var X_serviceDesc = _X_serviceDesc` alias per service file that v1.7.x does not.  A machine
# with the old plugin rewrites nine .pb.go files on every init, the tree goes dirty, and
# package_release.sh correctly refuses artifacts that "correspond to no commit" -- so
# 1st_node_bringup.sh fails at PACKAGING, several minutes and one full build after the actual
# fault, with an error that names neither the plugin nor the version.  That happened on every run
# on 2026-08-18 (Mac had gogoproto v1.7.0, M1 v1.4.12, go.mod asks for v1.7.2).
#
# THE OBVIOUS CHECK IS THE WRONG ONE.  Both machines reported the same `Ignite CLI version`
# (v29.10.1-dev) -- a string baked in at build time -- while running module v29.7.0 and v29.8.0 and
# producing different output.  Comparing what ignite PRINTS is therefore a check that cannot fail.
# `go version -m` reports the module a Go binary was built from, which is what actually varies, and
# it works for a release tarball and a source build alike.
#
# Sourced or run; prints nothing on success unless --verbose.

SCRIPT_DIR="${0:A:h}"
cd "$SCRIPT_DIR/.." || exit 1

verbose=0
[[ $1 == "--verbose" ]] && verbose=1

want=$(awk '$1 == "github.com/cosmos/gogoproto" { print $2; exit }' go.mod)
if [[ -z $want ]]; then
    print -u2 "check_codegen_plugins.sh: could not read github.com/cosmos/gogoproto from go.mod"
    exit 1
fi

plugin=$(command -v protoc-gen-gocosmos)
if [[ -z $plugin ]]; then
    print -u2 "protoc-gen-gocosmos is not on PATH, so ignite would generate with a different plugin."
    print -u2 "    go install github.com/cosmos/gogoproto/protoc-gen-gocosmos@$want"
    exit 1
fi

have=$(go version -m "$plugin" 2>/dev/null \
    | awk '$1 == "mod" && $2 == "github.com/cosmos/gogoproto" { print $3; exit }')

if [[ $have != $want ]]; then
    print -u2 ""
    print -u2 "protoc-gen-gocosmos is the WRONG VERSION for this project."
    print -u2 "    installed: ${have:-unknown}   ($plugin)"
    print -u2 "    go.mod:    $want"
    print -u2 ""
    print -u2 "    Generating with it rewrites the .pb.go files in a shape this project did not commit."
    print -u2 "    You will not see that here -- it surfaces later as \"the working tree is dirty\" when"
    print -u2 "    packaging, long after the build that caused it."
    print -u2 ""
    print -u2 "    Fix:"
    print -u2 "        go install github.com/cosmos/gogoproto/protoc-gen-gocosmos@$want"
    print -u2 "        sudo install -m 0755 \"\$HOME/go/bin/protoc-gen-gocosmos\" /usr/local/bin/protoc-gen-gocosmos"
    print -u2 "    or re-run ubuntu/setup_qadena_build.sh, which now pins it from go.mod."
    print -u2 ""
    exit 1
fi

(( verbose )) && print "protoc-gen-gocosmos $have matches go.mod"

# IGNITE, checked the same way and for the same reason.  Pinned in ubuntu/setup_qadena_build.sh
# rather than go.mod, because ignite is a tool this project runs, not a module it links.
want_ignite=$(awk -F= '/^IGNITE_VERSION=/ { print $2; exit }' ubuntu/setup_qadena_build.sh | tr -d ' ')
if [[ -n $want_ignite ]]; then
    ignite_bin=$(command -v ignite)
    if [[ -z $ignite_bin ]]; then
        print -u2 "ignite is not on PATH."
        exit 1
    fi
    have_ignite=$(go version -m "$ignite_bin" 2>/dev/null \
        | awk '$1 == "mod" && $2 == "github.com/ignite/cli/v29" { print $3; exit }')
    if [[ $have_ignite != "v$want_ignite" ]]; then
        print -u2 ""
        print -u2 "ignite is the WRONG VERSION for this project."
        print -u2 "    installed: ${have_ignite:-unknown}   ($ignite_bin)"
        print -u2 "    pinned:    v$want_ignite   (ubuntu/setup_qadena_build.sh)"
        print -u2 ""
        print -u2 "    ignite embeds its own protobuf generator, so a different build regenerates the"
        print -u2 "    .pb.go files in a shape this project did not commit -- surfacing later as"
        print -u2 "    \"the working tree is dirty\" when packaging.  Note that \`ignite version\` prints"
        print -u2 "    the same string for both, so trust this comparison rather than that one."
        print -u2 ""
        print -u2 "    Fix: re-run ubuntu/setup_qadena_build.sh, or install the pinned release."
        print -u2 ""
        exit 1
    fi
    (( verbose )) && print "ignite $have_ignite matches the pin"

    # NO STALENESS CHECK HERE, and that is a deliberate negative result.
    #
    # The obvious one -- refuse when ~/.ignite/cache is older than the ignite binary -- was written
    # and REJECTED: it fires on a machine that generates perfectly (this Mac has a cache older than
    # its binary and reproduces the committed tree exactly).  mtime is not evidence about what the
    # cache CONTAINS, and a check that cries wolf on a healthy machine is worse than none: it trains
    # people to skip the one that matters.
    #
    # The cache is invalidated where it can be done correctly instead -- ubuntu/setup_qadena_build.sh
    # clears it whenever it installs a different ignite.  If you upgrade ignite by hand, clear it by
    # hand:  rm -rf ~/.ignite/cache ~/.ignite/ignite_cache.db
fi

exit 0
