#!/bin/zsh
#
# Is this machine's protobuf generator the one this project pins?
#
# ANY ignite invocation that regenerates protos -- `ignite generate proto-go`, and `ignite chain
# init`, which does it as a side effect -- runs the LOCAL plugins named in proto/buf.gen.gogo.yaml
# (`gocosmos`, `grpc-gateway`).  Ignite does not carry them; it runs whatever is installed.  So the
# generated Go depends on a binary version nothing in the repo controlled until now.
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
# (v29.10.1-dev) while producing different output, so comparing ignite's version is a check that
# cannot fail.  `go version -m` reports the module that built a binary, which is what varies.
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
exit 0
