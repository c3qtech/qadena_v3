#!/bin/zsh

# VERIFY THE PLUGINS BEFORE GENERATING.
#
# `ignite generate proto-go` does not generate anything itself -- proto/buf.gen.gogo.yaml names
# `gocosmos` and `grpc-gateway` as LOCAL plugins, so buf runs whichever binaries are on the machine.
# Different plugin versions emit different Go: gogoproto v1.4.12 adds an extra
# `var X_serviceDesc = _X_serviceDesc` alias per service file that v1.7.x does not.
#
# That difference is invisible here and surfaces two steps later as something else entirely: the
# regenerated .pb.go files dirty the tree, and package_release.sh refuses artifacts that
# "correspond to no commit", so phase 7 of 1st_node_bringup.sh fails on a machine whose only fault
# is an old plugin.  Measured 2026-08-18: Mac had gogoproto v1.7.0, M1 v1.4.12, go.mod asks v1.7.2.
#
# The obvious check is the wrong one.  Both machines reported the SAME ignite version
# (v29.10.1-dev) while producing different output, so comparing `ignite version` is a check that
# cannot fail.  `go version -m` reports the module that built a binary, which is the thing that
# actually varies.

SCRIPT_DIR="${0:A:h}"
cd "$SCRIPT_DIR/.." || exit 1

# The same preflight init.sh runs, because both regenerate with the same local plugins.
"$SCRIPT_DIR/check_codegen_plugins.sh" --verbose || exit 1

ignite generate proto-go --yes
