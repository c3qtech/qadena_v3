#!/bin/zsh
#
# Apply config.yml's `app:` stanza to a node's app.toml.
#
#   scripts/apply_app_config.sh [--config <config.yml>] [--app-toml <app.toml>] [--dry-run]
#
# WHY THIS EXISTS.  There are two ways a node's app.toml comes into being, and only one of them
# reads config.yml:
#
#   GENESIS NODE   buildscripts/init.sh runs `ignite chain init`, which renders the whole `app:`
#                  stanza of config/config.yml into app.toml -- [json-rpc], [evm], [wasm], pruning,
#                  the lot.
#
#   JOINED NODE    add_full_node.sh runs `qadenad init`, which writes the stock cosmos-sdk template.
#                  That template has NO [json-rpc], NO [evm] and NO [wasm] section at all.
#
# So a joined node silently differed from the genesis node in every setting config.yml prescribes.
# The way this surfaced: the EVM JSON-RPC never came up on the second node.  Nothing failed, nothing
# logged an error -- port 8545 simply was not listening, because `json-rpc.enable` lives in a section
# that did not exist.  run.sh makes that harder to spot, not easier: it passes --json-rpc.api on the
# command line, so the API list is configured while the server itself stays off.
#
# Also missing on such a node: the evm mempool limits, wasm's query_gas_limit and memory_cache_size,
# and the pruning settings.  None of them are consensus-critical -- which is exactly why a node can
# be wrong about all of them and still look healthy.
#
# HOW IT MERGES.  dasel renders the YAML stanza to TOML with the same types ignite produces (numbers
# stay quoted strings there, so they stay quoted here).  Then:
#
#   root scalars   written with `dasel put` -- they already exist in the stock template
#   [tables]       appended whole when absent
#
# Leaf-by-leaf `dasel put` is NOT used for tables: dasel panics ("unable to set value with missing
# setFn") when asked to create a key under a table that does not exist yet, which is precisely the
# case here.  A table that IS already present is left alone and reported rather than half-merged --
# silently interleaving two sources into one section is how you get a config nobody can reason about.

SCRIPT_DIR="${0:A:h}"

# Standalone-friendly: this ships in release packages, where there is no build tree to source from.
if [[ -f "$SCRIPT_DIR/setup_env.sh" ]]; then
    source "$SCRIPT_DIR/setup_env.sh"
fi

set -e

config_yml="${QADENAHOME:-$HOME/qadena}/config/config.yml"
app_toml="${QADENAHOME:-$HOME/qadena}/config/app.toml"
dry_run=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)   config_yml="$2"; shift 2 ;;
    --app-toml) app_toml="$2"; shift 2 ;;
    --dry-run)  dry_run=1; shift ;;
    --help)
      echo "Usage: apply_app_config.sh [--config <config.yml>] [--app-toml <app.toml>] [--dry-run]"
      echo ""
      echo "Applies the 'app:' stanza of config.yml to app.toml, so a node joined with"
      echo "'qadenad init' ends up with the same [json-rpc], [evm], [wasm] and pruning"
      echo "settings that 'ignite chain init' gives the genesis node."
      exit 0 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

fail() { echo "apply_app_config.sh: $1" >&2; exit 1; }

command -v dasel > /dev/null 2>&1 || fail "dasel is required"
[[ -f "$config_yml" ]] || fail "no config.yml at $config_yml"
[[ -f "$app_toml" ]]   || fail "no app.toml at $app_toml"

# dasel needs an absolute path for -f when it rewrites in place.
app_toml="${app_toml:A}"

rendered=$(dasel -f "$config_yml" -r yaml -w toml '.validators.[0].app' 2>/dev/null) \
    || fail "could not read .validators.[0].app from $config_yml"
[[ -n "$rendered" ]] || fail "$config_yml has no validators[0].app stanza"

echo "source: $config_yml"
echo "target: $app_toml"

changed=0

# put_leaf <dotted-path> <dasel-rendered-value> -- dasel emits TOML strings single-quoted and
# booleans bare, which is enough to pick the type back out.
put_leaf() {
    local dpath="$1" val="$2" t
    if [[ "$val" == \'*\' ]]; then
        val="${val:1:-1}"; t=string
    elif [[ "$val" == "true" || "$val" == "false" ]]; then
        t=bool
    else
        t=string
    fi
    if [[ $dry_run -eq 1 ]]; then
        echo "  would set $dpath = $val ($t)"
    else
        dasel put -t "$t" -v "$val" ".$dpath" -f "$app_toml"
        echo "  set $dpath = $val"
    fi
    changed=1
}

# WALK THE RENDERED TOML SECTION BY SECTION, where a section is any [header] -- including dotted
# sub-tables like [evm.mempool].  For each one:
#
#   header already in app.toml   write its keys individually, so existing settings in that section
#                                survive and only what config.yml prescribes is overwritten
#   header absent                append the section verbatim
#
# The split matters.  A leaf `dasel put` into a table that does NOT exist panics outright ("unable to
# set value with missing setFn"), and appending into a table that DOES exist would produce a
# duplicate header.  Treating dotted sub-tables as sections in their own right is what keeps both
# cases honest: [evm] gets appended whole, and if [state-sync] is already there its keys are set in
# place.  dasel renders parents before children, so an appended [evm] always precedes [evm.mempool].
section=""            # current [header], empty means root scalars
pending_block=""      # accumulated lines for a section being appended
pending_name=""

flush_pending() {
    [[ -n "$pending_name" ]] || return 0
    if [[ $dry_run -eq 1 ]]; then
        echo "  would append [$pending_name] ($(echo "$pending_block" | wc -l | tr -d ' ') lines)"
    else
        printf '\n%s\n' "$pending_block" >> "$app_toml"
        echo "  appended [$pending_name]"
    fi
    changed=1
    pending_name=""; pending_block=""
}

while IFS= read -r line; do
    # STRIP THE INDENT BEFORE ANYTHING ELSE.  dasel indents keys inside tables by two spaces and
    # nests sub-table headers further still -- "  [evm.mempool]" is a header, and testing the raw
    # line for a leading '[' misses it, which silently turned it into a key named "[evm.mempool]".
    # (Plain POSIX trimming: zsh's [[:space:]]## needs extendedglob, which is not set here.)
    trimmed="${line#"${line%%[![:space:]]*}"}"

    [[ -n "$trimmed" ]] || continue

    if [[ "$trimmed" == \[*\] ]]; then
        flush_pending
        section="${trimmed:1:-1}"
        # Sub-tables are sections in their own right; dasel renders parents first, so an appended
        # [evm] always lands before [evm.mempool] and the result is valid TOML either way.
        if grep -qF "$trimmed" "$app_toml"; then
            echo "  [$section] exists -- setting its keys in place"
        else
            pending_name="$section"
            pending_block="$trimmed"
        fi
        continue
    fi

    if [[ -n "$pending_name" ]]; then
        pending_block="$pending_block"$'\n'"  $trimmed"
        continue
    fi

    key="${trimmed%% =*}"
    val="${trimmed#*= }"
    if [[ -n "$section" ]]; then
        put_leaf "$section.$key" "$val"
    else
        put_leaf "$key" "$val"
    fi
done <<< "$rendered"
flush_pending

if [[ $changed -eq 0 ]]; then
    echo "nothing to apply"
else
    echo "done -- restart the node for this to take effect"
fi
