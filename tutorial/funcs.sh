run_cmd() {
  local cmd="$*"
  local border
  border="$(printf '%*s' $(( ${#cmd} + 6 )) '' | tr ' ' '*')"
  echo "$border"
  echo "* > $cmd *"
  echo "$border"
  echo "Results:"
  eval "$cmd"
}

run_cmd_capture() {
  local cmd="$*"
  local wrap_width=80
  local wrapped
  local maxlen=0
  local line
  local border
  local i=0

  wrapped="$(echo "$cmd" | fold -s -w "$wrap_width")"

  while IFS= read -r line; do
    if (( ${#line} > maxlen )); then
      maxlen=${#line}
    fi
  done <<< "$wrapped"

  border="$(printf '%*s' $(( maxlen + 6 )) '' | tr ' ' '*')"
  echo "$border" >&2

  while IFS= read -r line; do
    i=$(( i + 1 ))
    if (( i == 1 )); then
      printf '* > %-*s *\n' "$maxlen" "$line" >&2
    else
      printf '*   %-*s *\n' "$maxlen" "$line" >&2
    fi
  done <<< "$wrapped"

  echo "$border" >&2
  eval "$cmd"
}




