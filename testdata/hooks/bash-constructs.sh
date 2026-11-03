# Parser coverage fixture.
name=${PROJECT_NAME:-latra}
printf '%s\n' "$name" | sed 's/a/A/g' >output.txt
result="$(printf '%s' "$name")"
cat <(printf '%s' "$result")
(cd /project && pwd)

build() {
  local target=$1
  echo "building ${target}"
}

if [[ -n $result ]]; then
  for item in one two; do
    case $item in
      one) build "$item" ;;
      *) echo "$((1 + 2))" ;;
    esac
  done
fi

cat <<'EOF'
fixture
EOF

