# Slum Pinpoint — SDG 1 Challenge Writeup

> **Challenge:** Geolocation OSINT — identify three informal settlements from SVG photos with visual/textual cues and submit their Wikipedia centroid coordinates.
>
> **Flag:** `SDG{535b292811676d2f785f622c4edc91a9}`

## Approach

### 1. Fetch the photos

The API provided three SVG images via `?action=photos`. Each was an EXIF-stripped SVG containing baked-in base64 PNG data plus textual cue lines.

### 2. Photo A — Dharavi (Mumbai, India)

**Coordinates:** `19.03778, 72.85361`

| Cue | Interpretation |
|---|---|
| Devanagari script | Hindi/Marathi language → India |
| Peninsular landform | Mumbai occupies a peninsula |
| Rail bridge | Mumbai's suburban railway network |
| Saltwater inlet / mangroves | Mahim Creek / Arabian Sea |
| Tropical climate | Western India |

Dharavi is one of the world's largest slums, located between Mumbai's Western and Central railway lines near Mahim Creek.

### 3. Photo B — Kibera (Nairobi, Kenya)

**Coordinates:** `-1.317, 36.783`

| Cue | Interpretation |
|---|---|
| East African terrain | Highlands / Great Rift Valley region |
| Swahili signage | Kenya / Tanzania |
| Railway line | Uganda Railway (Mombasa–Nairobi–Kisumu) |
| Acacia/jacaranda trees | Common East African species |
| Corrugated metal roofs | Typical informal housing (mabati) |

Kibera is Africa's largest urban slum, in southwest Nairobi along the Uganda Railway line.

### 4. Photo C — Rocinha (Rio de Janeiro, Brazil)

**Coordinates:** `-22.98861, -43.24833`

| Cue | Interpretation |
|---|---|
| Portuguese signage | Brazil |
| Hillside favela | Rio de Janeiro's iconic landscape |
| South Atlantic coastline | Rio's Zona Sul beaches |
| Elevated highway | Autoestrada Lagoa-Barra / Elevado do Joá |
| Beach umbrellas | São Conrado / Leblon beaches |
| Aerial tramway/cable car | Teleférico / urban mobility projects |

Rocinha is Rio's most populous favela, perched on a steep hillside between São Conrado and Gávea.

### 5. Coordinate lookup

Wikipedia page coordinates (used as reference centroids):

| Settlement | Wikipedia Coordinates | Decimal |
|---|---|---|
| Dharavi | 19°02′16″N 72°51′13″E | 19.03778, 72.85361 |
| Kibera | 1°19′S 36°47′E | -1.317, 36.783 |
| Rocinha | 22°59′19″S 43°14′54″W | -22.98861, -43.24833 |

### 6. Submission

```bash
curl -s -X POST "https://hackforachangeruntime.vercel.app/api/\
slum-pinpoint?seed=<seed>&action=verify" \
  -H "Content-Type: application/json" \
  -d '{"coords":[
    {"lat":19.03778,"lon":72.85361},
    {"lat":-1.317,"lon":36.783},
    {"lat":-22.98861,"lon":-43.24833}
  ]}'
```

**Response:** `{"ok":true,"distances_km":[0.11,0.79,0.29],"survey_token":"ad2710a703b00e032a19393d31ea66cc"}`

All three guesses fell within 1 km of the Wikipedia centroids.

### 7. Flag claim

```bash
curl -s -X POST "https://vgwukffsjudbybdeuodn.supabase.co/functions/v1/claim-runtime-flag" \
  -H "Authorization: Bearer <launch_jwt>" \
  -d '{"token":"<launch_jwt>","proof":"ad2710a703b00e032a19393d31ea66cc","slug":"slum-pinpoint"}'
```

**Flag:** `SDG{535b292811676d2f785f622c4edc91a9}`
