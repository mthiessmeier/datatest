# Baltic OSINT Watch — Current Assessment

**Generated:** 2026-08-25T16:25:56Z  
**Meeting phase:** ongoing  
**Overall watch condition:** AMBER  
**H1 — visit concerned a near-term Baltic attack/provocation:** AMBER (5.0/10 indicator score)  
**H2 — warning/deconfliction effort failed:** GREEN (2.9/10 indicator score; provisional while the visit is ongoing)

> This is a public-source indicator monitor, not a probability estimate and not an inference about the purpose of an undisclosed U.S. government mission. A score reflects observable warning signatures, source quality, recency and corroboration.

## Collection summary

- New unique items this run: **331**
- Rolling observations retained (72 hours): **331**
- Raw items collected before deduplication: **494**
- Collection errors: **10**

## Triggered indicators (rolling 72 hours)

| ID | Indicator | Severity | Hits | Independent domains | Best source tier |
|---|---|---:|---:|---:|---:|
| H1-I08 | Kinetic or sabotage incident at Baltic critical infrastructure | critical | 3 | 3 | 3 |
| H1-I03 | Abrupt reinforcement of Baltic air/missile defence posture | high | 1 | 1 | 3 |
| H1-I09 | Coordinated Russian attribution/retaliation narrative | medium | 3 | 3 | 3 |

## New items that triggered indicators

- **[Lithuania Warns Russia Could Stage False Flag Attacks on Baltic Critical Infrastructure - Межа. Новини України.](https://news.google.com/rss/articles/CBMibEFVX3lxTE9xbVliNWRIZEZLVUNZYTc5WG1Wc1RfWVN5clZ5YlJab1ZfVFdxdW9XTUllc0UxSDVZbngtT0FvQ1BPWFRBT3ZYS1dHU3NJd1ZJa0Q4aDFIV0swanJtV3c1US1UZDk3X2RmbTc5cQ?oc=5)** — Межа. Новини України.; tier 3; 2026-08-24T16:28:25Z; indicators: H1-I08, H1-I09
- **[Estonia is using all diplomatic channels to ensure that Ukraine receives additional air defence equipment, - Karis - Цензор.НЕТ](https://news.google.com/rss/articles/CBMikwFBVV95cUxQV3hRcDFldzJSMGFuWnhuWTFXN3Z0ZDlIUjlROGFERkl2Qi00X0NjVzdPSG9URFpQSlh4X3dBSnVFTndJU1RjdjNVWm1ZUWdSZEE5ZmEtOG1yR0QySm1yRHA0MldqQXN0d0dDV1hiVF9mbXJ5aDYxYlFCU1FLUEdnN1g0QUpmN1BZVDVfNWVWVURYUlk?oc=5)** — Цензор.НЕТ; tier 3; 2026-08-25T12:53:00Z; indicators: H1-I03
- **[Zelenskyy comments on possible support from Ukraine in event of Russian attack on Baltic states - Українська правда](https://news.google.com/rss/articles/CBMiZEFVX3lxTE1nN0kzb29zdExHZ3E4RmJjbEdJWTAtRVdGVnh5aDJrR2xPMHpSYXhGaWJCTFVINlduZk9obnlqV3F1bEE4NlJLOUtYNlJjUi1jRGFQaWtKeFBjdW5FV2tmOW5vb1XSAXBBVV95cUxNLTY3ZXl4NU9OZWhmMXphYTltZFZDeTVHMXplMUhfajdSczRGWE4tYm1LWDJ3S1ZmUnRPTFNSNjNBWlBaTUhLem00NGpyVWlJUWszOGI1cnNyb08zMDVnMThsOHhSWVBWYUxkTjljT0h6?oc=5)** — Українська правда; tier 3; 2026-08-25T15:19:00Z; indicators: H1-I08, H1-I09
- **[Zelenskyy comments on possible support from Ukraine in event of Russian attack on Baltic states - Yahoo](https://news.google.com/rss/articles/CBMiogFBVV95cUxPbFdlR1VRb3lESnVDaFpCdEJBNGU3cjRQZ19kSkVuNXRvSF9lajcwLXdDRFdIblpGVUlvTWRQZlZVNHR0eU9mT1RUdkQzaWVoMEE3LW5lOFo1TjMxZG1MM0IzN2h2MEZfUFctYUQwbVJaSUQ2SHB4YlZyejh1em9jZjdiZXhoUzY3TXR0VDRaMEpIN3p0LTktQmlVZ204b3lTa0E?oc=5)** — Yahoo; tier 3; 2026-08-25T15:19:00Z; indicators: H1-I08, H1-I09

## Escalation logic

- **AMBER** may be produced by one meaningful but uncorroborated indicator. It is a collection cue, not a warning of attack.
- **ORANGE** requires a high aggregate score plus at least two independent domains and at least one official/high-reliability source, unless a direct official critical warning is observed.
- **RED** requires either a direct official critical indicator or a multi-source cluster containing at least two critical indicators. Social-only reporting is capped at AMBER.
- Silence, Kremlin denial, secrecy, a C-17/C-40 movement, or departure without a readout do not independently establish either hypothesis.

## Collection health

- RSS NATO News: HTTPError: 404 Client Error: Not Found for url: https://www.nato.int/cps/en/natohq/rssFeed.xsl/rssFeed.xml
- GDELT Russian western force preparation: HTTPError: 429 Client Error: Too Many Requests for url: https://api.gdeltproject.org/api/v2/doc/doc?query=%28Kaliningrad+OR+Pskov+OR+Belarus+OR+Leningrad%29+%28deployment+OR+mobilization+OR+missile+OR+launcher+OR+convoy+OR+readiness+OR+NOTAM+OR+airspace%29&mode=ArtList&maxrecords=100&format=json&timespan=1d&sort=DateDesc
- GDELT Baltic critical infrastructure attack: HTTPError: 429 Client Error: Too Many Requests for url: https://api.gdeltproject.org/api/v2/doc/doc?query=%28Latvia+OR+Lithuania+OR+Estonia+OR+Baltic%29+%28critical+infrastructure+OR+factory+OR+power+OR+rail+OR+port+OR+airport+OR+telecom%29+%28sabotage+OR+attack+OR+fire+OR+explosion+OR+cyberattack%29&mode=ArtList&maxrecords=100&format=json&timespan=1d&sort=DateDesc
- GDELT NATO emergency posture: HTTPError: 429 Client Error: Too Many Requests for url: https://api.gdeltproject.org/api/v2/doc/doc?query=NATO+%28Baltic+OR+Kaliningrad+OR+Latvia+OR+Lithuania+OR+Estonia%29+%28Article+4+OR+emergency+OR+readiness+OR+air+defence+OR+air+defense+OR+AWACS+OR+combat+air+patrol%29&mode=ArtList&maxrecords=100&format=json&timespan=1d&sort=DateDesc
- GDELT Baltic diplomatic warning: HTTPError: 429 Client Error: Too Many Requests for url: https://api.gdeltproject.org/api/v2/doc/doc?query=%28Riga+OR+Vilnius+OR+Tallinn+OR+Latvia+OR+Lithuania+OR+Estonia%29+%28security+alert+OR+embassy+OR+evacuation+OR+shelter+OR+ordered+departure+OR+credible+threat%29&mode=ArtList&maxrecords=100&format=json&timespan=1d&sort=DateDesc
- GDELT Ratcliffe Moscow outcome: HTTPError: 429 Client Error: Too Many Requests for url: https://api.gdeltproject.org/api/v2/doc/doc?query=Ratcliffe+Moscow+%28warning+OR+talks+OR+meeting+OR+rejected+OR+departed+OR+Kremlin+OR+no+agreement+OR+consequences%29&mode=ArtList&maxrecords=100&format=json&timespan=1d&sort=DateDesc
- Bluesky Baltic drone Kaliningrad: HTTPError: 403 Client Error: Forbidden for url: https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts?q=Baltic+drone+Kaliningrad&limit=75&sort=latest
- Bluesky Latvia Lithuania Estonia airspace drone: HTTPError: 403 Client Error: Forbidden for url: https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts?q=Latvia+Lithuania+Estonia+airspace+drone&limit=75&sort=latest
- Bluesky Ratcliffe Moscow Kremlin: HTTPError: 403 Client Error: Forbidden for url: https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts?q=Ratcliffe+Moscow+Kremlin&limit=75&sort=latest
- Bluesky Baltic critical infrastructure Russia: HTTPError: 403 Client Error: Forbidden for url: https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts?q=Baltic+critical+infrastructure+Russia&limit=75&sort=latest

