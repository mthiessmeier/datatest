# Baltic OSINT Watch

An hourly, public-source warning monitor for two narrowly defined hypotheses:

- **H1:** the undisclosed U.S. intelligence visit to Moscow concerned a near-term Russian attack or deniable provocation against Latvia, Lithuania, Estonia, or closely connected NATO infrastructure.
- **H2:** a warning, deconfliction effort, or deterrent message associated with that visit failed.

The monitor does **not** attempt to discover the purpose of a classified or undisclosed mission. It collects only public news, RSS feeds, and public social commentary, then scores observable warning indicators. The scores are collection and triage aids—not probabilities and not conclusions about intent.

## Schedule and outputs

The GitHub Actions workflow runs every hour at minute **17 UTC**, on manual dispatch, and when the monitor/configuration changes.

Each run:

1. Collects Google News RSS, GDELT news, Baltic public-media RSS, NATO RSS, and public Bluesky search results.
2. Deduplicates items and retains a rolling 72-hour evidence window.
3. Applies explicit H1, H2, and disconfirming indicators.
4. Writes `reports/latest.md` and updates `data/state.json`.
5. Updates the assigned GitHub issue **[Baltic OSINT Watch] Current assessment**.
6. Creates a separate assigned issue only when the watch condition newly transitions to **ORANGE** or **RED**.

## Alert discipline

- **GREEN:** no meaningful configured warning signature.
- **AMBER:** one meaningful but uncorroborated signal or a weak multi-source cluster.
- **ORANGE:** a high score with independent corroboration and at least one official/high-reliability source, or a direct official critical warning.
- **RED:** a direct official critical indicator or a corroborated cluster containing multiple critical indicators.

Social-only reporting is capped at **AMBER**. Silence, secrecy, a diplomatic motorcade, a C-17/C-40 movement, or departure without a readout cannot independently produce ORANGE or RED.

## Sources

The default configuration uses:

- Google News RSS query feeds
- GDELT DOC 2.1
- LSM Latvia English Defence and Politics RSS
- ERR Estonia English News RSS
- NATO News RSS
- Bluesky public search API

The collector fails soft: an unavailable source is recorded in the report but does not stop the remaining sweep.

## Files

- `monitor.py` — collectors, indicator matching, scoring, reporting, and GitHub issue updates
- `config/watch_config.json` — queries, feeds, source tiers, and collection window
- `ANALYTIC_FRAMEWORK.md` — hypotheses, scenario model, indicator rationale, false positives, and escalation gates
- `.github/workflows/hourly-osint.yml` — hourly scheduler
- `data/state.json` — deduplication and rolling evidence state
- `reports/latest.md` — latest machine-generated assessment

## Operating boundaries

This is defensive OSINT. It does not use credentials for private platforms, acquire non-public data, identify covert personnel, penetrate systems, or conduct facility-level targeting reconnaissance. All automated judgments remain subject to human analytic review.
