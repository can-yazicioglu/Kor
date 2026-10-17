# Repository media

These assets illustrate the **actual local synthetic demo**, not a customer deployment or externally hosted service.

| Asset | Provenance |
|---|---|
| `banner.svg` | Original repository-native SVG artwork; no IBM certification or partner logo. |
| `kor-demo.gif` | Chromium screen recording of the running Vela application. Public demo fixtures only; no fake score overlays or mocked responses. |
| `../screenshots/attack-review.png` | Browser screenshot after the public 20-attempt brute-force replay. |
| `../screenshots/security-proof.png` | Browser screenshot after demo MFA, restricted-resource denial and an altered-receipt check. |
| `../screenshots/desktop.png`, `security-desk.png`, `mobile.png` | Desktop/mobile browser captures refreshed with the Kör branding. |

The walkthrough and screenshots were refreshed on **17 October 2026** from the Kör-branded runtime committed with this media update. Recording automation lives in [`scripts/capture_demo.mjs`](../../scripts/capture_demo.mjs); the capture-time runtime manifest digest is recorded in [`provenance.json`](provenance.json). Scores, receipt digests and countdowns can vary between runs; no identities or live bearer handles are displayed in the published media.

## What the animation shows

- A public, bounded brute-force replay creates 20 synthetic failed events.
- The current risk and reasons appear beside the fictional sign-in form.
- The published credentials lead to a demo MFA challenge and fictional workspace.
- An original receipt verifies; an altered-score copy is rejected.
- The employee resource is authorized, while the restricted console is denied.
- The evidence workbench exposes the retained state; reset clears the demo.

The baseline already recommends review for normal complete-context events because validated action thresholds are unavailable. The attack animation must not be read as evidence of a validated classifier. The public MFA code is not a real second factor.

## Record it again

Install the browser development dependencies from the [development guide](../development.md). Start a dedicated local server in one terminal:

```bash
python3 app/serve.py --port 18341
```

In another terminal:

```bash
node scripts/capture_demo.mjs
```

The script accepts an optional **loopback-only** URL, asserts the displayed outcomes, checks for page errors and external requests, and checks that cookies/local/session storage remain empty. It records WebM under ignored `.local/repo-media/` and writes all five desktop/mobile screenshots above. Stop the dedicated server after capture. Do not use a real account or customer environment.

To encode with FFmpeg, replace `RECORDING.webm` with the path printed by the script:

```bash
ffmpeg -i .local/repo-media/RECORDING.webm \
  -filter_complex '[0:v]fps=4,scale=960:-1:flags=lanczos,split[a][b];[a]palettegen=stats_mode=full:max_colors=64[p];[b][p]paletteuse=dither=none:diff_mode=rectangle' \
  -loop 0 -y docs/media/kor-demo.gif
```

The GIF retains the recorded sequence and timing; only resolution, frame rate and palette are reduced for download size. It loops automatically. Static screenshots and the textual walkthrough provide alternatives to motion. The repository runtime has no dependency on FFmpeg or the recording tool.

README status badges link to CI, runtime requirements, the license and prototype status. They are labels, not security certifications or claims of production performance.
