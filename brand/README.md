# Clearance logo

| File | Use |
|---|---|
| `clearance-logo.svg` | the source |
| `clearance-logo-512.png` | the GitHub App's logo (Settings > Display information; GitHub wants a square image under 1 MB) |
| `clearance-slack-icon.svg` | the source of the Slack app icon: Hangar's Clearance mark (a check over the hold-short lines, in the instrument dial; hangar `brand/marks/clearance-tile.svg`) on a full-bleed square, because Slack rounds the corners itself, so transparent corners would show Slack's background |
| `clearance-slack-icon-1024.png` | the Slack app icon upload (Slack wants a square, 512-2000 px) |

An amber `C`, a gauge arc open to the right, and a sky-blue check passing through the opening: a change that was
cleared. Colors are Hangar's dark theme: ground `#14181D`, amber `#E8A33D`, sky `#6FB2D9`. Use `#14181D` as the
App's badge background color.

Re-render after editing the SVG (macOS):

```
qlmanage -t -s 512 -o /tmp brand/clearance-logo.svg && cp /tmp/clearance-logo.svg.png brand/clearance-logo-512.png
```

The Slack icon re-renders the same way:

```
qlmanage -t -s 1024 -o /tmp brand/clearance-slack-icon.svg && cp /tmp/clearance-slack-icon.svg.png brand/clearance-slack-icon-1024.png
```
