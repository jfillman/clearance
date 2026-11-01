# Clearance logo

| File | Use |
|---|---|
| `clearance-logo.svg` | the source |
| `clearance-logo-512.png` | the GitHub App's logo (Settings > Display information; GitHub wants a square image under 1 MB) |

An amber `C`, a gauge arc open to the right, and a sky-blue check passing through the opening: a change that was
cleared. Colors are Hangar's dark theme: ground `#14181D`, amber `#E8A33D`, sky `#6FB2D9`. Use `#14181D` as the
App's badge background color.

Re-render after editing the SVG (macOS):

```
qlmanage -t -s 512 -o /tmp brand/clearance-logo.svg && cp /tmp/clearance-logo.svg.png brand/clearance-logo-512.png
```
