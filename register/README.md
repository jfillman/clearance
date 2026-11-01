# Clearance register (GitHub Action)

Registers what a workflow is about to deploy with Clearance's deployment gate, so the Clearance GitHub App, installed
as a **deployment protection rule** on the environment, can answer the deploy job
([docs/provenance-app.md](../docs/provenance-app.md), phases 2a and 2b).

```yaml
jobs:
  register:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write          # Clearance accepts this workflow's OIDC token, for this repository only
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 2 }
      - run: ./render.sh prod HEAD~1 > /tmp/before && ./render.sh prod HEAD > /tmp/after   # your renderer
      - uses: jfillman/clearance/register@v0.23.0
        with:
          url: https://clearance.example.com
          app: shop
          env: prod
          cluster: prod-eu
          before: /tmp/before
          after: /tmp/after
  deploy:
    needs: register
    environment: prod          # protected by the Clearance App
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh
```

- **Cleared** (tiers 0 and 1, by policy): the deploy job starts.
- **Holding** for people (tiers 2 and 3): `register` succeeds and the deploy job waits on the protection rule until
  they clear or deny the change.
- **Denied**, or refused (`DG-REPO`: a workflow registers changes for its own repository only): `register` fails.

Clearance must list the workflow as a verifier: its principal is `github:<sub>`, for example
`github:repo:acme/shop:ref:refs/heads/main`, so `CLEARANCE_VERIFIERS` takes `github:repo:acme/*`. The environment
name is matched lowercased, so `env` is the GitHub environment's name.
