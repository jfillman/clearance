# Release-style build helpers. A plain `go build ./cmd/clearance` needs none of this: it embeds the committed
# placeholder UI. Released images carry the real one (Dockerfile, release workflow).

# The pinned clearance-ui bundle (web-ui.lock) into internal/web/static, sha256-verified. Leaves the tree dirty
# (index.html replaced, assets/ ignored); `make web-ui-clean` puts the placeholder back.
.PHONY: web-ui
web-ui:
	go run ./tools/webui

# Only check the pin: it resolves and the checksum matches.
.PHONY: web-ui-verify
web-ui-verify:
	go run ./tools/webui -verify

.PHONY: web-ui-clean
web-ui-clean:
	git checkout -- internal/web/static/index.html
	git clean -fdxq internal/web/static

# The release-style binary, and the test that its embedded index.html is the UI's and not the placeholder.
.PHONY: build-release
build-release: web-ui
	CLEARANCE_REQUIRE_UI_BUNDLE=1 go test -count=1 -run TestReleaseBundleIsTheUI ./internal/web
	go build -trimpath -o clearance ./cmd/clearance
