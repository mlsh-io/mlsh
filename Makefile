# MLSH — build targets

APP          := target/MLSH.app
CONTENTS     := $(APP)/Contents
MACOS        := $(CONTENTS)/MacOS
RESOURCES    := $(CONTENTS)/Resources
SWIFT_DIR    := mlsh-menubar
WIN_TARGET   := x86_64-pc-windows-msvc
WIN_DIR      := target/windows
SIGNAL_IMAGE := ghcr.io/$(shell git config --get remote.origin.url 2>/dev/null | sed -n 's|.*github.com[:/]\(.*\)\.git|\1|p' | tr '[:upper:]' '[:lower:]' | cut -d/ -f1)/mlsh-signal
GIT_VERSION  := $(shell git describe --tags --always --dirty=-dirty 2>/dev/null || echo dev)

.DEFAULT_GOAL := help

# ---------------------------------------------------------------------------
# Top-level targets
# ---------------------------------------------------------------------------

.PHONY: help fmt lint app app-universal cli cli-universal windows menubar menubar-universal signal signal-image clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

fmt: ## Format all Rust code
	cargo fmt --all

lint: ## Run fmt check + clippy on all crates
	cargo fmt --all --check
	cargo clippy --all -- -D warnings -A clippy::uninlined_format_args

app: cli menubar bundle ## Build MLSH.app for current arch
	@echo "\nDone: $(APP)  (run with: open $(APP))"

app-universal: cli-universal menubar-universal bundle ## Build MLSH.app universal (x86_64 + arm64)
	@echo "\nDone: $(APP)  — universal (run with: open $(APP))"

# ---------------------------------------------------------------------------
# Rust
# ---------------------------------------------------------------------------

cli: ## Build mlsh + mlshtund (current arch)
	@echo "==> Building Rust binaries..."
	cargo build --release -p mlsh-cli

cli-universal: ## Build mlsh + mlshtund universal (x86_64 + arm64)
	@echo "==> Building Rust binaries (universal)..."
	cargo build --release -p mlsh-cli --target aarch64-apple-darwin
	cargo build --release -p mlsh-cli --target x86_64-apple-darwin

# ---------------------------------------------------------------------------
# Windows
# ---------------------------------------------------------------------------

windows: ## Build mlsh.exe + mlshtund.exe (cross-compile via cargo-xwin)
	@echo "==> Building Windows binaries ($(WIN_TARGET))..."
	PATH="/opt/homebrew/opt/llvm/bin:$$PATH" cargo xwin build --release -p mlsh-cli --target $(WIN_TARGET)
	@rm -rf $(WIN_DIR)
	@mkdir -p $(WIN_DIR)
	@cp target/$(WIN_TARGET)/release/mlsh.exe $(WIN_DIR)/mlsh.exe
	@cp target/$(WIN_TARGET)/release/mlsh.exe $(WIN_DIR)/mlshtund.exe
	@echo "\nDone: $(WIN_DIR)/\n  mlsh.exe\n  mlshtund.exe"

# ---------------------------------------------------------------------------
# Signal server
# ---------------------------------------------------------------------------

signal: ## Build mlsh-signal (current arch)
	@echo "==> Building mlsh-signal..."
	cargo build --release -p mlsh-signal

signal-image: ## Build mlsh-signal Docker image (linux/amd64,arm64)
	@echo "==> Building mlsh-signal Docker image..."
	docker buildx build \
		--file mlsh-signal/Containerfile \
		--platform linux/amd64,linux/arm64 \
		--build-arg GIT_VERSION=$(GIT_VERSION) \
		--tag $(SIGNAL_IMAGE):$(GIT_VERSION) \
		--tag $(SIGNAL_IMAGE):latest \
		.

# ---------------------------------------------------------------------------
# Swift
# ---------------------------------------------------------------------------

menubar: ## Build Swift menu bar app (current arch)
	@echo "==> Building Swift menu bar app..."
	cd $(SWIFT_DIR) && swift build -c release

menubar-universal: ## Build Swift menu bar app universal (x86_64 + arm64)
	@echo "==> Building Swift menu bar app (universal)..."
	cd $(SWIFT_DIR) && swift build -c release --arch arm64 --arch x86_64

# ---------------------------------------------------------------------------
# Assemble .app bundle
# ---------------------------------------------------------------------------

.PHONY: bundle
bundle:
	@rm -rf $(APP)
	@mkdir -p $(MACOS) $(RESOURCES)
	@# Rust binary
	@if [ -f target/aarch64-apple-darwin/release/mlsh ] && [ -f target/x86_64-apple-darwin/release/mlsh ]; then \
		echo "==> Assembling MLSH.app (universal)..."; \
		lipo -create \
			target/aarch64-apple-darwin/release/mlsh \
			target/x86_64-apple-darwin/release/mlsh \
			-output $(MACOS)/mlsh; \
	else \
		echo "==> Assembling MLSH.app..."; \
		cp target/release/mlsh $(MACOS)/mlsh; \
	fi
	@ln -sf mlsh $(MACOS)/mlshtund
	@# Swift binary
	@if [ -f $(SWIFT_DIR)/.build/apple/Products/Release/MLSHMenuBar ]; then \
		cp $(SWIFT_DIR)/.build/apple/Products/Release/MLSHMenuBar $(MACOS)/MLSHMenuBar; \
	else \
		cp $(SWIFT_DIR)/.build/release/MLSHMenuBar $(MACOS)/MLSHMenuBar; \
	fi
	@cp $(SWIFT_DIR)/Info.plist $(CONTENTS)/Info.plist

# ---------------------------------------------------------------------------
# Clean
# ---------------------------------------------------------------------------

clean: ## Remove all build artifacts
	cargo clean
	rm -rf $(SWIFT_DIR)/.build
	rm -rf $(APP)
	rm -rf $(WIN_DIR)
