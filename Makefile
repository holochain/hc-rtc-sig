# hc-rtc-sig Makefile

.PHONY: all publish test static docs tools tool_rust tool_fmt tool_readme

SHELL = /usr/bin/env sh

all: test

publish:
	@case "$(crate)" in \
		hc-rtc-sig) \
			export MANIFEST="./Cargo.toml"; \
			;; \
		*) \
			echo "USAGE: make publish crate=hc-rtc-sig"; \
			exit 1; \
			;; \
	esac; \
	export VER="v$$(grep version $${MANIFEST} | head -1 | cut -d ' ' -f 3 | cut -d \" -f 2)"; \
	echo "publish $(crate) $${MANIFEST} $${VER}"; \
	git diff --exit-code; \
	cargo publish --manifest-path $${MANIFEST}; \
	git tag -a "$(crate)-$${VER}" -m "$(crate)-$${VER}"; \
	git push --tags;

test: static tools
	RUST_BACKTRACE=1 cargo test

static: docs tools
	cargo fmt -- --check
	cargo clippy

docs: tools
	printf '### The `hc-rtc-sig-srv` executable\n`hc-rtc-sig-srv --help`\n```text\n' > src/docs/srv_help.md
	cargo run -- --help >> src/docs/srv_help.md
	printf '\n```\n' >> src/docs/srv_help.md
	cargo readme -o README.md
	printf '\n' >> README.md
	cat src/docs/srv_help.md >> README.md
	@if [ "${CI}x" != "x" ]; then git diff --exit-code; fi

tools: tool_rust tool_fmt tool_clippy tool_readme

tool_rust:
	@if rustup --version >/dev/null 2>&1; then \
		echo "# Makefile # found rustup, setting override stable"; \
		rustup override set stable; \
	else \
		echo "# Makefile # rustup not found, hopefully we're on stable"; \
	fi;

tool_fmt: tool_rust
	@if ! (cargo fmt --version); \
	then \
		if rustup --version >/dev/null 2>&1; then \
			echo "# Makefile # installing rustfmt with rustup"; \
			rustup component add rustfmt; \
		else \
			echo "# Makefile # rustup not found, cannot install rustfmt"; \
			exit 1; \
		fi; \
	else \
		echo "# Makefile # rustfmt ok"; \
	fi;

tool_clippy: tool_rust
	@if ! (cargo clippy --version); \
	then \
		if rustup --version >/dev/null 2>&1; then \
			echo "# Makefile # installing clippy with rustup"; \
			rustup component add clippy; \
		else \
			echo "# Makefile # rustup not found, cannot install clippy"; \
			exit 1; \
		fi; \
	else \
		echo "# Makefile # clippy ok"; \
	fi;

tool_readme: tool_rust
	@if ! (cargo readme --version); \
	then \
		cargo install cargo-readme; \
	else \
		echo "# Makefile # readme ok"; \
	fi;
