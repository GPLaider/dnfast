NAME := dnfast
VERSION := $(shell awk -F'"' '/^version = / { print $$2; exit }' Cargo.toml)
SPEC := packaging/dnfast.spec

.PHONY: srpm
srpm:
	set -eux; \
	test -n "$(outdir)"; \
	outdir_abs="$$(readlink -f "$(outdir)")"; \
	build_root="$$(mktemp -d)"; \
	trap 'rm -rf "$$build_root"' EXIT; \
	dnf -y install cargo git gzip rpm-build tar; \
	git archive --format=tar.gz --prefix="$(NAME)-$(VERSION)/" HEAD \
		> "$$outdir_abs/$(NAME)-$(VERSION).tar.gz"; \
	cargo vendor --locked --versioned-dirs "$$build_root/vendor" >/dev/null; \
	tar -C "$$build_root" -czf \
		"$$outdir_abs/$(NAME)-$(VERSION)-vendor.tar.gz" vendor; \
	rpmbuild -bs \
		--define "_sourcedir $$outdir_abs" \
		--define "_srcrpmdir $$outdir_abs" \
		"$(SPEC)"
