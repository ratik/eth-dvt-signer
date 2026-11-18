# The TEE image's build and test tools (integration/tee/README.md): mkosi and the systemd tools
# it runs (repart, ukify), GRUB (the image's boot loader, built by `qemu.sh build`), QEMU with
# OVMF and swtpm, the AmdSev OVMF and sev-snp-measure (SEV-SNP), what the harness inspects disks with, and Go for go-tpm-tools' gotpm (the
# version its go.mod names, from trixie-backports). Every
# package comes from one Debian snapshot (SNAPSHOT), so the tools are the same on every build
# (plain HTTP: the slim image has no CA roots yet, and apt checks the archive signatures).
ARG BASE
FROM ${BASE}
ARG SNAPSHOT
ARG MKOSI_VERSION
ARG GO_PACKAGE
ARG OVMF_AMDSEV_URL
ARG OVMF_AMDSEV_DEB_SHA256
ARG OVMF_AMDSEV_SHA256
ARG SNP_MEASURE_URL
ARG SNP_MEASURE_SHA256
RUN rm -f /etc/apt/sources.list.d/* && \
	printf 'Types: deb\nURIs: http://snapshot.debian.org/archive/debian/%s\nSuites: trixie trixie-updates trixie-backports\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\nCheck-Valid-Until: no\n\nTypes: deb\nURIs: http://snapshot.debian.org/archive/debian-security/%s\nSuites: trixie-security\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\nCheck-Valid-Until: no\n' \
		"$SNAPSHOT" "$SNAPSHOT" >/etc/apt/sources.list.d/snapshot.sources && \
	printf 'Acquire::Retries "5";\nAcquire::http::Timeout "60";\n' >/etc/apt/apt.conf.d/80retries && \
	apt-get update && \
	DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
		mkosi=${MKOSI_VERSION} apt dpkg debian-archive-keyring gnupg ca-certificates \
		systemd systemd-repart systemd-ukify systemd-boot-efi udev kmod cpio zstd xz-utils \
		erofs-utils dosfstools mtools cryptsetup-bin e2fsprogs fdisk util-linux \
		qemu-system-x86 qemu-utils ovmf swtpm swtpm-tools grub-efi-amd64-bin grub-common \
		python3 python3-pefile python3-cryptography curl openssh-client openssl git ${GO_PACKAGE} && \
	rm -rf /var/lib/apt/lists/*
# SEV-SNP: the AmdSev OVMF (/usr/share/ovmf-amdsev/OVMF.amdsev.fd) and sev-snp-measure
# (/opt/sev-snp-measure, run as /usr/local/bin/sev-snp-measure), each checked against
# its SHA-256 (versions.env).
RUN set -e; tmp="$(mktemp -d)"; \
	curl -sfL --retry 5 -o "$tmp/ovmf.deb" "$OVMF_AMDSEV_URL"; \
	echo "$OVMF_AMDSEV_DEB_SHA256  $tmp/ovmf.deb" | sha256sum -c -; \
	dpkg-deb -x "$tmp/ovmf.deb" "$tmp/ovmf"; \
	echo "$OVMF_AMDSEV_SHA256  $tmp/ovmf/usr/share/ovmf/OVMF.amdsev.fd" | sha256sum -c -; \
	install -D -m 0644 "$tmp/ovmf/usr/share/ovmf/OVMF.amdsev.fd" /usr/share/ovmf-amdsev/OVMF.amdsev.fd; \
	curl -sfL --retry 5 -o "$tmp/measure.whl" "$SNP_MEASURE_URL"; \
	echo "$SNP_MEASURE_SHA256  $tmp/measure.whl" | sha256sum -c -; \
	python3 -m zipfile -e "$tmp/measure.whl" /opt/sev-snp-measure; \
	printf '#!/bin/sh\nPYTHONPATH=/opt/sev-snp-measure exec python3 -I -c "import sys; sys.path.insert(0, \\"/opt/sev-snp-measure\\"); from sevsnpmeasure.cli import main; sys.exit(main())" "$@"\n' \
		>/usr/local/bin/sev-snp-measure; \
	chmod 0755 /usr/local/bin/sev-snp-measure; \
	sev-snp-measure --help >/dev/null; \
	rm -rf "$tmp"
