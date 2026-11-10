# The TEE image's build and test tools (integration/tee/README.md): mkosi and the systemd tools
# it runs (repart, ukify), QEMU with OVMF, and what the harness inspects disks with. Every
# package comes from one Debian snapshot (SNAPSHOT), so the tools are the same on every build
# (plain HTTP: the slim image has no CA roots yet, and apt checks the archive signatures).
ARG BASE
FROM ${BASE}
ARG SNAPSHOT
ARG MKOSI_VERSION
RUN rm -f /etc/apt/sources.list.d/* && \
	printf 'Types: deb\nURIs: http://snapshot.debian.org/archive/debian/%s\nSuites: trixie trixie-updates\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\nCheck-Valid-Until: no\n\nTypes: deb\nURIs: http://snapshot.debian.org/archive/debian-security/%s\nSuites: trixie-security\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\nCheck-Valid-Until: no\n' \
		"$SNAPSHOT" "$SNAPSHOT" >/etc/apt/sources.list.d/snapshot.sources && \
	printf 'Acquire::Retries "5";\nAcquire::http::Timeout "60";\n' >/etc/apt/apt.conf.d/80retries && \
	apt-get update && \
	DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
		mkosi=${MKOSI_VERSION} apt dpkg debian-archive-keyring gnupg ca-certificates \
		systemd systemd-repart systemd-ukify systemd-boot-efi udev kmod cpio zstd xz-utils \
		erofs-utils dosfstools mtools cryptsetup-bin e2fsprogs fdisk util-linux \
		qemu-system-x86 qemu-utils ovmf \
		python3 python3-pefile curl openssh-client && \
	rm -rf /var/lib/apt/lists/*
