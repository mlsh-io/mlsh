FROM fedora:43

RUN dnf install -y --setopt=install_weak_deps=False \
        mkosi \
        dnf5 \
        dnf5-plugins \
        distribution-gpg-keys \
        e2fsprogs \
        btrfs-progs \
        xfsprogs \
        dosfstools \
        mtools \
        squashfs-tools \
        erofs-utils \
        gdisk \
        util-linux \
        cpio \
        tar \
        xz \
        zstd \
        kmod \
        systemd \
        systemd-udev \
        systemd-boot-unsigned \
        systemd-container \
        systemd-ukify \
        sbsigntools \
        virt-firmware \
        grub2-tools \
        grub2-efi-aa64 \
        grub2-efi-aa64-modules \
        shim-aa64 \
        openssl \
        ca-certificates \
        sudo \
    && dnf clean all

WORKDIR /work
ENTRYPOINT ["/work/build.sh"]
