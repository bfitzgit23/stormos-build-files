# Dockerfile — build the StormOS XFCE ISO in a clean Arch container.
#
#   docker build -t stormos-builder <path-to>/install-stormos-xfce
#   docker run --privileged --rm \
#       -v "$PWD/out:/out" \
#       -v stormos-pacman-cache:/var/cache/pacman/pkg \
#       stormos-builder
#
# The ISO (and sha256 checksums) land in the mounted /out directory.
# --privileged is required, not optional: mkarchiso installs packages into a
# chroot and mounts proc/sys/dev inside it, which needs CAP_SYS_ADMIN.
#
# Speed notes:
# - Packages downloaded while building the image are kept in a BuildKit cache
#   mount, so rebuilding the image usually costs nothing in download time.
# - The stormos-pacman-cache named volume persists the packages mkarchiso
#   downloads, so a second ISO run costs near-zero download time and the
#   remaining time is the unavoidable squashfs/m_xorriso crunch.
FROM archlinux:latest

RUN --mount=type=cache,sharing=locked,target=/var/cache/pacman/pkg \
    pacman-key --init && pacman -Syu --noconfirm archiso grub syslinux

COPY . /profile

WORKDIR /profile

# /out and /work are the mkarchiso output and work directories; /out is the
# interesting one and is normally bind-mounted at run time.
RUN mkdir -p /out /work && chmod 777 /out /work

ENTRYPOINT ["mkarchiso", "-v", "-w", "/work", "-o", "/out", "/profile"]
