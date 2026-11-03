# Dockerfile — build the StormOS XFCE ISO in a clean Arch container.
#
#   docker build -t stormos-builder <path-to>/install-stormos-xfce
#   docker run --privileged --rm -v "$PWD/out:/out" stormos-builder
#
# The ISO (and sha256 checksums) land in the mounted /out directory.
# --privileged is required, not optional: mkarchiso installs packages into a
# chroot and mounts proc/sys/dev inside it, which needs CAP_SYS_ADMIN.
FROM archlinux:latest

RUN pacman-key --init && pacman -Syu --noconfirm archiso grub syslinux && rm -rf /var/cache/pacman/pkg

COPY . /profile

WORKDIR /profile

# /out and /work are the mkarchiso output and work directories; /out is the
# interesting one and is normally bind-mounted at run time.
RUN mkdir -p /out /work && chmod 777 /out /work

ENTRYPOINT ["mkarchiso", "-v", "-w", "/work", "-o", "/out", "/profile"]
