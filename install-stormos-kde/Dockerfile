# Dockerfile — build the StormOS KDE ISO in a clean Arch container.
#
#   docker build -t stormos-builder <path-to>/install-stormos-kde
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

# A Windows git checkout materialises git symlinks as one-line text files.
# Restore real symlinks in the build context; otherwise systemd's *.wants
# entries and /etc/localtime are broken in the live image.
SHELL ["/bin/bash", "-c"]

# Normalise CRLF from a Windows checkout. grep -I skips binary payloads such as
# PNGs; every remaining text file gets LF-only endings before mkarchiso reads it.
RUN find /profile -type f -print0 \
      | while IFS= read -r -d '' file; do \
          if LC_ALL=C grep -Iq . "$file" 2>/dev/null; then \
            sed -i 's/\r$//' "$file"; \
          fi; \
        done

RUN find /profile/airootfs/etc/systemd/system -type d -name '*.wants' -print0 \
      | while IFS= read -r -d '' dir; do \
          for link in "$dir"/*; do \
            [ -f "$link" ] || continue; \
            target=$(cat "$link"); \
            case "$target" in /*) ln -sfn "$target" "$link" ;; esac; \
          done; \
        done \
    && if [ -f /profile/airootfs/etc/localtime ]; then \
         target=$(cat /profile/airootfs/etc/localtime); \
         case "$target" in /*) ln -sfn "$target" /profile/airootfs/etc/localtime ;; esac; \
       fi

WORKDIR /profile

# /out and /work are the mkarchiso output and work directories; /out is the
# interesting one and is normally bind-mounted at run time.
RUN mkdir -p /out /work && chmod 777 /out /work

ENTRYPOINT ["mkarchiso", "-v", "-w", "/work", "-o", "/out", "/profile"]
