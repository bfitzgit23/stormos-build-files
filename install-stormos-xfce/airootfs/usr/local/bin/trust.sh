f=FILE; gio set -t string $f metadata::xfce-exe-checksum "$(sha256sum $f | awk '{print $1}')"
