# Building the stormos-react-desktop package

## TL;DR

    ./build-package.sh          # builds source tarball + runs makepkg -scf
    ./build-package.sh -i       # same, then installs with pacman
    ./build-package.sh --src-only   # just the source tarball

## Why plain `makepkg -scf` failed before

makepkg builds from the source tarball declared in `source=()`, not from the
project directory you are standing in. Two failure modes came from that:

1. `cannot start 'dist/'` — the old PKGBUILD ran `build()` and `package()`
   in `$srcdir` itself, where there was no project, so no `dist/` was ever
   produced. (The PKGBUILD is fixed now: it cds into
   `$srcdir/$pkgname`.)
2. `src/stormos-react-desktop: No such file or directory` — with the fixed
   PKGBUILD, makepkg still needs the source tarball
   `stormos-react-desktop-0.2.0.tar.gz` to exist next to the PKGBUILD so it
   can extract `src/stormos-react-desktop-0.2.0/`. Running makepkg without
   that tarball gives exactly that error.

`build-package.sh` handles the whole flow: it builds the React bundle,
creates a correctly-laid-out source tarball (top-level directory
`stormos-react-desktop-<ver>/`, no `node_modules` or build artifacts), then
hands off to `makepkg`.

## Manual equivalent

    # from the project directory
    npm install --no-audit --no-fund --ignore-scripts
    npm run build
    # stage the tree as stormos-react-desktop-<ver>/ and tar it up:
    #   (top-level dir name must match $pkgname-$pkgver in the PKGBUILD)
    tar -czf stormos-react-desktop-0.2.0.tar.gz \
        --transform 's,^\.,stormos-react-desktop-0.2.0,' \
        --exclude='./node_modules' --exclude='./dist' \
        --exclude='./react-desktop' --exclude='./src' --exclude='./pkg' \
        --exclude='./*.tar.gz' --exclude='./*.pkg.tar.zst' \
        .
    makepkg -scif

## Installing the result

    sudo pacman -U stormos-react-desktop-0.2.0-<rel>-x86_64.pkg.tar.zst

## Using it on the ISO

The XFCE profile in `stormos-build-files` already ships the built runtime
(`usr/share/stormos-shell`, `/usr/bin/stormos-*`, `/etc/xdg/labwc/*`) plus
the runtime packages in `packages.x86_64`, and lightdm defaults to the
StormOS session. This package is for installed systems and for building the
ISO from the repo instead of airootfs copies.
