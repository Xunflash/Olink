#!/bin/sh
# Build the release AppImage (dist/Olink-<version>-x86_64.AppImage).
#
# Rust embeds the source paths of every crate it compiles (for panic
# messages), and those live under your home directory, so a plain build
# carries your username. --remap-path-prefix rewrites $HOME to "~"; the check
# at the end refuses to finish if the home path is still in the binary.
set -eu
cd "$(dirname "$0")/.."

export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$HOME=~"
NO_STRIP=true GSTREAMER_INCLUDE_BAD_PLUGINS=1 npm run tauri build -- --bundles appimage

bin=src-tauri/target/release/olink
if grep -qaF "$HOME" "$bin"; then
  echo "error: $bin still contains $HOME; not publishing it" >&2
  exit 1
fi

version=$(sed -n 's/^version = "\(.*\)"/\1/p' src-tauri/Cargo.toml | head -1)
mkdir -p dist
cp src-tauri/target/release/bundle/appimage/*_"$version"_amd64.AppImage "dist/Olink-$version-x86_64.AppImage"
(cd dist && sha256sum "Olink-$version-x86_64.AppImage" > "Olink-$version-x86_64.AppImage.sha256")
echo "built dist/Olink-$version-x86_64.AppImage"
