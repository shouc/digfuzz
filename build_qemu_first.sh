#!/bin/sh
#
# american fuzzy lop++ - QEMU build script
# --------------------------------------
#
# Originally written by Andrew Griffiths <agriffiths@google.com> and
#                       Michal Zalewski
#
# TCG instrumentation and block chaining support by Andrea Biondo
#                                    <andrea.biondo965@gmail.com>
#
# QEMU 5+ port, TCG thread-safety, CompareCoverage and NeverZero
# counters by Andrea Fioraldi <andreafioraldi@gmail.com>
#
# Copyright 2015, 2016, 2017 Google Inc. All rights reserved.
# Copyright 2019-2020 AFLplusplus Project. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   https://www.apache.org/licenses/LICENSE-2.0
#
# This script downloads, patches, and builds a version of QEMU with
# minor tweaks to allow non-instrumented binaries to be run under
# afl-fuzz. 
#
# The modifications reside in patches/*. The standalone QEMU binary
# will be written to ../afl-qemu-trace.
#


cd $1 || exit 1

echo "[*] Making sure imported headers matches"
cp "../afl_shared/config.h" "./qemuafl/imported/" || exit 1
cp "../afl_shared/cmplog.h" "./qemuafl/imported/" || exit 1
cp "../afl_shared/snapshot-inl.h" "./qemuafl/imported/" || exit 1
cp "../afl_shared/types.h" "./qemuafl/imported/" || exit 1

if [ -n "$HOST" ]; then
  echo "[+] Configuring host architecture to $HOST..."
  CROSS_PREFIX=$HOST-
else
  CROSS_PREFIX=
fi

echo "[*] Configuring QEMU for $CPU_TARGET..."

ORIG_CPU_TARGET="$CPU_TARGET"

if [ "$ORIG_CPU_TARGET" = "" ]; then
  CPU_TARGET="`uname -m`"
  test "$CPU_TARGET" = "i686" && CPU_TARGET="i386"
  test "$CPU_TARGET" = "arm64v8" && CPU_TARGET="aarch64"
  case "$CPU_TARGET" in 
    *arm*)
      CPU_TARGET="arm"
      ;;
  esac
fi

echo "Building for CPU target $CPU_TARGET"

# --enable-pie seems to give a couple of exec's a second performance
# improvement, much to my surprise. Not sure how universal this is..
QEMU_CONF_FLAGS=" \
  --audio-drv-list= \
  --disable-blobs \
  --disable-bochs \
  --disable-brlapi \
  --disable-bsd-user \
  --disable-bzip2 \
  --disable-cap-ng \
  --disable-cloop \
  --disable-curl \
  --disable-curses \
  --disable-dmg \
  --disable-fdt \
  --disable-gcrypt \
  --disable-glusterfs \
  --disable-gnutls \
  --disable-gtk \
  --disable-guest-agent \
  --disable-iconv \
  --disable-libiscsi \
  --disable-libnfs \
  --disable-libssh \
  --disable-libusb \
  --disable-linux-aio \
  --disable-live-block-migration \
  --disable-lzo \
  --disable-nettle \
  --disable-numa \
  --disable-opengl \
  --disable-parallels \
  --disable-plugins \
  --disable-qcow1 \
  --disable-qed \
  --disable-rbd \
  --disable-rdma \
  --disable-replication \
  --disable-sdl \
  --disable-seccomp \
  --disable-sheepdog \
  --disable-smartcard \
  --disable-snappy \
  --disable-spice \
  --disable-system \
  --disable-tools \
  --disable-tpm \
  --disable-usb-redir \
  --disable-vde \
  --disable-vdi \
  --disable-vhost-crypto \
  --disable-vhost-kernel \
  --disable-vhost-net \
  --disable-vhost-scsi \
  --disable-vhost-user \
  --disable-vhost-vdpa \
  --disable-vhost-vsock \
  --disable-virglrenderer \
  --disable-virtfs \
  --disable-vnc \
  --disable-vnc-jpeg \
  --disable-vnc-png \
  --disable-vnc-sasl \
  --disable-vte \
  --disable-vvfat \
  --disable-xen \
  --disable-xen-pci-passthrough \
  --disable-xfsctl \
  --target-list="${CPU_TARGET}-linux-user" \
  --without-default-devices \
  "

if [ -n "${CROSS_PREFIX}" ]; then

  QEMU_CONF_FLAGS="$QEMU_CONF_FLAGS --cross-prefix=$CROSS_PREFIX"

fi

if [ "$STATIC" = "1" ]; then

  echo Building STATIC binary

  # static PIE causes https://github.com/AFLplusplus/AFLplusplus/issues/892
  QEMU_CONF_FLAGS="$QEMU_CONF_FLAGS \
    --static --disable-pie \
    --extra-cflags=-DAFL_QEMU_STATIC_BUILD=1 \
    "

else

  QEMU_CONF_FLAGS="${QEMU_CONF_FLAGS} --enable-pie "

fi

if [ "$DEBUG" = "1" ]; then

  echo Building DEBUG binary

  # --enable-gcov might go here but incurs a mesonbuild error on meson
  # versions prior to 0.56:
  # https://github.com/qemu/meson/commit/903d5dd8a7dc1d6f8bef79e66d6ebc07c
  QEMU_CONF_FLAGS="$QEMU_CONF_FLAGS \
    --disable-strip \
    --enable-debug \
    --enable-debug-info \
    --enable-debug-mutex \
    --enable-debug-stack-usage \
    --enable-debug-tcg \
    --enable-qom-cast-debug \
    --enable-werror \
    "

else

  QEMU_CONF_FLAGS="$QEMU_CONF_FLAGS \
    --disable-debug-info \
    --disable-debug-mutex \
    --disable-debug-tcg \
    --disable-qom-cast-debug \
    --disable-stack-protector \
    --disable-werror \
    "

fi

if [ "$PROFILING" = "1" ]; then

  echo Building PROFILED binary

  QEMU_CONF_FLAGS="$QEMU_CONF_FLAGS \
    --enable-gprof \
    --enable-profiler \
    "

fi

# shellcheck disable=SC2086
./configure $QEMU_CONF_FLAGS || exit 1

echo "[+] Configuration complete."

echo "[*] Attempting to build QEMU (fingers crossed!)..."

make -j `nproc` || exit 1

echo "[+] Build process successful!"

echo "[*] Copying binary..."

cp -f "build/${CPU_TARGET}-linux-user/qemu-${CPU_TARGET}" "../afl-qemu-trace" || exit 1

cd ..
ls -l ../afl-qemu-trace || exit 1

echo "[+] Successfully created '../afl-qemu-trace'."
