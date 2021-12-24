cd $1

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
echo "[+] Configuration complete."

echo "[*] Attempting to build QEMU (fingers crossed!)..."
make clean
make -j `nproc` || exit 1

echo "[+] Build process successful!"

echo "[*] Copying binary..."
cp -f "build/${CPU_TARGET}-linux-user/qemu-${CPU_TARGET}" "../afl-qemu-trace" || exit 1

cd ../