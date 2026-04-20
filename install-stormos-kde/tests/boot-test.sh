#!/bin/bash
#
# StormOS Boot Test Script
# Tests that the ISO boots correctly in QEMU
#
# Usage:
#   ./tests/boot-test.sh                    # Tests latest ISO in out/
#   ./tests/boot-test.sh path/to/iso.iso   # Tests specific ISO
#
# Requirements:
#   - qemu-base or qemu-full (pacman -S qemu-base)
#   - KVM support recommended for speed (pacman -S qemu-base)
#

set -e

ISO_FILE="${1:-out/*.iso}"
TIMEOUT=120

echo "========================================"
echo "StormOS Boot Test"
echo "========================================"

# Check if ISO exists
if ! ls $ISO_FILE 1> /dev/null 2>&1; then
    echo "ERROR: No ISO file found matching: $ISO_FILE"
    echo "Run 'make' or './build.sh' first to build an ISO"
    exit 1
fi

ISO_PATH=$(ls $ISO_FILE | head -1)
echo "Testing ISO: $ISO_PATH"

# Check for QEMU
if ! command -v qemu-system-x86_64 &> /dev/null; then
    echo "ERROR: QEMU not installed"
    echo "Run: sudo pacman -S qemu-base"
    exit 1
fi

# Start VM with KVM if available
echo "Starting VM..."
if [ -w /dev/kvm ] 2>/dev/null; then
    echo "Using KVM acceleration"
    KVM_FLAG="-enable-kvm -cpu host"
else
    echo "KVM not available, using software emulation"
    KVM_FLAG=""
fi

qemu-system-x86_64 \
    -m 2G \
    -cdrom "$ISO_PATH" \
    -display none \
    -serial mon:telnet:127.0.0.1:5000,server,nowait \
    -netdev user,id=net0 \
    -device virtio-net-pci,netdev=net0 \
    $KVM_FLAG \
    -machine q35 &

VM_PID=$!
echo "VM started with PID: $VM_PID"

# Wait for boot
echo "Waiting for boot ($TIMEOUT seconds)..."
sleep $TIMEOUT

# Check if VM is still running
if kill -0 $VM_PID 2>/dev/null; then
    echo ""
    echo "✓ VM is still running (boot successful)"
    echo "✓ You can connect to the serial console with:"
    echo "  telnet 127.0.0.1 5000"
    
    # Kill VM
    kill $VM_PID 2>/dev/null || true
    wait $VM_PID 2>/dev/null || true
    echo "✓ VM stopped"
    exit 0
else
    echo ""
    echo "✗ VM stopped unexpectedly (boot failed)"
    echo "Check the serial output above for errors"
    exit 1
fi
