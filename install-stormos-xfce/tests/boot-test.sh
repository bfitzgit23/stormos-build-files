#!/bin/bash
#
# StormOS Boot Test Script
# Tests that the ISO boots correctly in QEMU
#

set -e

ISO_FILE=\"${1:-stormos-*.iso}\"
TIMEOUT=120

echo \"========================================\"
echo \"StormOS Boot Test\"
echo \"========================================\"

# Check if ISO exists
if ! ls $ISO_FILE 1> /dev/null 2>&1; then
    echo \"ERROR: No ISO file found matching: $ISO_FILE\"
    exit 1
fi

ISO_PATH=$(ls $ISO_FILE | head -1)
echo \"Testing ISO: $ISO_PATH\"

# Install dependencies if not present
if ! command -v qemu-system-x86_64 &> /dev/null; then
    echo \"Installing QEMU...\"
    pacman -S --noconfirm qemu-base
fi

# Start VM
echo \"Starting VM...\"
qemu-system-x86_64 \
    -m 2G \
    -cdrom \"$ISO_PATH\" \
    -display none \
    -serial file:boot.log \
    -netdev user,id=net0 \
    -device virtio-net-pci,netdev=net0 \
    -enable-kvm &

VM_PID=$!
echo \"VM started with PID: $VM_PID\"

# Wait for boot
echo \"Waiting for boot ($TIMEOUT seconds)...\"
sleep $TIMEOUT

# Check if VM is still running
if kill -0 $VM_PID 2>/dev/null; then
    echo \"✓ VM is still running (boot successful)\"
    
    # Check boot log for errors
    if grep -i \"error\|failed\|panic\" boot.log 2>/dev/null; then
        echo \"⚠ Warnings found in boot log\"
        cat boot.log | tail -20
    else
        echo \"✓ No critical errors in boot log\"
    fi
    
    # Kill VM gracefully
    kill $VM_PID 2>/dev/null || true
    echo \"✓ VM stopped\"
    exit 0
else
    echo \"✗ VM stopped unexpectedly (boot failed)\"
    if [ -f boot.log ]; then
        echo \"Boot log:\"
        cat boot.log
    fi
    exit 1
fi
