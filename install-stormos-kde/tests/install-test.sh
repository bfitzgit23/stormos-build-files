#!/bin/bash
#
# StormOS Installation Test Script
# Tests that the ISO has correct structure and can potentially be installed
#
# Usage:
#   ./tests/install-test.sh                    # Tests latest ISO in out/
#   ./tests/install-test.sh path/to/iso.iso    # Tests specific ISO
#
# Requirements:
#   - guestfs-tools (pacman -S guestfs-tools)
#
# Note: This script does NOT perform a full installation.
# It only validates the ISO structure and contents.
#

set -e

ISO_FILE="${1:-out/*.iso}"

echo "========================================"
echo "StormOS Installation Test"
echo "========================================"

# Check if ISO exists
if ! ls $ISO_FILE 1> /dev/null 2>&1; then
    echo "ERROR: No ISO file found matching: $ISO_FILE"
    echo "Run 'make' or './build.sh' first to build an ISO"
    exit 1
fi

ISO_PATH=$(ls $ISO_FILE | head -1)
echo "Testing ISO: $ISO_PATH"

# Check for guestmount
if ! command -v guestmount &> /dev/null; then
    echo "ERROR: guestfs-tools not installed"
    echo "Run: sudo pacman -S guestfs-tools"
    exit 1
fi

# Mount ISO
echo ""
echo "Mounting ISO..."
mkdir -p /tmp/stormos-test
if guestmount -a "$ISO_PATH" -i /tmp/stormos-test 2>/dev/null; then
    echo "✓ ISO mounted successfully"
else
    echo "✗ Failed to mount ISO"
    exit 1
fi

TEST_DIR="/tmp/stormos-test"
PASS=0
FAIL=0

echo ""
echo "========================================"
echo "Running Tests"
echo "========================================"

# Test 1: Check ISO structure
echo ""
echo "Test 1: ISO Structure"
echo "---"
if [ -d "$TEST_DIR/EFI" ]; then
    echo "✓ EFI directory found"
    ((PASS++))
else
    echo "✗ EFI directory missing"
    ((FAIL++))
fi

if [ -d "$TEST_DIR/boot" ]; then
    echo "✓ Boot directory found"
    ((PASS++))
else
    echo "✗ Boot directory missing"
    ((FAIL++))
fi

# Test 2: Check bootloader files
echo ""
echo "Test 2: Bootloader Files"
echo "---"
if [ -f "$TEST_DIR/EFI/BOOT/BOOTX64.EFI" ]; then
    echo "✓ UEFI bootloader found"
    ((PASS++))
else
    echo "✗ UEFI bootloader missing"
    ((FAIL++))
fi

if ls $TEST_DIR/boot/initramfs*.img 1> /dev/null 2>&1; then
    echo "✓ Initramfs found"
    ((PASS++))
else
    echo "✗ Initramfs missing"
    ((FAIL++))
fi

if ls $TEST_DIR/boot/vmlinuz* 1> /dev/null 2>&1; then
    echo "✓ Kernel found"
    ((PASS++))
else
    echo "✗ Kernel missing"
    ((FAIL++))
fi

# Test 3: Check Calamares
echo ""
echo "Test 3: Calamares Installer"
echo "---"
if [ -f "$TEST_DIR/usr/bin/calamares" ]; then
    echo "✓ Calamares found"
    ((PASS++))
else
    echo "✗ Calamares missing"
    ((FAIL++))
fi

if [ -d "$TEST_DIR/etc/calamares" ]; then
    echo "✓ Calamares config found"
    ((PASS++))
else
    echo "✗ Calamares config missing"
    ((FAIL++))
fi

# Test 4: Check live user configuration
echo ""
echo "Test 4: Live User Configuration"
echo "---"
if grep -q "liveuser" $TEST_DIR/etc/passwd 2>/dev/null; then
    echo "✓ Live user configured"
    ((PASS++))
else
    echo "✗ Live user missing"
    ((FAIL++))
fi

if [ -f "$TEST_DIR/etc/lightdm/lightdm.conf" ]; then
    echo "✓ LightDM configured"
    ((PASS++))
else
    echo "✗ LightDM missing"
    ((FAIL++))
fi

# Test 5: Check Plymouth (boot splash)
echo ""
echo "Test 5: Boot Splash (Plymouth)"
echo "---"
if [ -d "$TEST_DIR/usr/share/plymouth" ]; then
    echo "✓ Plymouth found"
    ((PASS++))
else
    echo "✗ Plymouth missing"
    ((FAIL++))
fi

# Test 6: Check root filesystem
echo ""
echo "Test 6: Root Filesystem"
echo "---"
if [ -f "$TEST_DIR/root/.automated_script ] 2>/dev/null || [ -f "$TEST_DIR/airootfs.sfs" ]; then
    echo "✓ Compressed root filesystem found"
    ((PASS++))
else
    echo "✗ Compressed root filesystem missing"
    ((FAIL++))
fi

# Cleanup
echo ""
echo "========================================"
echo "Cleanup"
echo "========================================"
guestunmount /tmp/stormos-test 2>/dev/null || true
rmdir /tmp/stormos-test 2>/dev/null || true
echo "✓ ISO unmounted"

# Summary
echo ""
echo "========================================"
echo "Test Results"
echo "========================================"
echo "Passed: $PASS"
echo "Failed: $FAIL"
echo ""

if [ $FAIL -eq 0 ]; then
    echo "✓ All tests passed!"
    echo "This ISO is ready for manual installation testing."
    exit 0
else
    echo "✗ Some tests failed."
    echo "Please review the issues above."
    exit 1
fi
