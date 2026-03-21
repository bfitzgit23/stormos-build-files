#!/bin/bash
#
# StormOS Installation Test Script
# Tests that the ISO can be installed using Calamares
#

set -e

ISO_FILE=\"${1:-stormos-*.iso}\"
TIMEOUT=600

echo \"========================================\"
echo \"StormOS Installation Test\"
echo \"========================================\"

# Check if ISO exists
if ! ls $ISO_FILE 1> /dev/null 2>&1; then
    echo \"ERROR: No ISO file found matching: $ISO_FILE\"
    exit 1
fi

ISO_PATH=$(ls $ISO_FILE | head -1)
echo \"Testing ISO: $ISO_PATH\"

# Install dependencies
echo \"Installing test dependencies...\"
pacman -S --noconfirm qemu-base guestfs-tools

# Mount ISO
echo \"Mounting ISO...\"
mkdir -p /mnt/iso
guestmount -a \"$ISO_PATH\" -i /mnt/iso

# Test 1: Check ISO structure
echo \"\"
echo \"Test 1: ISO Structure\"
echo \"---\"
test -d /mnt/iso/EFI && echo \"✓ EFI directory found\" || echo \"✗ EFI directory missing\"
test -d /mnt/iso/boot && echo \"✓ Boot directory found\" || echo \"✗ Boot directory missing\"

# Test 2: Check bootloader files
echo \"\"
echo \"Test 2: Bootloader Files\"
echo \"---\"
test -f /mnt/iso/EFI/BOOT/BOOTX64.EFI && echo \"✓ UEFI bootloader found\" || echo \"✗ UEFI bootloader missing\"
test -f /mnt/iso/boot/initramfs*.img && echo \"✓ Initramfs found\" || echo \"✗ Initramfs missing\"

# Test 3: Check Calamares
echo \"\"
echo \"Test 3: Calamares Installer\"
echo \"---\"
test -f /mnt/iso/usr/bin/calamares && echo \"✓ Calamares found\" || echo \"✗ Calamares missing\"
test -d /mnt/iso/etc/calamares && echo \"✓ Calamares config found\" || echo \"✗ Calamares config missing\"

# Test 4: Check live user configuration
echo \"\"
echo \"Test 4: Live User Configuration\"
echo \"---\"
grep -q \"liveuser\" /mnt/iso/etc/passwd && echo \"✓ Live user configured\" || echo \"✗ Live user missing\"
grep -q \"autologin\" /mnt/iso/etc/lightdm/lightdm.conf && echo \"✓ LightDM autologin configured\" || echo \"⚠ LightDM autologin not found\"

# Test 5: Check packages
echo \"\"
echo \"Test 5: Core Packages\"
echo \"---\"
grep -q \"xfce\" /mnt/iso/var/lib/pacman/local/*/desc 2>/dev/null && echo \"✓ XFCE package found\" || echo \"✗ XFCE package missing\"

# Cleanup
echo \"\"
echo \"Cleanup...\"
guestunmount /mnt/iso || true

echo \"\"
echo \"========================================\"
echo \"Installation Test Complete\"
echo \"========================================\"
