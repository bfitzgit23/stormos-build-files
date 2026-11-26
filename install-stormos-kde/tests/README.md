# StormOS Testing Scripts

These scripts help you test StormOS ISO builds locally before releasing.

## Requirements

Install required packages:

```bash
sudo pacman -S qemu-base guestfs-tools
```

Optionally enable KVM for faster testing:

```bash
sudo pacman -S qemu-base
sudo modprobe kvm-intel  # Intel CPUs
sudo modprobe kvm-amd    # AMD CPUs
sudo chmod 666 /dev/kvm   # Allow non-root access
```

## Test Scripts

### Boot Test (`boot-test.sh`)

Tests that the ISO boots correctly in QEMU.

```bash
# Test latest ISO in out/
./tests/boot-test.sh

# Test specific ISO
./tests/boot-test.sh path/to/stormos.iso
```

What it does:
- Starts QEMU with the ISO
- Waits 120 seconds for boot
- Checks if system stays alive
- Reports success/failure

### Installation Test (`install-test.sh`)

Validates ISO structure and contents without installing.

```bash
# Test latest ISO in out/
./tests/install-test.sh

# Test specific ISO
./tests/install-test.sh path/to/stormos.iso
```

What it checks:
- EFI bootloader files
- Kernel and initramfs
- Calamares installer
- Live user configuration
- Plymouth boot splash
- Root filesystem

## Full Testing Workflow

```bash
# 1. Build the ISO
./build.sh -v

# 2. Run installation test (quick)
./tests/install-test.sh

# 3. Run boot test (slower)
./tests/boot-test.sh

# 4. If boot test passes, test in VirtualBox/VMware/real hardware
```

## Troubleshooting

### "KVM not available"
Enable KVM in BIOS or run without it (slower):

```bash
# The script handles this automatically, but for manual QEMU:
qemu-system-x86_64 ...        # Without -enable-kvm
```

### "Failed to mount ISO"
Run as root (guestfs-tools requires root):

```bash
sudo ./tests/install-test.sh
```

### QEMU display issues
Use VNC or serial console:

```bash
# VNC (port 5900)
qemu-system-x86_64 -vnc :0 -cdrom stormos.iso ...

# Serial console (as used by boot-test.sh)
telnet 127.0.0.1 5000
```
