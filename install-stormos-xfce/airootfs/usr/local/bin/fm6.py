import sys
import os
import shutil
import subprocess
import threading
from pathlib import Path
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QToolBar, QStatusBar, QLineEdit, QLabel, 
                            QMessageBox, QInputDialog, QFileDialog, QMenu,
                            QAbstractItemView, QHeaderView, QTabWidget,
                            QToolButton, QComboBox, QStyleFactory, QDialog,
                            QDialogButtonBox, QFormLayout, QCheckBox, QGroupBox,
                            QFileSystemModel, QAction, QSizePolicy, QMenuBar,
                            QListWidget, QListWidgetItem, QProgressDialog,
                            QProgressBar, QDockWidget, QFrame, QTreeView, QListView, QSplitter, QSlider)
from PyQt5.QtCore import QDir, QModelIndex, Qt, QSortFilterProxyModel, pyqtSignal, QSize, QThread, QMimeData, QTimer, QSettings, QUrl
from PyQt5.QtGui import QIcon, QKeySequence, QPalette, QColor, QFont, QPixmap, QDrag, QPainter
import platform
import psutil
import getpass
import time
import json
import stat

class SettingsManager:
    """Manages application settings persistence"""
    def __init__(self):
        self.settings = QSettings("ThunarClone", "ThunarClone")
        
    def save_window_state(self, window):
        """Save window geometry and state"""
        self.settings.setValue("geometry", window.saveGeometry())
        self.settings.setValue("windowState", window.saveState())
        self.settings.setValue("iconSize", window.icon_size)
        
    def load_window_state(self, window):
        """Load window geometry and state"""
        geometry = self.settings.value("geometry")
        if geometry:
            window.restoreGeometry(geometry)
        
        state = self.settings.value("windowState")
        if state:
            window.restoreState(state)
            
        # Load icon size
        icon_size = self.settings.value("iconSize", 32, type=int)
        window.icon_size = icon_size
        window.update_icon_size(icon_size)

class FileOperationThread(QThread):
    progress = pyqtSignal(int)
    message = pyqtSignal(str)
    finished_success = pyqtSignal()
    error_occurred = pyqtSignal(str)
    
    def __init__(self, operation_type, source_paths, destination_dir, parent=None):
        super().__init__(parent)
        self.operation_type = operation_type
        self.source_paths = source_paths
        self.destination_dir = destination_dir
        self.cancelled = False
        
    def cancel(self):
        self.cancelled = True
        
    def run(self):
        try:
            total_files = self.count_total_files()
            processed_files = 0
            
            for source_path in self.source_paths:
                if self.cancelled:
                    break
                    
                dest_path = os.path.join(self.destination_dir, os.path.basename(source_path))
                
                if self.operation_type == 'copy':
                    self.copy_item(source_path, dest_path, total_files, processed_files)
                elif self.operation_type == 'move':
                    self.move_item(source_path, dest_path, total_files, processed_files)
                    
            if not self.cancelled:
                self.finished_success.emit()
                
        except Exception as e:
            self.error_occurred.emit(str(e))
            
    def count_total_files(self):
        total = 0
        for path in self.source_paths:
            if os.path.isfile(path):
                total += 1
            else:
                for root, dirs, files in os.walk(path):
                    total += len(files)
        return total
        
    def copy_item(self, src, dst, total_files, processed_files):
        if os.path.isfile(src):
            self.message.emit(f"Copying {os.path.basename(src)}")
            self.safe_copy_file(src, dst)
            processed_files += 1
            progress = int((processed_files / total_files) * 100) if total_files > 0 else 0
            self.progress.emit(progress)
        else:
            if not os.path.exists(dst):
                os.makedirs(dst)
                
            for item in os.listdir(src):
                if self.cancelled:
                    return
                src_path = os.path.join(src, item)
                dst_path = os.path.join(dst, item)
                self.copy_item(src_path, dst_path, total_files, processed_files)
                
    def move_item(self, src, dst, total_files, processed_files):
        self.message.emit(f"Moving {os.path.basename(src)}")
        self.safe_move(src, dst)
        processed_files += 1
        progress = int((processed_files / total_files) * 100) if total_files > 0 else 0
        self.progress.emit(progress)
        
    def safe_copy_file(self, src, dst):
        if os.path.exists(dst):
            base, ext = os.path.splitext(dst)
            counter = 1
            while os.path.exists(f"{base} ({counter}){ext}"):
                counter += 1
            dst = f"{base} ({counter}){ext}"
            
        shutil.copy2(src, dst)
        
    def safe_move(self, src, dst):
        if os.path.exists(dst):
            base, ext = os.path.splitext(dst)
            counter = 1
            while os.path.exists(f"{base} ({counter}){ext}"):
                counter += 1
            dst = f"{base} ({counter}){ext}"
            
        shutil.move(src, dst)

class ThumbnailGenerator:
    @staticmethod
    def generate_video_thumbnail(video_path, thumbnail_path, size=256):
        """Generate thumbnail for video using ffmpegthumbnailer"""
        try:
            cmd = [
                'ffmpegthumbnailer',
                '-i', video_path,
                '-o', thumbnail_path,
                '-s', str(size),
                '-q', '10'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            return False
            
    @staticmethod
    def generate_image_thumbnail(image_path, thumbnail_path, size=256):
        """Generate thumbnail for image"""
        try:
            pixmap = QPixmap(image_path)
            if not pixmap.isNull():
                # Scale the image to create thumbnail
                scaled_pixmap = pixmap.scaled(size, size, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                return scaled_pixmap.save(thumbnail_path)
            return False
        except Exception:
            return False

class ThumbnailFileSystemModel(QFileSystemModel):
    def __init__(self):
        super().__init__()
        self.thumbnail_cache = {}
        self.thumbnail_dir = os.path.expanduser('~/.cache/thunar-clone/thumbnails')
        os.makedirs(self.thumbnail_dir, exist_ok=True)
        
    def data(self, index, role=Qt.DisplayRole):
        # Handle thumbnails for decoration role in first column only
        if role == Qt.DecorationRole and index.column() == 0:
            file_path = self.filePath(index)
            
            # Check if we should generate thumbnail
            if self.should_generate_thumbnail(file_path):
                thumbnail = self.get_thumbnail(file_path)
                if thumbnail:
                    return thumbnail
                
        # For all other cases, use the parent implementation
        return super().data(index, role)
        
    def should_generate_thumbnail(self, file_path):
        if os.path.isdir(file_path):
            return False
            
        # Video files
        video_extensions = {'.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm', '.m4v', '.3gp'}
        # Image files
        image_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp', '.svg'}
        
        ext = os.path.splitext(file_path)[1].lower()
        return ext in video_extensions.union(image_extensions)
        
    def get_thumbnail(self, file_path):
        # Check cache first
        if file_path in self.thumbnail_cache:
            return self.thumbnail_cache[file_path]
            
        # Generate thumbnail path
        file_hash = str(hash(file_path))
        thumbnail_path = os.path.join(self.thumbnail_dir, f"{file_hash}.png")
        
        # Check if thumbnail exists and is recent
        if os.path.exists(thumbnail_path):
            file_mtime = os.path.getmtime(file_path)
            thumb_mtime = os.path.getmtime(thumbnail_path)
            
            # Use cached thumbnail if it's newer than file modification
            if thumb_mtime >= file_mtime:
                icon = QIcon(thumbnail_path)
                self.thumbnail_cache[file_path] = icon
                return icon
        
        # Generate new thumbnail
        ext = os.path.splitext(file_path)[1].lower()
        success = False
        
        if ext in {'.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm', '.m4v', '.3gp'}:
            success = ThumbnailGenerator.generate_video_thumbnail(file_path, thumbnail_path)
        elif ext in {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp'}:
            success = ThumbnailGenerator.generate_image_thumbnail(file_path, thumbnail_path)
            
        if success and os.path.exists(thumbnail_path):
            icon = QIcon(thumbnail_path)
            self.thumbnail_cache[file_path] = icon
            return icon
            
        # Fallback to default icon - return None to use parent implementation
        return None

class AutoMounter(QThread):
    """Thread for automatically mounting USB devices with proper permission handling"""
    mount_success = pyqtSignal(str, str)  # device, mount_point
    mount_failed = pyqtSignal(str, str)   # device, error

    def __init__(self):
        super().__init__()
        self.running = True
        self.mount_queue = []
        self.username = getpass.getuser()
        self.uid = os.getuid()
        self.gid = os.getgid()
        self.actual_mount_point = None  # Store the actual mount point

    def run(self):
        while self.running:
            if self.mount_queue:
                device = self.mount_queue.pop(0)
                self.try_mount_device(device)
            time.sleep(1)

    def add_device(self, device):
        """Add device to mount queue"""
        if device not in self.mount_queue:
            self.mount_queue.append(device)

    def try_mount_device(self, device):
        """Try to mount a device with proper permission handling"""
        if platform.system() != "Linux":
            return
        try:
            print(f"AutoMounter: Attempting to mount {device}")
            
            # Check if device is already mounted
            result = subprocess.run(['findmnt', '-n', '-o', 'TARGET', '-S', device], 
                                  capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip():
                print(f"AutoMounter: {device} is already mounted at {result.stdout.strip()}")
                self.mount_success.emit(device, result.stdout.strip())
                return  # Already mounted
            
            # Try udisks2 first (recommended approach)
            if self.try_udisks_mount(device):
                return
                
            # If udisks2 fails, try manual mounting
            # Get device info
            device_name = os.path.basename(device)
            # Try multiple mount paths in order of preference
            mount_paths = self.get_mount_paths(device_name)
            # Detect filesystem type
            fstype = self.detect_filesystem(device)
            print(f"AutoMounter: Detected filesystem type: {fstype}")
            
            # Try each mount path
            for mount_path in mount_paths:
                success = self.mount_at_path(device, mount_path, fstype)
                if success:
                    return
            self.mount_failed.emit(device, "Mount failed - no suitable mount point")
        except Exception as e:
            print(f"AutoMounter: Error mounting {device}: {e}")
            self.mount_failed.emit(device, str(e))

    def get_mount_paths(self, device_name):
        """Get list of user-writable mount paths (avoid /media entirely)"""
        paths = []

        # ✅ Preferred: /run/media/$USER — created automatically by udisks2
        run_media = f"/run/media/{self.username}"
        if os.path.exists(run_media):
            paths.append(f"{run_media}/{device_name}")

        # ✅ Fallback: ~/media — fully user-controlled
        home_media = os.path.expanduser("~/media")
        os.makedirs(home_media, exist_ok=True)  # Safe: inside your home
        paths.append(f"{home_media}/{device_name}")

        # ✅ Last resort: temporary mount in /tmp (if needed for testing)
        tmp_mount = f"/tmp/mount_{device_name}_{os.getpid()}"
        paths.append(tmp_mount)

        return paths

    def try_udisks_mount(self, device):
        """Mount using udisks2 — let it choose the mount point"""
        try:
            print(f"AutoMounter: Trying udisks2 for {device}")
            result = subprocess.run(
                ['udisksctl', 'mount', '--block-device', device, '--no-user-interaction'],
                capture_output=True, text=True, timeout=15
            )
            print(f"AutoMounter: udisksctl output: {result.stdout}")
            print(f"AutoMounter: udisksctl error: {result.stderr}")
            print(f"AutoMounter: udisksctl return code: {result.returncode}")
            
            if result.returncode == 0:
                # Extract actual mount point from udisisksctl output
                # Example output: "Mounted /dev/sdb1 at /run/media/user/UNTITLED."
                for word in result.stdout.split():
                    if word.startswith('/run/media/'):
                        self.actual_mount_point = word
                        self.mount_success.emit(device, word)
                        return True
            return False
        except (FileNotFoundError, subprocess.SubprocessError) as e:
            print(f"AutoMounter: udisks2 exception: {e}")
            return False

    def mount_at_path(self, device, mount_path, fstype):
        """Mount device at specified path"""
        try:
            print(f"AutoMounter: Trying manual mount at {mount_path}")
            # Create mount directory if it doesn't exist
            os.makedirs(mount_path, exist_ok=True)
            
            # Get appropriate mount options for filesystem type
            mount_options = self.get_mount_options(fstype)
            
            # Try mounting with appropriate options
            cmd = ['mount'] + mount_options + [device, mount_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                self.actual_mount_point = mount_path
                self.mount_success.emit(device, mount_path)
                return True
                
            # If mount failed, try with different options
            fallback_options = [
                ['-t', fstype],
                ['-t', 'auto'],
                ['-o', 'rw'],
                []
            ]
            for opts in fallback_options:
                cmd = ['mount'] + opts + [device, mount_path]
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        self.actual_mount_point = mount_path
                        self.mount_success.emit(device, mount_path)
                        return True
                except:
                    continue
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            print(f"AutoMounter: Manual mount exception: {e}")
        return False

    def detect_filesystem(self, device):
        """Detect filesystem type of device"""
        try:
            # Try blkid
            result = subprocess.run(['blkid', '-o', 'value', '-s', 'TYPE', device], 
                                  capture_output=True, text=True)
            print(f"AutoMounter: blkid output for {device}: {result.stdout}")
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except Exception as e:
            print(f"AutoMounter: blkid exception: {e}")
        try:
            # Try file command
            result = subprocess.run(['file', '-s', device], 
                                  capture_output=True, text=True)
            print(f"AutoMounter: file command output for {device}: {result.stdout}")
            if result.returncode == 0:
                output = result.stdout.lower()
                if 'fat' in output or 'vfat' in output:
                    return 'vfat'
                elif 'ntfs' in output:
                    return 'ntfs'
                elif 'ext' in output:
                    return 'ext4'
                elif 'exfat' in output:
                    return 'exfat'
        except Exception as e:
            print(f"AutoMounter: file command exception: {e}")
        return 'auto'

    def get_mount_options(self, fstype):
        """Get appropriate mount options for filesystem type"""
        options_map = {
            'vfat': ['-t', 'vfat', '-o', f'uid={self.uid},gid={self.gid},umask=000,shortname=mixed,utf8=1'],
            'ntfs': ['-t', 'ntfs-3g', '-o', f'uid={self.uid},gid={self.gid},umask=000,utf8=1'],
            'exfat': ['-t', 'exfat', '-o', f'uid={self.uid},gid={self.gid},umask=000'],
            'ext4': ['-t', 'ext4'],
            'ext3': ['-t', 'ext3'],
            'ext2': ['-t', 'ext2'],
        }
        return options_map.get(fstype, [])

    def stop(self):
        self.running = False

class USBMonitor(QThread):
    """Advanced USB monitoring thread with auto-mount capability"""
    usb_detected = pyqtSignal(list)  # Signal with list of USB devices
    status_message = pyqtSignal(str)  # Status message signal

    def __init__(self):
        super().__init__()
        self.running = True
        self.last_mounts = set()
        self.last_devices = set()
        self.auto_mounter = AutoMounter()
        self.auto_mounter.mount_success.connect(self.on_mount_success)
        self.auto_mounter.mount_failed.connect(self.on_mount_failed)
        self.auto_mounter.start()

    def run(self):
        while self.running:
            try:
                # Get current mounts and devices
                current_mounts = self.get_all_mounts()
                current_devices = self.get_all_usb_devices()
                
                # Check for new devices
                new_devices = current_devices - self.last_devices
                for device in new_devices:
                    print(f"USBMonitor: New device detected: {device}")
                    # For USB devices, we'll try to mount them regardless of filesystem detection
                    # since udisks2 can handle the mounting process
                    if device.startswith('/dev/sd') and not device.startswith('/dev/sda'):
                        print(f"USBMonitor: Adding USB device {device} to mount queue")
                        self.auto_mounter.add_device(device)
                        self.status_message.emit(f"Auto-mounting {device}...")
                
                # Check for changes
                if current_mounts != self.last_mounts or current_devices != self.last_devices:
                    all_devices = list(current_mounts.union(current_devices))
                    self.usb_detected.emit(all_devices)
                    self.last_mounts = current_mounts
                    self.last_devices = current_devices
                time.sleep(2)  # Check every 2 seconds
            except Exception as e:
                print(f"USB Monitor Error: {e}")
                time.sleep(5)  # Wait longer on error

    def has_filesystem(self, device):
        """Check if device has a recognizable filesystem"""
        # Since we're having permission issues, we'll just assume USB devices have filesystems
        # and let udisks2 handle the actual mounting
        if device.startswith('/dev/sd') and not device.startswith('/dev/sda'):
            return True
        return False

    def get_all_mounts(self):
        """Get all mount points that might be USB"""
        mounts = set()
        # Check psutil
        try:
            for partition in psutil.disk_partitions():
                if self.is_likely_usb(partition):
                    mounts.add(partition.mountpoint)
        except:
            pass
        # Check common mount directories
        mount_dirs = ['/media', '/mnt', '/run/media']
        for mount_dir in mount_dirs:
            if os.path.exists(mount_dir):
                try:
                    for user_dir in os.listdir(mount_dir):
                        user_path = os.path.join(mount_dir, user_dir)
                        if os.path.isdir(user_path):
                            for device in os.listdir(user_path):
                                device_path = os.path.join(user_path, device)
                                if os.path.ismount(device_path):
                                    mounts.add(device_path)
                except:
                    pass
        return mounts

    def get_all_usb_devices(self):
        """Get all USB block devices"""
        devices = set()
        # Method 1: Check /sys/block
        try:
            for device in os.listdir('/sys/block'):
                if device.startswith('sd') or device.startswith('hd'):
                    try:
                        with open(f'/sys/block/{device}/removable', 'r') as f:
                            if f.read().strip() == '1':
                                devices.add(f'/dev/{device}')
                    except:
                        pass
        except:
            pass
        # Method 2: Use lsblk
        try:
            result = subprocess.run(['lsblk', '-J'], capture_output=True, text=True)
            if result.returncode == 0:
                data = json.loads(result.stdout)
                for device in data.get('blockdevices', []):
                    if self.lsblk_is_usb(device):
                        devices.add(f"/dev/{device['name']}")
                        # Also add partitions
                        for child in device.get('children', []):
                            devices.add(f"/dev/{child['name']}")
        except:
            pass
        # Method 3: Check /dev/disk/by-id
        try:
            if os.path.exists('/dev/disk/by-id'):
                for device_id in os.listdir('/dev/disk/by-id'):
                    if 'usb' in device_id.lower():
                        try:
                            device_path = os.path.realpath(f'/dev/disk/by-id/{device_id}')
                            if os.path.exists(device_path):
                                devices.add(device_path)
                        except:
                            pass
        except:
            pass
        return devices

    def is_likely_usb(self, partition):
        """Check if partition is likely a USB device"""
        try:
            # Check device path
            if '/dev/sd' in partition.device:
                # Exclude system drive (usually sda)
                device_name = os.path.basename(partition.device)
                if not device_name.startswith('sda'):
                    return True
            # Check mount options
            if 'usb' in partition.opts.lower():
                return True
            # Check mount point
            if any(path in partition.mountpoint for path in ['/media/', '/mnt/', '/run/media/']):
                return True
            # Check filesystem type
            if partition.fstype.lower() in ['vfat', 'exfat', 'ntfs', 'msdos', 'fat32']:
                return True
        except:
            pass
        return False

    def lsblk_is_usb(self, device):
        """Check if lsblk device is USB"""
        try:
            if device.get('rm') == '1':  # Removable flag
                return True
            if device.get('type') == 'disk' and not device['name'].startswith('sda'):
                return True
        except:
            pass
        return False

    def on_mount_success(self, device, mount_point):
        """Handle successful mount"""
        self.status_message.emit(f"Mounted {device} at {mount_point}")
        # Refresh drives list after a short delay to ensure mount is fully registered
        QTimer.singleShot(1000, lambda: self.usb_detected.emit(list(self.get_all_mounts().union(self.get_all_usb_devices()))))

    def on_mount_failed(self, device, error):
        """Handle failed mount"""
        self.status_message.emit(f"Failed to mount {device}: {error}")

    def stop(self):
        self.running = False
        self.auto_mounter.stop()

class DevicesPane(QWidget):
    device_clicked = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        self.usb_monitor = USBMonitor()
        self.usb_monitor.usb_detected.connect(self.refresh_devices)
        self.usb_monitor.status_message.connect(self.show_status_message)
        self.usb_monitor.start()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Header
        header_layout = QHBoxLayout()
        devices_label = QLabel("Devices and Drives")
        devices_label.setStyleSheet("font-weight: bold; color: #ffffff;")
        
        refresh_btn = QToolButton()
        refresh_btn.setIcon(QIcon.fromTheme('view-refresh'))
        refresh_btn.setToolTip("Refresh devices")
        refresh_btn.clicked.connect(self.refresh_devices)
        
        header_layout.addWidget(devices_label)
        header_layout.addStretch()
        header_layout.addWidget(refresh_btn)
        
        layout.addLayout(header_layout)
        
        # Status message
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: #aaaaaa; font-style: italic;")
        layout.addWidget(self.status_label)
        
        # Devices list
        self.devices_list = QListWidget()
        self.devices_list.setIconSize(QSize(24, 24))
        self.devices_list.itemDoubleClicked.connect(self.on_device_double_clicked)
        layout.addWidget(self.devices_list)
        
        # Initial refresh
        self.refresh_devices()
        
    def show_status_message(self, message):
        self.status_label.setText(message)
        # Clear the message after 5 seconds
        QTimer.singleShot(5000, lambda: self.status_label.setText(""))
        
    def refresh_devices(self, devices_list=None):
        self.devices_list.clear()
        
        # Get mounted filesystems
        try:
            # Read /proc/mounts or use psutil if available
            mounts_file = '/proc/mounts'
            if os.path.exists(mounts_file):
                with open(mounts_file, 'r') as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 2:
                            device = parts[0]
                            mount_point = parts[1]
                            
                            # Filter out system mounts
                            if (mount_point.startswith('/') and 
                                not mount_point.startswith(('/sys', '/proc', '/dev', '/run')) and
                                not any(x in device for x in ('sysfs', 'proc', 'devpts', 'tmpfs', 'cgroup'))):
                                
                                self.add_device(device, mount_point)
            
            # Add removable media from /media and /run/media
            self.add_removable_media()
            
            # Add USB devices from monitor if provided
            if devices_list:
                for device in devices_list:
                    if isinstance(device, str) and device.startswith('/dev/'):
                        self.add_device(device, device)
                        
        except Exception as e:
            print(f"Error reading devices: {e}")
            
    def add_device(self, device, mount_point):
        item = QListWidgetItem()
        
        # Get device name
        device_name = os.path.basename(mount_point)
        if device_name == '':
            device_name = "Root Filesystem"
        elif device.startswith('/dev/'):
            device_name = os.path.basename(device)
            
        item.setText(f"{device_name}\n{mount_point}")
        item.setData(Qt.UserRole, mount_point)
        
        # Set icon based on device type
        if 'cdrom' in device or 'dvd' in device:
            icon = QIcon.fromTheme('drive-optical')
        elif 'usb' in device or 'sd' in device:
            icon = QIcon.fromTheme('drive-removable-media')
        else:
            icon = QIcon.fromTheme('drive-harddisk')
            
        if icon.isNull():
            icon = self.style().standardIcon(self.style().SP_DriveHDIcon)
            
        item.setIcon(icon)
        self.devices_list.addItem(item)
        
    def add_removable_media(self):
        media_dirs = ['/media', '/run/media', '/mnt']
        
        for media_dir in media_dirs:
            if os.path.exists(media_dir):
                try:
                    for user_dir in os.listdir(media_dir):
                        user_path = os.path.join(media_dir, user_dir)
                        if os.path.isdir(user_path):
                            for device_dir in os.listdir(user_path):
                                device_path = os.path.join(user_path, device_dir)
                                if os.path.ismount(device_path):
                                    item = QListWidgetItem()
                                    item.setText(f"{device_dir}\n{device_path}")
                                    item.setData(Qt.UserRole, device_path)
                                    item.setIcon(QIcon.fromTheme('drive-removable-media'))
                                    self.devices_list.addItem(item)
                except PermissionError:
                    continue
                    
    def on_device_double_clicked(self, item):
        mount_point = item.data(Qt.UserRole)
        if os.path.exists(mount_point):
            self.device_clicked.emit(mount_point)
            
    def closeEvent(self, event):
        # Clean up threads when closing
        if hasattr(self, 'usb_monitor'):
            self.usb_monitor.stop()
            self.usb_monitor.wait()
        super().closeEvent(event)

class DragDropTreeView(QTreeView):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setDragEnabled(True)
        self.setDropIndicatorShown(True)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        
    def startDrag(self, supportedActions):
        indexes = self.selectedIndexes()
        if not indexes:
            return
            
        drag = QDrag(self)
        mime_data = QMimeData()
        
        # Get file paths
        file_paths = []
        model = self.model()
        for index in indexes:
            if index.column() == 0:  # Only process first column
                file_path = model.filePath(index)
                file_paths.append(file_path)
                
        # Set MIME data - FIXED: Use QUrl directly instead of Qt.QUrl
        mime_data.setUrls([QUrl.fromLocalFile(path) for path in file_paths])
        drag.setMimeData(mime_data)
        
        # Set drag pixmap
        if len(file_paths) == 1:
            icon = model.data(indexes[0], Qt.DecorationRole)
            if icon:
                pixmap = icon.pixmap(32, 32)
                drag.setPixmap(pixmap)
                
        # Start drag
        drag.exec_(Qt.CopyAction | Qt.MoveAction, Qt.CopyAction)
        
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()
            
    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()
            
    def dropEvent(self, event):
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            file_paths = [url.toLocalFile() for url in urls]
            
            # Get drop position
            index = self.indexAt(event.pos())
            if index.isValid():
                target_path = self.model().filePath(index)
                if os.path.isdir(target_path):
                    destination_dir = target_path
                else:
                    destination_dir = os.path.dirname(target_path)
            else:
                destination_dir = self.model().rootPath()
                
            # Determine operation (copy or move)
            if event.keyboardModifiers() & Qt.ShiftModifier:
                operation = 'move'
            else:
                operation = 'copy'
                
            # Emit signal for main window to handle
            self.parent().file_dropped.emit(file_paths, destination_dir, operation)
            event.acceptProposedAction()
        else:
            event.ignore()

class EnhancedProgressDialog(QDialog):
    def __init__(self, title, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.resize(400, 150)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        
        layout = QVBoxLayout(self)
        
        # Operation label
        self.operation_label = QLabel("Preparing operation...")
        layout.addWidget(self.operation_label)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        layout.addWidget(self.progress_bar)
        
        # Details label
        self.details_label = QLabel("")
        self.details_label.setWordWrap(True)
        layout.addWidget(self.details_label)
        
        # Button layout
        button_layout = QHBoxLayout()
        
        self.pause_button = QToolButton()
        self.pause_button.setText("Pause")
        self.pause_button.clicked.connect(self.toggle_pause)
        
        self.cancel_button = QToolButton()
        self.cancel_button.setText("Cancel")
        self.cancel_button.clicked.connect(self.cancel_operation)
        
        button_layout.addWidget(self.pause_button)
        button_layout.addStretch()
        button_layout.addWidget(self.cancel_button)
        
        layout.addLayout(button_layout)
        
        self.is_paused = False
        
    def toggle_pause(self):
        self.is_paused = not self.is_paused
        self.pause_button.setText("Resume" if self.is_paused else "Pause")
        
    def cancel_operation(self):
        self.reject()
        
    def update_progress(self, value, operation_text="", details=""):
        self.progress_bar.setValue(value)
        if operation_text:
            self.operation_label.setText(operation_text)
        if details:
            self.details_label.setText(details)

class FileBrowserTab(QWidget):
    """A tab containing a file browser view"""
    file_dropped = pyqtSignal(list, str, str)  # file_paths, destination, operation
    status_update = pyqtSignal(str, str)  # status_text, path
    
    def __init__(self, path, main_window, parent=None):
        super().__init__(parent)
        self.current_path = path
        self.history = [self.current_path]
        self.history_index = 0
        self.main_window = main_window  # Store reference to main window
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Use custom tree view with drag-drop support for detailed view
        self.tree_view = DragDropTreeView()
        self.list_model = ThumbnailFileSystemModel()
        self.list_model.setRootPath("")
        self.list_model.setFilter(QDir.AllEntries | QDir.NoDotAndDotDot | QDir.AllDirs)
        self.tree_view.setModel(self.list_model)
        
        # Set column headers
        self.list_model.setHeaderData(0, Qt.Horizontal, "Name")
        self.list_model.setHeaderData(1, Qt.Horizontal, "Size")
        self.list_model.setHeaderData(2, Qt.Horizontal, "Type")
        self.list_model.setHeaderData(3, Qt.Horizontal, "Date Modified")
        
        # Set column widths
        self.tree_view.setColumnWidth(0, 300)
        self.tree_view.setColumnWidth(1, 100)
        self.tree_view.setColumnWidth(2, 100)
        self.tree_view.setColumnWidth(3, 150)
        
        # Fix: Properly set the root index using the model's index method
        root_index = self.list_model.index(self.current_path)
        if root_index.isValid():
            self.tree_view.setRootIndex(root_index)
        else:
            # Fallback to home directory if path is invalid
            self.current_path = QDir.homePath()
            root_index = self.list_model.index(self.current_path)
            self.tree_view.setRootIndex(root_index)
        
        self.tree_view.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.tree_view.setContextMenuPolicy(Qt.CustomContextMenu)
        
        layout.addWidget(self.tree_view)
        
        # Connect signals
        self.tree_view.doubleClicked.connect(self.tree_view_double_clicked)
        self.tree_view.customContextMenuRequested.connect(self.show_context_menu)
        self.tree_view.selectionModel().selectionChanged.connect(self.selection_changed)
        
    def tree_view_double_clicked(self, index):
        path = self.list_model.filePath(index)
        if os.path.isdir(path):
            self.navigate_to_path(path)
        else:
            self.open_file(path)
            
    def navigate_to_path(self, path):
        if not path or not os.path.exists(path):
            # Fallback to home directory if path is invalid
            path = QDir.homePath()
        
        self.current_path = path
        root_index = self.list_model.index(self.current_path)
        if root_index.isValid():
            self.tree_view.setRootIndex(root_index)
        else:
            # If still invalid, use root directory
            self.current_path = "/"
            root_index = self.list_model.index(self.current_path)
            self.tree_view.setRootIndex(root_index)
        
        if self.history_index < len(self.history) - 1:
            self.history = self.history[:self.history_index + 1]
        self.history.append(self.current_path)
        self.history_index = len(self.history) - 1
        
        self.update_status_bar()
        
    def go_back(self):
        if self.history_index > 0:
            self.history_index -= 1
            self.navigate_to_path(self.history[self.history_index])
            
    def go_forward(self):
        if self.history_index < len(self.history) - 1:
            self.history_index += 1
            self.navigate_to_path(self.history[self.history_index])
            
    def go_up(self):
        parent = os.path.dirname(self.current_path)
        if parent and os.path.exists(parent):
            self.navigate_to_path(parent)
            
    def go_home(self):
        home_path = os.path.expanduser('~')
        self.navigate_to_path(home_path)
        
    def refresh(self):
        # Force refresh of the file system models
        self.list_model.setRootPath("")  # Clear the current path
        self.list_model.setRootPath(self.current_path)  # Reset to current path
        
        # Update the root index
        root_index = self.list_model.index(self.current_path)
        if root_index.isValid():
            self.tree_view.setRootIndex(root_index)
        
        # Update status bar
        self.update_status_bar()
        
    def selection_changed(self):
        self.update_status_bar()
            
    def update_status_bar(self):
        try:
            items = os.listdir(self.current_path)
            file_count = sum(1 for item in items if os.path.isfile(os.path.join(self.current_path, item)))
            folder_count = sum(1 for item in items if os.path.isdir(os.path.join(self.current_path, item)))
            
            selected_count = len(self.tree_view.selectedIndexes()) // 4  # Divide by number of columns
            
            if selected_count > 0:
                status_text = f"{selected_count} selected — {file_count} files, {folder_count} folders"
            else:
                status_text = f"{file_count} files, {folder_count} folders"
                
            # Emit signal to update status bar in main window
            self.status_update.emit(status_text, self.current_path)
            
        except PermissionError:
            self.status_update.emit("Permission denied", self.current_path)
        except FileNotFoundError:
            self.status_update.emit("Path not found", self.current_path)
            
    def show_context_menu(self, position):
        menu = QMenu(self)
        
        index = self.tree_view.indexAt(position)
        if index.isValid():
            selected_count = len(self.tree_view.selectedIndexes()) // 4  # Divide by number of columns
            path = self.list_model.filePath(index)
            
            if os.path.isdir(path):
                menu.addAction(self.main_window.create_action('Open', 'document-open', 'Return', self.open_selected))
                menu.addAction(self.main_window.create_action('Open in New Tab', 'tab-new', 'Ctrl+Return', lambda: self.main_window.open_in_new_tab(path)))
                menu.addAction(self.main_window.create_action('Open in New Window', 'window-new', None, lambda: self.main_window.new_window(path)))
            else:
                menu.addAction(self.main_window.create_action('Open', 'document-open', 'Return', self.open_selected))
                menu.addAction(self.main_window.create_action('Open With...', 'system-run', None, self.open_with))
                
                # Add executable toggle option for files
                if self.main_window.is_file_executable(path):
                    menu.addAction(self.main_window.create_action('Remove Executable Permission', 'application-x-executable', None, self.main_window.toggle_executable))
                else:
                    menu.addAction(self.main_window.create_action('Make Executable', 'application-x-executable', None, self.main_window.toggle_executable))
            
            menu.addSeparator()
            menu.addAction(self.main_window.create_action('Cut', 'edit-cut', 'Ctrl+X', self.main_window.cut_selected))
            menu.addAction(self.main_window.create_action('Copy', 'edit-copy', 'Ctrl+C', self.main_window.copy_selected))
            
            if self.main_window.clipboard_paths:
                menu.addAction(self.main_window.create_action('Paste', 'edit-paste', 'Ctrl+V', self.main_window.paste_files))
            
            menu.addSeparator()
            menu.addAction(self.main_window.create_action('Rename', 'edit-rename', 'F2', self.main_window.rename_selected))
            
            if selected_count > 0:
                menu.addAction(self.main_window.create_action('Move to Trash', 'user-trash', 'Delete', self.main_window.delete_selected))
                menu.addAction(self.main_window.create_action('Delete', 'edit-delete', 'Shift+Delete', self.main_window.permanent_delete))
            
            menu.addSeparator()
            menu.addAction(self.main_window.create_action('Properties', 'document-properties', 'Alt+Return', self.main_window.show_properties))
        else:
            if self.main_window.clipboard_paths:
                menu.addAction(self.main_window.create_action('Paste', 'edit-paste', 'Ctrl+V', self.main_window.paste_files))
                menu.addSeparator()
            
            menu.addAction(self.main_window.create_action('Create Folder', 'folder-new', 'Ctrl+Shift+N', self.main_window.new_folder))
            menu.addAction(self.main_window.create_action('Create Document', 'document-new', None, self.main_window.new_file))
            menu.addSeparator()
            menu.addAction(self.main_window.create_action('Open in Terminal', 'utilities-terminal', None, self.main_window.open_in_terminal))
            menu.addAction(self.main_window.create_action('Open as Root', 'system-software-install', None, self.main_window.open_as_root))
            menu.addSeparator()
            menu.addAction(self.main_window.create_action('Properties', 'document-properties', 'Alt+Return', self.main_window.show_properties))
        
        menu.exec_(self.tree_view.viewport().mapToGlobal(position))

    def open_selected(self):
        indexes = self.tree_view.selectedIndexes()
        if indexes:
            path = self.list_model.filePath(indexes[0])
            if os.path.isdir(path):
                self.navigate_to_path(path)
            else:
                self.open_file(path)

    def open_file(self, path):
        try:
            if sys.platform.startswith('linux'):
                subprocess.run(['xdg-open', path])
            elif sys.platform == 'darwin':  # macOS
                subprocess.run(['open', path])
            elif sys.platform == 'win32':  # Windows
                os.startfile(path)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not open file: {str(e)}")

    def open_with(self):
        indexes = self.tree_view.selectedIndexes()
        if indexes:
            path = self.list_model.filePath(indexes[0])
            if os.path.isfile(path):
                # Simple dialog to choose application
                app, ok = QInputDialog.getText(self, "Open With", "Enter application name:")
                if ok and app:
                    try:
                        subprocess.run([app, path])
                    except Exception as e:
                        QMessageBox.warning(self, "Error", f"Could not open file with {app}: {str(e)}")

class ThunarClone(QMainWindow):
    file_dropped = pyqtSignal(list, str, str)  # file_paths, destination, operation
    
    def __init__(self, path=None):
        super().__init__()
        self.current_path = path or QDir.homePath()
        self.history = [self.current_path]
        self.history_index = 0
        self.clipboard_operation = None
        self.clipboard_paths = []
        self.file_operation_thread = None
        self.progress_dialog = None
        self.icon_size = 32  # Default icon size
        self.settings_manager = SettingsManager()

        # Initialize status labels early to prevent AttributeError
        self.status_label_left = None
        self.status_label_right = None

        self.init_ui()
        self.apply_black_theme()
        # Load saved settings after UI is created
        self.settings_manager.load_window_state(self)
        
    def init_ui(self):
        self.setWindowTitle('StormOS File Manager')
        self.setGeometry(100, 100, 1200, 800)
        
        # Set window icon (favicon)
        self.setWindowIcon(self.create_favicon())
        
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create toolbar
        self.create_toolbar()
        
        # Create main splitter (sidebar + content)
        self.create_main_splitter()
        
        # Create status bar
        self.create_status_bar()
        
        # Connect signals
        self.connect_signals()
        
        # Load XDG folders for places
        self.load_xdg_folders()
        
    def create_favicon(self):
        """Create a favicon for the application"""
        # Create a simple folder icon as pixmap
        pixmap = QPixmap(64, 64)
        pixmap.fill(Qt.transparent)
        
        # Create a painter to draw the icon
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Draw a folder shape
        painter.setBrush(QColor(50, 100, 200))
        painter.setPen(QColor(30, 80, 180))
        painter.drawRoundedRect(8, 12, 48, 40, 5, 5)
        
        # Draw folder tab
        painter.drawRoundedRect(12, 8, 40, 12, 3, 3)
        
        painter.end()
        
        return QIcon(pixmap)
        
    def create_menu_bar(self):
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('File')
        file_menu.addAction(self.create_action('New Window', 'window-new', 'Ctrl+N', self.new_window))
        file_menu.addAction(self.create_action('New Tab', 'tab-new', 'Ctrl+T', self.new_tab))
        file_menu.addSeparator()
        file_menu.addAction(self.create_action('Create Folder', 'folder-new', 'Ctrl+Shift+N', self.new_folder))
        file_menu.addAction(self.create_action('Create Document', 'document-new', None, self.new_file))
        file_menu.addSeparator()
        file_menu.addAction(self.create_action('Open', 'document-open', 'Ctrl+O', self.open_selected))
        file_menu.addSeparator()
        file_menu.addAction(self.create_action('Rename', 'edit-rename', 'F2', self.rename_selected))
        file_menu.addAction(self.create_action('Move to Trash', 'user-trash', 'Delete', self.delete_selected))
        file_menu.addAction(self.create_action('Delete', 'edit-delete', 'Shift+Delete', self.permanent_delete))
        file_menu.addSeparator()
        file_menu.addAction(self.create_action('Properties', 'document-properties', 'Alt+Return', self.show_properties))
        file_menu.addSeparator()
        file_menu.addAction(self.create_action('Close Tab', 'window-close', 'Ctrl+W', self.close_current_tab))
        file_menu.addAction(self.create_action('Close Window', 'window-close', 'Ctrl+Shift+W', self.close))
        
        # Edit menu
        edit_menu = menubar.addMenu('Edit')
        edit_menu.addAction(self.create_action('Cut', 'edit-cut', 'Ctrl+X', self.cut_selected))
        edit_menu.addAction(self.create_action('Copy', 'edit-copy', 'Ctrl+C', self.copy_selected))
        edit_menu.addAction(self.create_action('Paste', 'edit-paste', 'Ctrl+V', self.paste_files))
        edit_menu.addAction(self.create_action('Select All', 'edit-select-all', 'Ctrl+A', self.select_all))
        edit_menu.addAction(self.create_action('Select None', 'edit-clear', 'Ctrl+Shift+A', self.select_none))
        edit_menu.addSeparator()
        edit_menu.addAction(self.create_action('Invert Selection', 'edit-select-invert', 'Ctrl+I', self.invert_selection))
        
        # View menu
        view_menu = menubar.addMenu('View')
        self.view_toolbar_action = self.create_action('Toolbar', None, None, self.toggle_toolbar)
        self.view_toolbar_action.setCheckable(True)
        self.view_toolbar_action.setChecked(True)
        
        self.view_statusbar_action = self.create_action('Statusbar', None, None, self.toggle_statusbar)
        self.view_statusbar_action.setCheckable(True)
        self.view_statusbar_action.setChecked(True)
        
        self.view_sidebar_action = self.create_action('Sidebar', None, None, self.toggle_sidebar)
        self.view_sidebar_action.setCheckable(True)
        self.view_sidebar_action.setChecked(True)
        
        view_menu.addAction(self.view_toolbar_action)
        view_menu.addAction(self.view_statusbar_action)
        view_menu.addAction(self.view_sidebar_action)
        view_menu.addSeparator()
        
        view_mode_menu = view_menu.addMenu('View Mode')
        self.view_icons_action = self.create_action('Icons', 'view-list-icons', None, lambda: self.change_view_mode('icons'))
        self.view_icons_action.setCheckable(True)
        
        self.view_list_action = self.create_action('List', 'view-list-details', None, lambda: self.change_view_mode('list'))
        self.view_list_action.setCheckable(True)
        self.view_list_action.setChecked(True)
        
        self.view_compact_action = self.create_action('Compact', 'view-list-text', None, lambda: self.change_view_mode('compact'))
        self.view_compact_action.setCheckable(True)
        
        view_mode_menu.addAction(self.view_icons_action)
        view_mode_menu.addAction(self.view_list_action)
        view_mode_menu.addAction(self.view_compact_action)
        
        # Zoom menu
        zoom_menu = view_menu.addMenu('Zoom')
        zoom_menu.addAction(self.create_action('Zoom In', 'zoom-in', 'Ctrl++', self.zoom_in))
        zoom_menu.addAction(self.create_action('Zoom Out', 'zoom-out', 'Ctrl+-', self.zoom_out))
        zoom_menu.addAction(self.create_action('Reset Zoom', 'zoom-original', 'Ctrl+0', self.reset_zoom))
        
        # Go menu
        go_menu = menubar.addMenu('Go')
        go_menu.addAction(self.create_action('Back', 'go-previous', 'Alt+Left', self.go_back))
        go_menu.addAction(self.create_action('Forward', 'go-next', 'Alt+Right', self.go_forward))
        go_menu.addAction(self.create_action('Up', 'go-up', 'Alt+Up', self.go_up))
        go_menu.addSeparator()
        go_menu.addAction(self.create_action('Home', 'go-home', 'Alt+Home', self.go_home))
        go_menu.addAction(self.create_action('Desktop', 'user-desktop', None, lambda: self.navigate_to_path(self.get_xdg_folder('DESKTOP'))))
        go_menu.addAction(self.create_action('Documents', 'folder-documents', None, lambda: self.navigate_to_path(self.get_xdg_folder('DOCUMENTS'))))
        go_menu.addAction(self.create_action('Downloads', 'folder-downloads', None, lambda: self.navigate_to_path(self.get_xdg_folder('DOWNLOAD'))))
        go_menu.addAction(self.create_action('Music', 'folder-music', None, lambda: self.navigate_to_path(self.get_xdg_folder('MUSIC'))))
        go_menu.addAction(self.create_action('Pictures', 'folder-pictures', None, lambda: self.navigate_to_path(self.get_xdg_folder('PICTURES'))))
        go_menu.addAction(self.create_action('Videos', 'folder-videos', None, lambda: self.navigate_to_path(self.get_xdg_folder('VIDEOS'))))
        go_menu.addSeparator()
        go_menu.addAction(self.create_action('Computer', 'computer', None, lambda: self.navigate_to_path('/')))
        go_menu.addAction(self.create_action('Network', 'network-workgroup', None, lambda: self.navigate_to_path('/net')))
        go_menu.addSeparator()
        go_menu.addAction(self.create_action('Recent', 'document-open-recent', None, self.show_recent))
        
    def create_action(self, text, icon_name, shortcut, slot=None):
        action = QAction(text, self)
        if icon_name:
            icon = QIcon.fromTheme(icon_name)
            if icon.isNull():
                # Fallback icons for common actions
                icon_fallbacks = {
                    'go-previous': self.style().standardIcon(self.style().SP_ArrowBack),
                    'go-next': self.style().standardIcon(self.style().SP_ArrowForward),
                    'go-up': self.style().standardIcon(self.style().SP_ArrowUp),
                    'go-home': self.style().standardIcon(self.style().SP_DirHomeIcon),
                    'view-refresh': self.style().standardIcon(self.style().SP_BrowserReload),
                    'edit-delete': self.style().standardIcon(self.style().SP_TrashIcon),
                    'user-trash': self.style().standardIcon(self.style().SP_TrashIcon),
                    'computer': self.style().standardIcon(self.style().SP_ComputerIcon),
                    'folder-new': self.style().standardIcon(self.style().SP_FileDialogNewFolder),
                    'document-new': self.style().standardIcon(self.style().SP_FileIcon),
                    'edit-cut': self.style().standardIcon(self.style().SP_FileDialogDetailedView),
                    'edit-copy': self.style().standardIcon(self.style().SP_FileDialogContentsView),
                    'edit-paste': self.style().standardIcon(self.style().SP_DialogOkButton),
                    'zoom-in': self.style().standardIcon(self.style().SP_ArrowUp),
                    'zoom-out': self.style().standardIcon(self.style().SP_ArrowDown),
                    'zoom-original': self.style().standardIcon(self.style().SP_BrowserReload),
                    'utilities-terminal': self.style().standardIcon(self.style().SP_ComputerIcon),
                    'application-x-executable': self.style().standardIcon(self.style().SP_DialogApplyButton),
                    'tab-new': self.style().standardIcon(self.style().SP_FileDialogNewFolder),
                    'window-new': self.style().standardIcon(self.style().SP_FileDialogNewFolder),
                    'application-exit': self.style().standardIcon(self.style().SP_DialogCloseButton),
                    'document-open': self.style().standardIcon(self.style().SP_DialogOpenButton),
                    'system-run': self.style().standardIcon(self.style().SP_MediaPlay),
                    'system-software-install': self.style().standardIcon(self.style().SP_ComputerIcon),
                    'document-properties': self.style().standardIcon(self.style().SP_FileDialogDetailedView)
                }
                icon = icon_fallbacks.get(icon_name, self.style().standardIcon(self.style().SP_FileIcon))
            action.setIcon(icon)
        if shortcut:
            action.setShortcut(QKeySequence(shortcut))
        if slot:
            action.triggered.connect(slot)
        return action
        
    def create_toolbar(self):
        # Create main toolbar
        self.toolbar = QToolBar()
        self.toolbar.setIconSize(QSize(16, 16))
        self.toolbar.setMovable(False)
        self.addToolBar(self.toolbar)
        
        # Create a widget to hold the navigation buttons
        nav_widget = QWidget()
        nav_layout = QHBoxLayout(nav_widget)
        nav_layout.setContentsMargins(0, 0, 0, 0)
        nav_layout.setSpacing(2)
        
        # Navigation actions
        self.back_action = self.create_action('Back', 'go-previous', 'Alt+Left', self.go_back)
        self.forward_action = self.create_action('Forward', 'go-next', 'Alt+Right', self.go_forward)
        self.up_action = self.create_action('Up', 'go-up', 'Alt+Up', self.go_up)
        self.home_action = self.create_action('Home', 'go-home', 'Alt+Home', self.go_home)
        self.refresh_action = self.create_action('Refresh', 'view-refresh', 'F5', self.refresh)
        
        # Add navigation buttons to the nav layout
        back_btn = QToolButton()
        back_btn.setDefaultAction(self.back_action)
        nav_layout.addWidget(back_btn)
        
        forward_btn = QToolButton()
        forward_btn.setDefaultAction(self.forward_action)
        nav_layout.addWidget(forward_btn)
        
        up_btn = QToolButton()
        up_btn.setDefaultAction(self.up_action)
        nav_layout.addWidget(up_btn)
        
        home_btn = QToolButton()
        home_btn.setDefaultAction(self.home_action)
        nav_layout.addWidget(home_btn)
        
        refresh_btn = QToolButton()
        refresh_btn.setDefaultAction(self.refresh_action)
        nav_layout.addWidget(refresh_btn)
        
        # Add the navigation widget to the toolbar
        self.toolbar.addWidget(nav_widget)
        
        # Add a separator
        self.toolbar.addSeparator()
        
        # Create a container widget for the address bar
        address_container = QWidget()
        address_container.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        address_layout = QHBoxLayout(address_container)
        address_layout.setContentsMargins(5, 0, 5, 0)
        address_layout.setSpacing(5)
        
        # Location label
        location_label = QLabel("Location:")
        location_label.setStyleSheet("color: #ffffff; padding: 0 5px;")
        address_layout.addWidget(location_label)
        
        # Location combo box (address bar)
        self.location_combo = QComboBox()
        self.location_combo.setEditable(True)
        self.location_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.location_combo.setInsertPolicy(QComboBox.NoInsert)
        self.location_combo.setMinimumWidth(300)
        address_layout.addWidget(self.location_combo)
        
        # Add the address container to the toolbar
        self.toolbar.addWidget(address_container)
        
        # Make the address container expand to fill available space
        self.toolbar.addWidget(QWidget())  # Spacer
        
    def create_main_splitter(self):
        main_splitter = QSplitter(Qt.Horizontal)
        main_layout = self.centralWidget().layout()
        main_layout.addWidget(main_splitter, 1)
        
        # Create sidebar (places, tree, and devices)
        self.create_sidebar(main_splitter)
        
        # Create content area with tabbed browsing
        self.create_content_area(main_splitter)
        
        main_splitter.setSizes([250, 750])
        
    def create_sidebar(self, parent_splitter):
        sidebar_widget = QWidget()
        sidebar_layout = QVBoxLayout(sidebar_widget)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)
        sidebar_layout.setSpacing(0)
        
        # Create a vertical splitter for the sidebar components
        sidebar_splitter = QSplitter(Qt.Vertical)
        
        # Places list
        places_group = QGroupBox("Places")
        places_layout = QVBoxLayout(places_group)
        
        self.places_list = QListWidget()
        self.places_list.setContextMenuPolicy(Qt.CustomContextMenu)
        
        places_layout.addWidget(self.places_list)
        sidebar_splitter.addWidget(places_group)
        
        # Tree view
        tree_group = QGroupBox("Tree")
        tree_layout = QVBoxLayout(tree_group)
        
        self.tree_view = QTreeView()
        self.tree_model = QFileSystemModel()
        self.tree_model.setRootPath("")
        self.tree_model.setFilter(QDir.AllEntries | QDir.NoDotAndDotDot | QDir.AllDirs)
        self.tree_view.setModel(self.tree_model)
        self.tree_view.setRootIndex(self.tree_model.index(self.current_path))
        self.tree_view.setColumnWidth(0, 200)
        self.tree_view.setSortingEnabled(True)
        self.tree_view.sortByColumn(0, Qt.AscendingOrder)
        self.tree_view.hideColumn(1)
        self.tree_view.hideColumn(2)
        self.tree_view.hideColumn(3)
        
        tree_layout.addWidget(self.tree_view)
        sidebar_splitter.addWidget(tree_group)
        
        # Devices pane
        devices_group = QGroupBox("Devices")
        devices_layout = QVBoxLayout(devices_group)
        
        self.devices_pane = DevicesPane()
        self.devices_pane.device_clicked.connect(self.navigate_to_path)
        
        devices_layout.addWidget(self.devices_pane)
        sidebar_splitter.addWidget(devices_group)
        
        # Set initial sizes for the sidebar components
        sidebar_splitter.setSizes([100, 200, 150])
        
        sidebar_layout.addWidget(sidebar_splitter)
        
        parent_splitter.addWidget(sidebar_widget)
        
    def create_content_area(self, parent_splitter):
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(0, 0, 0, 0)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabsClosable(True)
        self.tab_widget.tabCloseRequested.connect(self.close_tab)
        self.tab_widget.currentChanged.connect(self.tab_changed)
        
        # Create initial tab
        self.new_tab(self.current_path)
        
        content_layout.addWidget(self.tab_widget)
        
        parent_splitter.addWidget(content_widget)
        
    def create_status_bar(self):
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Create a container widget for status bar content
        status_widget = QWidget()
        status_layout = QHBoxLayout(status_widget)
        status_layout.setContentsMargins(0, 0, 0, 0)
        status_layout.setSpacing(10)
        
        # Initialize status labels as instance variables
        self.status_label_left = QLabel()
        self.status_label_right = QLabel()
        
        # Add left status label
        status_layout.addWidget(self.status_label_left)
        
        # Add stretch to push zoom controls to the right
        status_layout.addStretch()
        
        # Add zoom controls to status bar
        self.create_zoom_controls(status_layout)
        
        # Add right status label
        status_layout.addWidget(self.status_label_right)
        
        # Set the status widget as the permanent widget
        self.status_bar.addPermanentWidget(status_widget, 1)
        
        # Initialize status bar with default text
        self.status_label_left.setText("Ready")
        self.status_label_right.setText(self.current_path)

    def create_zoom_controls(self, parent_layout):
        """Create zoom controls and add them to the parent layout"""
        # Zoom out button
        zoom_out_btn = QToolButton()
        zoom_out_btn.setDefaultAction(self.create_action('Zoom Out', 'zoom-out', 'Ctrl+-', self.zoom_out))
        zoom_out_btn.setFixedSize(24, 24)
        parent_layout.addWidget(zoom_out_btn)
        
        # Zoom slider
        self.zoom_slider = QSlider(Qt.Horizontal)
        self.zoom_slider.setMinimum(16)
        self.zoom_slider.setMaximum(128)
        self.zoom_slider.setValue(self.icon_size)
        self.zoom_slider.setTickPosition(QSlider.NoTicks)
        self.zoom_slider.setMaximumWidth(100)
        self.zoom_slider.setFixedHeight(20)
        self.zoom_slider.valueChanged.connect(self.on_zoom_changed)
        parent_layout.addWidget(self.zoom_slider)
        
        # Zoom in button
        zoom_in_btn = QToolButton()
        zoom_in_btn.setDefaultAction(self.create_action('Zoom In', 'zoom-in', 'Ctrl++', self.zoom_in))
        zoom_in_btn.setFixedSize(24, 24)
        parent_layout.addWidget(zoom_in_btn)
        
        # Reset zoom button
        reset_zoom_btn = QToolButton()
        reset_zoom_btn.setDefaultAction(self.create_action('Reset Zoom', 'zoom-original', 'Ctrl+0', self.reset_zoom))
        reset_zoom_btn.setFixedSize(24, 24)
        parent_layout.addWidget(reset_zoom_btn)
        
    def connect_signals(self):
        self.tree_view.clicked.connect(self.tree_view_clicked)
        self.places_list.itemDoubleClicked.connect(self.places_item_double_clicked)
        self.location_combo.activated.connect(self.location_combo_activated)
        self.location_combo.lineEdit().returnPressed.connect(self.location_bar_return_pressed)
        self.file_dropped.connect(self.handle_file_drop)
        self.update_location_combo()
        
    def new_window(self, path=None):
        """Create a new file manager window"""
        if path is None:
            path = self.current_path
            
        new_win = ThunarClone(path)
        new_win.show()
        return new_win
        
    def new_tab(self, path=None):
        if path is None:
            path = self.current_path
        
        # Validate path
        if not path or not os.path.exists(path):
            path = QDir.homePath()
        
        try:
            # Create new tab - pass self (main window) as the second parameter
            tab = FileBrowserTab(path, self)  # Pass main window reference
            tab.file_dropped.connect(self.handle_file_drop)
            tab.status_update.connect(self.update_status_bar_from_tab)
            
            # Add tab to widget
            tab_name = os.path.basename(path) or path
            index = self.tab_widget.addTab(tab, tab_name)
            self.tab_widget.setCurrentIndex(index)
            
            # Update current path
            self.current_path = path
        except Exception as e:
            print(f"Error creating tab: {e}")
            # Fallback to home directory
            self.new_tab(QDir.homePath())
        
    def close_tab(self, index):
        # Don't close the last tab
        if self.tab_widget.count() <= 1:
            return
            
        self.tab_widget.removeTab(index)
        
    def close_current_tab(self):
        current_index = self.tab_widget.currentIndex()
        self.close_tab(current_index)
        
    def tab_changed(self, index):
        if index >= 0:
            current_tab = self.tab_widget.currentWidget()
            if current_tab:
                self.current_path = current_tab.current_path
                self.update_location_combo()
                self.setWindowTitle(f"StormOS File Manager - {self.current_path}")
                # Update status bar for new tab with safety check
                try:
                    current_tab.update_status_bar()
                except Exception as e:
                    print(f"Error updating status bar: {e}")
            
    def update_status_bar_from_tab(self, left_text, right_text):
        """Safely update status bar from tab - with proper attribute checking"""
        try:
            if hasattr(self, 'status_label_left') and self.status_label_left is not None:
                self.status_label_left.setText(left_text)
            if hasattr(self, 'status_label_right') and self.status_label_right is not None:
                self.status_label_right.setText(right_text)
        except AttributeError as e:
            print(f"Status bar update error: {e}")
            # Fallback to basic status bar update
            self.statusBar().showMessage(f"{left_text} - {right_text}")
        
    def is_file_executable(self, file_path):
        """Check if a file is executable"""
        try:
            file_stat = os.stat(file_path)
            # Check if any execute bit is set (user, group, or other)
            return (file_stat.st_mode & stat.S_IXUSR) or (file_stat.st_mode & stat.S_IXGRP) or (file_stat.st_mode & stat.S_IXOTH)
        except OSError:
            return False
            
    def toggle_executable(self):
        """Toggle executable permission for selected files"""
        current_tab = self.tab_widget.currentWidget()
        if not current_tab:
            return
            
        indexes = current_tab.tree_view.selectedIndexes()
        if not indexes:
            return
            
        files_to_process = []
        for index in indexes:
            if index.column() == 0:  # Only process first column
                path = current_tab.list_model.filePath(index)
                if os.path.isfile(path):  # Only process files, not directories
                    files_to_process.append(path)
        
        if not files_to_process:
            QMessageBox.information(self, "Info", "No files selected. Only files can be made executable.")
            return
            
        # Check if any files are executable
        executable_files = [f for f in files_to_process if self.is_file_executable(f)]
        
        if executable_files:
            # Some files are executable, ask if user wants to remove executable permission
            reply = QMessageBox.question(
                self, 
                "Remove Executable Permission",
                f"{len(executable_files)} of {len(files_to_process)} selected file(s) are executable.\n\n"
                f"Do you want to remove executable permission from all selected files?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                self.remove_executable_permission(files_to_process)
        else:
            # No files are executable, ask if user wants to add executable permission
            reply = QMessageBox.question(
                self,
                "Make Files Executable",
                f"Make {len(files_to_process)} selected file(s) executable?\n\n"
                f"This will run: sudo chmod +x [files]",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes
            )
            
            if reply == QMessageBox.Yes:
                self.add_executable_permission(files_to_process)
                
    def add_executable_permission(self, file_paths):
        """Add executable permission to files using sudo chmod +x"""
        try:
            # Create a progress dialog for the operation
            progress = QMessageBox(self)
            progress.setWindowTitle("Processing")
            progress.setText(f"Making {len(file_paths)} file(s) executable...")
            progress.setStandardButtons(QMessageBox.NoButton)
            progress.show()
            
            # Process each file
            QApplication.processEvents()  # Update UI
            
            for file_path in file_paths:
                try:
                    # Use sudo chmod +x to add executable permission
                    result = subprocess.run(
                        ['sudo', 'chmod', '+x', file_path],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    
                    if result.returncode != 0:
                        print(f"Failed to make {file_path} executable: {result.stderr}")
                        
                except subprocess.TimeoutExpired:
                    print(f"Timeout making {file_path} executable")
                except Exception as e:
                    print(f"Error making {file_path} executable: {e}")
                    
            progress.close()
            
            # Refresh the view
            self.refresh()
            
            QMessageBox.information(
                self,
                "Complete",
                f"Processed {len(file_paths)} file(s).\n\n"
                f"Note: You may need to enter your password for the sudo command."
            )
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to make files executable: {str(e)}")
            
    def remove_executable_permission(self, file_paths):
        """Remove executable permission from files using sudo chmod -x"""
        try:
            # Create a progress dialog for the operation
            progress = QMessageBox(self)
            progress.setWindowTitle("Processing")
            progress.setText(f"Removing executable permission from {len(file_paths)} file(s)...")
            progress.setStandardButtons(QMessageBox.NoButton)
            progress.show()
            
            # Process each file
            QApplication.processEvents()  # Update UI
            
            for file_path in file_paths:
                try:
                    # Use sudo chmod -x to remove executable permission
                    result = subprocess.run(
                        ['sudo', 'chmod', '-x', file_path],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    
                    if result.returncode != 0:
                        print(f"Failed to remove executable from {file_path}: {result.stderr}")
                        
                except subprocess.TimeoutExpired:
                    print(f"Timeout removing executable from {file_path}")
                except Exception as e:
                    print(f"Error removing executable from {file_path}: {e}")
                    
            progress.close()
            
            # Refresh the view
            self.refresh()
            
            QMessageBox.information(
                self,
                "Complete",
                f"Processed {len(file_paths)} file(s).\n\n"
                f"Note: You may need to enter your password for the sudo command."
            )
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to remove executable permission: {str(e)}")
            
    def open_in_terminal(self):
        """Open current directory in terminal"""
        try:
            if sys.platform.startswith('linux'):
                # Try different terminal emulators
                terminals = [
                    ['gnome-terminal', '--working-directory=' + self.current_path],
                    ['konsole', '--workdir', self.current_path],
                    ['xfce4-terminal', '--default-working-directory=' + self.current_path],
                    ['terminator', '--working-directory=' + self.current_path],
                    ['tilix', '-w', self.current_path],
                    ['urxvt', '-cd', self.current_path],
                    ['xterm', '-e', 'bash -c "cd ' + self.current_path + '; bash"'],
                    ['alacritty', '--working-directory', self.current_path],
                    ['kitty', '--directory', self.current_path]
                ]
                
                for terminal_cmd in terminals:
                    try:
                        subprocess.Popen(terminal_cmd)
                        return
                    except (FileNotFoundError, subprocess.SubprocessError):
                        continue
                        
                # If no terminal found, show error
                QMessageBox.warning(self, "Error", "No suitable terminal emulator found.")
                
            elif sys.platform == 'darwin':  # macOS
                subprocess.run(['open', '-a', 'Terminal', self.current_path])
            elif sys.platform == 'win32':  # Windows
                subprocess.run(['cmd', '/c', 'start', 'cmd', '/k', 'cd', '/d', self.current_path])
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not open terminal: {str(e)}")
            
    def open_as_root(self):
        """Open current directory as root using sudo thunar"""
        try:
            if sys.platform.startswith('linux'):
                # Check if thunar is available
                result = subprocess.run(['which', 'thunar'], capture_output=True, text=True)
                if result.returncode != 0:
                    QMessageBox.warning(self, "Error", "Thunar file manager is not installed.")
                    return
                    
                # Ask for confirmation
                reply = QMessageBox.question(
                    self,
                    "Open as Root",
                    f"Open '{self.current_path}' as root?\n\n"
                    f"This will launch Thunar with administrator privileges.\n"
                    f"You will need to enter your password.",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No
                )
                
                if reply == QMessageBox.Yes:
                    # Launch thunar as root
                    try:
                        subprocess.Popen(['sudo', 'thunar', self.current_path])
                        QMessageBox.information(
                            self,
                            "Opening as Root",
                            f"Thunar is opening '{self.current_path}' as root.\n\n"
                            f"Enter your password when prompted."
                        )
                    except Exception as e:
                        QMessageBox.critical(self, "Error", f"Failed to open Thunar as root: {str(e)}")
            else:
                QMessageBox.information(self, "Not Supported", "Open as Root is only supported on Linux.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not open as root: {str(e)}")

    def update_icon_size(self, size):
        """Update icon size for all views, respecting current view mode"""
        self.icon_size = size
        
        # Update icon size for tree view
        current_tab = self.tab_widget.currentWidget()
        if current_tab:
            current_tab.tree_view.setIconSize(QSize(size, size))
        
        # Always update these
        self.places_list.setIconSize(QSize(size // 2, size // 2))
        self.devices_pane.devices_list.setIconSize(QSize(size // 2, size // 2))
        self.tree_view.setIconSize(QSize(size // 2, size // 2))
        
        # Update zoom slider position
        if hasattr(self, 'zoom_slider'):
            self.zoom_slider.blockSignals(True)
            self.zoom_slider.setValue(size)
            self.zoom_slider.blockSignals(False)
        
        # Save the setting
        self.settings_manager.settings.setValue("iconSize", size)

    def get_current_view_mode(self):
        """Get the current view mode"""
        if self.view_icons_action.isChecked():
            return 'icons'
        elif self.view_list_action.isChecked():
            return 'list'
        elif self.view_compact_action.isChecked():
            return 'compact'
        return 'list'  # default

    def on_zoom_changed(self, value):
        """Handle zoom slider change"""
        self.update_icon_size(value)
        
    def zoom_in(self):
        """Increase icon size"""
        new_size = min(self.icon_size + 16, 128)
        self.update_icon_size(new_size)
        
    def zoom_out(self):
        """Decrease icon size"""
        new_size = max(self.icon_size - 16, 16)
        self.update_icon_size(new_size)
        
    def reset_zoom(self):
        """Reset icon size to default"""
        self.update_icon_size(32)
        
    def apply_black_theme(self):
        # Create a pure black palette
        black_palette = QPalette()
        black_palette.setColor(QPalette.Window, QColor(0, 0, 0))
        black_palette.setColor(QPalette.WindowText, QColor(255, 255, 255))
        black_palette.setColor(QPalette.Base, QColor(20, 20, 20))
        black_palette.setColor(QPalette.AlternateBase, QColor(30, 30, 30))
        black_palette.setColor(QPalette.ToolTipBase, QColor(10, 10, 10))
        black_palette.setColor(QPalette.ToolTipText, QColor(255, 255, 255))
        black_palette.setColor(QPalette.Text, QColor(255, 255, 255))
        black_palette.setColor(QPalette.Button, QColor(30, 30, 30))
        black_palette.setColor(QPalette.ButtonText, QColor(255, 255, 255))
        black_palette.setColor(QPalette.BrightText, Qt.red)
        black_palette.setColor(QPalette.Link, QColor(100, 150, 255))
        black_palette.setColor(QPalette.Highlight, QColor(50, 100, 200))
        black_palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
        black_palette.setColor(QPalette.Disabled, QPalette.Text, QColor(100, 100, 100))
        black_palette.setColor(QPalette.Disabled, QPalette.ButtonText, QColor(100, 100, 100))
        
        self.setPalette(black_palette)
        QApplication.setPalette(black_palette)
        
        # Apply black stylesheet
        self.setStyleSheet("""
            QMainWindow {
                background-color: #000000;
            }
            QMenuBar {
                background-color: #141414;
                color: #ffffff;
                border: none;
            }
            QMenuBar::item {
                background-color: transparent;
                padding: 4px 10px;
            }
            QMenuBar::item:selected {
                background-color: #3264c8;
            }
            QToolBar {
                background-color: #141414;
                border: none;
                border-bottom: 1px solid #333333;
                spacing: 3px;
                padding: 3px;
            }
            QToolButton {
                background-color: transparent;
                color: #ffffff;
                border: 1px solid transparent;
                padding: 4px;
                border-radius: 3px;
            }
            QToolButton:hover {
                background-color: #282828;
                border: 1px solid #444444;
            }
            QToolButton:pressed {
                background-color: #0a0a0a;
            }
            QTreeView, QListView, QListWidget {
                background-color: #141414;
                color: #ffffff;
                border: 1px solid #333333;
                outline: 0;
                alternate-background-color: #1a1a1a;
            }
            QTreeView::item, QListView::item, QListWidget::item {
                padding: 2px;
                border: 1px solid transparent;
            }
            QTreeView::item:selected, QListView::item:selected, QListWidget::item:selected {
                background-color: #3264c8;
                color: #ffffff;
            }
            QTreeView::item:hover, QListView::item:hover, QListWidget::item:hover {
                background-color: #1e1e1e;
            }
            QHeaderView::section {
                background-color: #141414;
                color: #ffffff;
                padding: 4px;
                border: 1px solid #333333;
            }
            QStatusBar {
                background-color: #141414;
                color: #ffffff;
                border-top: 1px solid #333333;
            }
            QComboBox {
                background-color: #1a1a1a;
                color: #ffffff;
                border: 1px solid #333333;
                padding: 2px 8px;
                border-radius: 3px;
            }
            QComboBox::drop-down {
                border: none;
                width: 20px;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 4px solid transparent;
                border-right: 4px solid transparent;
                border-top: 4px solid #ffffff;
                margin-right: 4px;
            }
            QComboBox QAbstractItemView {
                background-color: #1a1a1a;
                color: #ffffff;
                border: 1px solid #333333;
                selection-background-color: #3264c8;
            }
            QComboBox QLineEdit {
                background-color: #1a1a1a;
                color: #ffffff;
                border: none;
                padding: 2px;
            }
            QSlider::groove:horizontal {
                border: 1px solid #333333;
                height: 6px;
                background: #1a1a1a;
                border-radius: 3px;
            }
            QSlider::handle:horizontal {
                background: #3264c8;
                border: 1px solid #2a54a8;
                width: 14px;
                margin: -4px 0;
                border-radius: 7px;
            }
            QSlider::handle:horizontal:hover {
                background: #4075d0;
            }
            QMenu {
                background-color: #141414;
                color: #ffffff;
                border: 1px solid #333333;
            }
            QMenu::item {
                padding: 4px 20px;
            }
            QMenu::item:selected {
                background-color: #3264c8;
                color: #ffffff;
            }
            QGroupBox {
                font-weight: bold;
                color: #ffffff;
                border: 1px solid #333333;
                border-radius: 3px;
                margin-top: 1ex;
                background-color: #141414;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: #ffffff;
            }
            QLabel {
                color: #ffffff;
            }
            QDockWidget {
                background-color: #141414;
                color: #ffffff;
                border: 1px solid #333333;
            }
            QDockWidget::title {
                background-color: #141414;
                padding: 6px;
                border: none;
            }
            QProgressBar {
                border: 1px solid #333333;
                border-radius: 3px;
                text-align: center;
                color: #ffffff;
                background-color: #0a0a0a;
            }
            QProgressBar::chunk {
                background-color: #3264c8;
                border-radius: 2px;
            }
            QScrollBar:vertical {
                background-color: #141414;
                width: 12px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background-color: #333333;
                min-height: 20px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #444444;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
            QScrollBar:horizontal {
                background-color: #141414;
                height: 12px;
                margin: 0px;
            }
            QScrollBar::handle:horizontal {
                background-color: #333333;
                min-width: 20px;
                border-radius: 6px;
            }
            QScrollBar::handle:horizontal:hover {
                background-color: #444444;
            }
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
                width: 0px;
            }
            QTabWidget::pane {
                border: 1px solid #333333;
                background-color: #141414;
            }
            QTabBar::tab {
                background-color: #1a1a1a;
                color: #ffffff;
                border: 1px solid #333333;
                padding: 6px 12px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #3264c8;
            }
            QTabBar::tab:hover {
                background-color: #282828;
            }
        """)
        
    def load_xdg_folders(self):
        self.places_list.clear()
        
        xdg_folders = [
            ('Home', self.get_xdg_folder('HOME'), 'user-home'),
            ('Desktop', self.get_xdg_folder('DESKTOP'), 'user-desktop'),
            ('Documents', self.get_xdg_folder('DOCUMENTS'), 'folder-documents'),
            ('Downloads', self.get_xdg_folder('DOWNLOAD'), 'folder-downloads'),
            ('Music', self.get_xdg_folder('MUSIC'), 'folder-music'),
            ('Pictures', self.get_xdg_folder('PICTURES'), 'folder-pictures'),
            ('Videos', self.get_xdg_folder('VIDEOS'), 'folder-videos'),
            ('Templates', self.get_xdg_folder('TEMPLATES'), 'folder-templates'),
            ('Public', self.get_xdg_folder('PUBLICSHARE'), 'folder-publicshare'),
            ('Trash', os.path.expanduser('~/.local/share/Trash'), 'user-trash'),
        ]
        
        xdg_folders.append(('File System', '/', 'drive-harddisk'))
        xdg_folders.append(('Network', '/net', 'network-workgroup'))
        
        for name, path, icon_name in xdg_folders:
            if path and os.path.exists(path):
                item = QListWidgetItem(name)
                icon = QIcon.fromTheme(icon_name)
                if icon.isNull():
                    if icon_name == 'user-home':
                        icon = self.style().standardIcon(self.style().SP_DirHomeIcon)
                    elif icon_name == 'drive-harddisk':
                        icon = self.style().standardIcon(self.style().SP_DriveHDIcon)
                    elif icon_name == 'network-workgroup':
                        icon = self.style().standardIcon(self.style().SP_DriveNetIcon)
                    else:
                        icon = self.style().standardIcon(self.style().SP_DirIcon)
                
                item.setIcon(icon)
                item.setData(Qt.UserRole, path)
                self.places_list.addItem(item)
        
    def get_xdg_folder(self, folder_type):
        try:
            result = subprocess.run(['xdg-user-dir', folder_type], 
                                  capture_output=True, text=True, check=True)
            path = result.stdout.strip()
            if path and os.path.exists(path):
                return path
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        
        config_file = os.path.expanduser('~/.config/user-dirs.dirs')
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    for line in f:
                        if line.startswith(f'XDG_{folder_type}_DIR'):
                            path = line.split('=')[1].strip().strip('"')
                            path = path.replace('$HOME', os.path.expanduser('~'))
                            if os.path.exists(path):
                                return path
            except Exception:
                pass
        
        fallback_paths = {
            'HOME': os.path.expanduser('~'),
            'DESKTOP': os.path.expanduser('~/Desktop'),
            'DOCUMENTS': os.path.expanduser('~/Documents'),
            'DOWNLOAD': os.path.expanduser('~/Downloads'),
            'MUSIC': os.path.expanduser('~/Music'),
            'PICTURES': os.path.expanduser('~/Pictures'),
            'VIDEOS': os.path.expanduser('~/Videos'),
            'TEMPLATES': os.path.expanduser('~/Templates'),
            'PUBLICSHARE': os.path.expanduser('~/Public'),
        }
        
        return fallback_paths.get(folder_type, os.path.expanduser('~'))
        
    def update_location_combo(self):
        self.location_combo.clear()
        self.location_combo.addItem(self.current_path)
        
        common_paths = [
            self.get_xdg_folder('HOME'),
            self.get_xdg_folder('DESKTOP'),
            self.get_xdg_folder('DOCUMENTS'),
            self.get_xdg_folder('DOWNLOAD'),
            self.get_xdg_folder('MUSIC'),
            self.get_xdg_folder('PICTURES'),
            self.get_xdg_folder('VIDEOS'),
            '/',
            '/tmp'
        ]
        
        for path in common_paths:
            if path != self.current_path and path and os.path.exists(path):
                self.location_combo.addItem(path)
                
        self.location_combo.setEditText(self.current_path)
        
    def tree_view_clicked(self, index):
        path = self.tree_model.filePath(index)
        if os.path.isdir(path):
            self.navigate_to_path(path)
            
    def places_item_double_clicked(self, item):
        path = item.data(Qt.UserRole)
        if os.path.exists(path):
            self.navigate_to_path(path)
            
    def navigate_to_path(self, path):
        self.current_path = path
        
        # Update current tab
        current_tab = self.tab_widget.currentWidget()
        if current_tab:
            current_tab.navigate_to_path(path)
            # Update tab title
            index = self.tab_widget.currentIndex()
            self.tab_widget.setTabText(index, os.path.basename(path) or path)
        
        # Update tree view
        self.tree_view.setExpanded(self.tree_model.index(path), True)
        
        # Update window title
        self.setWindowTitle(f"StormOS File Manager - {path}")
        
        # Update location combo
        self.update_location_combo()
        
    def location_combo_activated(self, index):
        if index >= 0:
            path = self.location_combo.itemText(index)
            if os.path.exists(path):
                self.navigate_to_path(path)
                
    def location_bar_return_pressed(self):
        path = self.location_combo.currentText()
        if os.path.exists(path):
            self.navigate_to_path(path)
        else:
            QMessageBox.warning(self, "Path Not Found", f"The path '{path}' does not exist.")
            self.update_location_combo()
                    
    def go_back(self):
        current_tab = self.tab_widget.currentWidget()
        if current_tab:
            current_tab.go_back()
            self.current_path = current_tab.current_path
            self.update_location_combo()
            self.setWindowTitle(f"StormOS File Manager - {self.current_path}")
            
    def go_forward(self):
        current_tab = self.tab_widget.currentWidget()
        if current_tab:
            current_tab.go_forward()
            self.current_path = current_tab.current_path
            self.update_location_combo()
            self.setWindowTitle(f"StormOS File Manager - {self.current_path}")
            
    def go_up(self):
        current_tab = self.tab_widget.currentWidget()
        if current_tab:
            current_tab.go_up()
            self.current_path = current_tab.current_path
            self.update_location_combo()
            self.setWindowTitle(f"StormOS File Manager - {self.current_path}")
            
    def go_home(self):
        self.navigate_to_path(self.get_xdg_folder('HOME'))
        
    def refresh(self):
        # Refresh current tab
        current_tab = self.tab_widget.currentWidget()
        if current_tab:
            current_tab.refresh()
        
        # Refresh tree view
        self.tree_model.setRootPath("")
        self.tree_model.setRootPath(self.current_path)
        
        # Refresh devices pane
        self.devices_pane.refresh_devices()
        
    def update_status_bar(self):
        current_tab = self.tab_widget.currentWidget()
        if current_tab:
            current_tab.update_status_bar()
            
    def open_in_new_tab(self, path=None):
        if path is None:
            # Get selected item
            current_tab = self.tab_widget.currentWidget()
            if current_tab:
                indexes = current_tab.tree_view.selectedIndexes()
                if indexes:
                    path = current_tab.list_model.filePath(indexes[0])
                    if not os.path.isdir(path):
                        return  # Only open directories in new tabs
        
        if path and os.path.isdir(path):
            self.new_tab(path)
            
    def open_in_new_window(self, path=None):
        """Open selected directory in a new window"""
        if path is None:
            # Get selected item
            current_tab = self.tab_widget.currentWidget()
            if current_tab:
                indexes = current_tab.tree_view.selectedIndexes()
                if indexes:
                    path = current_tab.list_model.filePath(indexes[0])
                    if not os.path.isdir(path):
                        return  # Only open directories in new windows
        
        if path and os.path.isdir(path):
            self.new_window(path)
        
    def open_selected(self):
        current_tab = self.tab_widget.currentWidget()
        if current_tab:
            current_tab.open_selected()
        
    def cut_selected(self):
        current_tab = self.tab_widget.currentWidget()
        if current_tab:
            indexes = current_tab.tree_view.selectedIndexes()
            if indexes:
                self.clipboard_paths = [current_tab.list_model.filePath(index) for index in indexes if index.column() == 0]
                self.clipboard_operation = 'cut'

    def copy_selected(self):
        current_tab = self.tab_widget.currentWidget()
        if current_tab:
            indexes = current_tab.tree_view.selectedIndexes()
            if indexes:
                self.clipboard_paths = [current_tab.list_model.filePath(index) for index in indexes if index.column() == 0]
                self.clipboard_operation = 'copy'

    def paste_files(self):
        if not self.clipboard_paths:
            return
            
        current_tab = self.tab_widget.currentWidget()
        if current_tab:
            if self.clipboard_operation == 'copy':
                self.copy_files(self.clipboard_paths, current_tab.current_path)
            elif self.clipboard_operation == 'cut':
                self.move_files(self.clipboard_paths, current_tab.current_path)
                
            self.clipboard_paths = []
            self.clipboard_operation = None

    def copy_files(self, source_paths, destination_dir):
        self.start_file_operation('copy', source_paths, destination_dir)

    def move_files(self, source_paths, destination_dir):
        self.start_file_operation('move', source_paths, destination_dir)

    def start_file_operation(self, operation_type, source_paths, destination_dir):
        self.progress_dialog = EnhancedProgressDialog(f"{operation_type.capitalize()} Files", self)
        self.progress_dialog.show()
        
        self.file_operation_thread = FileOperationThread(operation_type, source_paths, destination_dir)
        self.file_operation_thread.progress.connect(self.progress_dialog.update_progress)
        self.file_operation_thread.message.connect(lambda msg: self.progress_dialog.update_progress(
            self.progress_dialog.progress_bar.value(), operation_text=msg))
        self.file_operation_thread.finished_success.connect(self.on_file_operation_success)
        self.file_operation_thread.error_occurred.connect(self.on_file_operation_error)
        self.file_operation_thread.finished.connect(self.progress_dialog.accept)
        self.progress_dialog.rejected.connect(self.file_operation_thread.cancel)
        
        self.file_operation_thread.start()

    def on_file_operation_success(self):
        self.refresh()
        QMessageBox.information(self, "Success", "File operation completed successfully.")

    def on_file_operation_error(self, error_msg):
        QMessageBox.critical(self, "Error", f"File operation failed: {error_msg}")

    def handle_file_drop(self, file_paths, destination_dir, operation):
        if operation == 'copy':
            self.copy_files(file_paths, destination_dir)
        elif operation == 'move':
            self.move_files(file_paths, destination_dir)

    def new_folder(self):
        current_tab = self.tab_widget.currentWidget()
        if not current_tab:
            return
            
        name, ok = QInputDialog.getText(self, "New Folder", "Folder name:")
        if ok and name:
            folder_path = os.path.join(current_tab.current_path, name)
            try:
                os.makedirs(folder_path, exist_ok=False)
                self.refresh()
            except FileExistsError:
                QMessageBox.warning(self, "Error", "A folder with this name already exists.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Could not create folder: {str(e)}")

    def new_file(self):
        current_tab = self.tab_widget.currentWidget()
        if not current_tab:
            return
            
        name, ok = QInputDialog.getText(self, "New File", "File name:")
        if ok and name:
            file_path = os.path.join(current_tab.current_path, name)
            try:
                with open(file_path, 'w') as f:
                    pass  # Create empty file
                self.refresh()
            except FileExistsError:
                QMessageBox.warning(self, "Error", "A file with this name already exists.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Could not create file: {str(e)}")

    def rename_selected(self):
        current_tab = self.tab_widget.currentWidget()
        if not current_tab:
            return
            
        indexes = current_tab.tree_view.selectedIndexes()
        if indexes:
            path = current_tab.list_model.filePath(indexes[0])
            old_name = os.path.basename(path)
            new_name, ok = QInputDialog.getText(self, "Rename", "New name:", text=old_name)
            if ok and new_name and new_name != old_name:
                new_path = os.path.join(os.path.dirname(path), new_name)
                try:
                    os.rename(path, new_path)
                    self.refresh()
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Could not rename: {str(e)}")

    def delete_selected(self):
        current_tab = self.tab_widget.currentWidget()
        if not current_tab:
            return
            
        indexes = current_tab.tree_view.selectedIndexes()
        if indexes:
            reply = QMessageBox.question(self, "Confirm Delete", 
                                       f"Move {len(indexes) // 4} item(s) to trash?",
                                       QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                paths = [current_tab.list_model.filePath(index) for index in indexes if index.column() == 0]
                self.move_to_trash(paths)
                self.refresh()

    def permanent_delete(self):
        current_tab = self.tab_widget.currentWidget()
        if not current_tab:
            return
            
        indexes = current_tab.tree_view.selectedIndexes()
        if indexes:
            reply = QMessageBox.question(self, "Confirm Permanent Delete", 
                                       f"Permanently delete {len(indexes) // 4} item(s)?\nThis action cannot be undone.",
                                       QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                paths = [current_tab.list_model.filePath(index) for index in indexes if index.column() == 0]
                for path in paths:
                    try:
                        if os.path.isdir(path):
                            shutil.rmtree(path)
                        else:
                            os.remove(path)
                    except Exception as e:
                        QMessageBox.critical(self, "Error", f"Could not delete {path}: {str(e)}")
                self.refresh()

    def move_to_trash(self, file_paths):
        """Move files to trash using multiple methods"""
        if not file_paths:
            return
            
        try:
            # Method 1: Try gio.Trash (Python 3.4+)
            try:
                import gi
                gi.require_version('Gio', '2.0')
                from gi.repository import Gio
                
                for path in file_paths:
                    file = Gio.File.new_for_path(path)
                    if file.query_exists(None):
                        file.trash(None)
                self.refresh()
                return
            except (ImportError, AttributeError, Exception):
                pass
            
            # Method 2: Try trash-cli if available
            if shutil.which('trash'):
                try:
                    for path in file_paths:
                        subprocess.run(['trash', path])
                    self.refresh()
                    return
                except Exception:
                    pass
            
            # Method 3: Manual trash directory creation and move
            self.manual_move_to_trash(file_paths)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to move files to trash: {str(e)}")

    def manual_move_to_trash(self, file_paths):
        """Manually move files to trash directory"""
        try:
            # Create trash directories if they don't exist
            trash_dirs = [
                os.path.expanduser("~/.local/share/Trash/files"),
                os.path.expanduser("~/.local/share/Trash/info")
            ]
            
            for trash_dir in trash_dirs:
                os.makedirs(trash_dir, exist_ok=True)
            
            # Move each file to trash
            for file_path in file_paths:
                try:
                    # Create info file for trash
                    info_file = os.path.join(os.path.expanduser("~/.local/share/Trash/info"), f"{os.path.basename(file_path)}.trashinfo")
                    
                    # Create info file content
                    with open(info_file, 'w') as f:
                        f.write(f"[Trash Info]\n")
                        f.write(f"Path={file_path}\n")
                        f.write(f"DeletionDate={datetime.now().isoformat()}\n")
                    
                    # Move file to trash
                    trash_file = os.path.join(os.path.expanduser("~/.local/share/Trash/files"), os.path.basename(file_path))
                    shutil.move(file_path, trash_file)
                except Exception as e:
                    print(f"Error moving {file_path} to trash: {e}")
                    
            self.refresh()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to move files to trash: {str(e)}")

    def show_properties(self):
        current_tab = self.tab_widget.currentWidget()
        if not current_tab:
            # Show properties for current directory
            path = self.current_path
        else:
            indexes = current_tab.tree_view.selectedIndexes()
            if not indexes:
                # Show properties for current directory
                path = current_tab.current_path
            else:
                path = current_tab.list_model.filePath(indexes[0])
            
        # Create properties dialog
        dialog = QDialog(self)
        dialog.setWindowTitle("Properties")
        dialog.resize(400, 300)
        
        layout = QFormLayout(dialog)
        
        # Basic info
        name = os.path.basename(path)
        layout.addRow("Name:", QLabel(name))
        
        # Type
        if os.path.isdir(path):
            file_type = "Directory"
        else:
            ext = os.path.splitext(path)[1]
            file_type = f"File ({ext})" if ext else "File"
        layout.addRow("Type:", QLabel(file_type))
        
        # Size
        if os.path.isdir(path):
            size = self.calculate_directory_size(path)
            size_text = self.format_size(size)
        else:
            size = os.path.getsize(path)
            size_text = self.format_size(size)
        layout.addRow("Size:", QLabel(size_text))
        
        # Path
        layout.addRow("Path:", QLabel(path))
        
        # Modified time
        mtime = os.path.getmtime(path)
        mtime_str = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
        layout.addRow("Modified:", QLabel(mtime_str))
        
        # Permissions
        if os.path.isfile(path):
            try:
                file_stat = os.stat(path)
                permissions = oct(file_stat.st_mode)[-3:]
                layout.addRow("Permissions:", QLabel(permissions))
                
                # Executable status
                if self.is_file_executable(path):
                    layout.addRow("Executable:", QLabel("Yes"))
                else:
                    layout.addRow("Executable:", QLabel("No"))
            except:
                pass
        
        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)
        
        dialog.exec_()

    def calculate_directory_size(self, path):
        total_size = 0
        try:
            for dirpath, dirnames, filenames in os.walk(path):
                for f in filenames:
                    fp = os.path.join(dirpath, f)
                    if os.path.exists(fp):
                        total_size += os.path.getsize(fp)
        except (PermissionError, OSError):
            pass
        return total_size

    def format_size(self, size):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"

    def select_all(self):
        current_tab = self.tab_widget.currentWidget()
        if current_tab:
            current_tab.tree_view.selectAll()

    def select_none(self):
        current_tab = self.tab_widget.currentWidget()
        if current_tab:
            current_tab.tree_view.clearSelection()

    def invert_selection(self):
        current_tab = self.tab_widget.currentWidget()
        if not current_tab:
            return
            
        model = current_tab.tree_view.model()
        selection = current_tab.tree_view.selectionModel()
        
        # Get all items
        root_index = current_tab.tree_view.rootIndex()
        for row in range(model.rowCount(root_index)):
            index = model.index(row, 0, root_index)
            if selection.isSelected(index):
                selection.select(index, QItemSelectionModel.Deselect)
            else:
                selection.select(index, QItemSelectionModel.Select)

    def change_view_mode(self, mode):
        # Apply view mode to all tabs
        for i in range(self.tab_widget.count()):
            tab = self.tab_widget.widget(i)
            if tab:
                if mode == 'icons':
                    # For icon view, we would need to switch to QListView
                    # This is a simplified version - in practice you might want a more complex solution
                    tab.tree_view.setColumnHidden(1, True)
                    tab.tree_view.setColumnHidden(2, True)
                    tab.tree_view.setColumnHidden(3, True)
                elif mode == 'list':
                    # Show all columns for detailed view
                    tab.tree_view.setColumnHidden(1, False)
                    tab.tree_view.setColumnHidden(2, False)
                    tab.tree_view.setColumnHidden(3, False)
                elif mode == 'compact':
                    # Compact view - show only name and size
                    tab.tree_view.setColumnHidden(1, False)
                    tab.tree_view.setColumnHidden(2, True)
                    tab.tree_view.setColumnHidden(3, True)
        
        # Update menu actions
        self.view_icons_action.setChecked(mode == 'icons')
        self.view_list_action.setChecked(mode == 'list')
        self.view_compact_action.setChecked(mode == 'compact')
        
        # Refresh the view
        self.refresh()

    def toggle_toolbar(self):
        self.toolbar.setVisible(self.view_toolbar_action.isChecked())

    def toggle_statusbar(self):
        self.status_bar.setVisible(self.view_statusbar_action.isChecked())

    def toggle_sidebar(self):
        main_splitter = self.findChild(QSplitter)
        if main_splitter:
            sidebar = main_splitter.widget(0)
            sidebar.setVisible(self.view_sidebar_action.isChecked())

    def show_recent(self):
        # Placeholder for recent files functionality
        QMessageBox.information(self, "Not Implemented", "Recent files functionality will be added in a future version.")
        
    def closeEvent(self, event):
        # Save window state before closing
        self.settings_manager.save_window_state(self)
        
        # Clean up threads when closing
        if hasattr(self, 'devices_pane') and hasattr(self.devices_pane, 'usb_monitor'):
            self.devices_pane.usb_monitor.stop()
            self.devices_pane.usb_monitor.wait()
        super().closeEvent(event)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    
    # Set application-wide properties
    app.setApplicationName("StormOS File Manager")
    app.setApplicationVersion("1.0")
    app.setOrganizationName("StormOS")
    
    # Create and show the main window
    window = ThunarClone()
    window.show()
    
    sys.exit(app.exec_())