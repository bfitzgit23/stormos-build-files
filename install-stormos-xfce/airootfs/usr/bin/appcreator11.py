#!/usr/bin/env python3
import os
import sys
import subprocess
import shutil
import tempfile
import time
import re
import ast
import traceback
import json
import platform
import socket
import psutil
import requests
from pathlib import Path
from typing import Optional, List, Dict, Tuple, Set, Any
from dataclasses import dataclass

from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QWidget, 
                            QLabel, QLineEdit, QPushButton, QFileDialog,
                            QTextEdit, QProgressBar, QMessageBox, QCheckBox,
                            QHBoxLayout, QGroupBox, QTabWidget, QStyleFactory,
                            QComboBox, QSpinBox, QToolButton, QSizePolicy)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSettings, QTimer
from PyQt5.QtGui import QIcon, QTextCursor, QPalette, QColor

__version__ = "2.0.0"

@dataclass
class BuildConfig:
    script_path: str = ""
    output_dir: str = ""
    icon_path: str = ""
    app_name: str = ""
    version: str = "1.0.0"
    compression: str = "xz"
    debug_mode: bool = False
    test_after_build: bool = True
    use_system_qt: bool = False
    use_system_gtk: bool = False
    toolkit: str = "auto"  # "qt", "gtk", or "auto"
    gtk_version: str = "3"  # "3" or "4"
    extra_packages: List[str] = None
    exclude_modules: List[str] = None
    qt_webengine_needed: bool = False
    gtk_webkit_needed: bool = False
    run_in_terminal: bool = True

    def __post_init__(self):
        if self.extra_packages is None:
            self.extra_packages = []
        if self.exclude_modules is None:
            self.exclude_modules = []

class DarkTheme:
    @staticmethod
    def apply(app):
        app.setStyle(QStyleFactory.create("Fusion"))
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.Window, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.WindowText, Qt.white)
        dark_palette.setColor(QPalette.Base, QColor(35, 35, 35))
        dark_palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ToolTipBase, QColor(25, 25, 25))
        dark_palette.setColor(QPalette.ToolTipText, Qt.white)
        dark_palette.setColor(QPalette.Text, Qt.white)
        dark_palette.setColor(QPalette.Button, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ButtonText, Qt.white)
        dark_palette.setColor(QPalette.BrightText, Qt.red)
        dark_palette.setColor(QPalette.Link, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.HighlightedText, QColor(35, 35, 35))
        dark_palette.setColor(QPalette.Disabled, QPalette.ButtonText, Qt.darkGray)
        app.setPalette(dark_palette)
        app.setStyleSheet("""
            QToolTip { color: #ffffff; background-color: #2a2a2a; border: 1px solid white; }
            QGroupBox { border: 1px solid gray; border-radius: 3px; margin-top: 0.5em; }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 3px; }
            QComboBox, QLineEdit, QSpinBox { background: #353535; border: 1px solid #555; padding: 2px; min-width: 75px; }
            QPushButton { background: #454545; border: 1px solid #555; padding: 5px; min-width: 80px; }
            QPushButton:hover { background: #555555; }
            QPushButton:pressed { background: #656565; }
            QTextEdit { background: #252525; }
            QProgressBar { border: 1px solid #444; border-radius: 3px; text-align: center; }
            QProgressBar::chunk { background: #3a3; width: 10px; }
        """)

class BuildThread(QThread):
    log_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int, str)
    finished_signal = pyqtSignal(bool, str)
    global_progress_signal = pyqtSignal(int, str)
    
    def __init__(self, config):
        super().__init__()
        self.config = config
        self.detected_imports = set()
    



    def verify_disk_space(self, required_mb):
        """Check disk space during build with automatic recovery"""
        try:
            stat = shutil.disk_usage(self.temp_build_dir.parent)
            available_mb = stat.free / (1024 * 1024)
            
            if available_mb < required_mb:
                self.log(f"Low disk space warning: {available_mb:.1f}MB available, {required_mb}MB recommended", "#FF9800")
                recovered = self.cleanup_temp_files((required_mb - available_mb) * 1024 * 1024)
                if recovered > 0:
                    self.log(f"Automatically recovered {recovered/(1024*1024):.1f}MB", "#2196F3")
        except Exception as e:
            self.log(f"Space verification failed: {str(e)}", "#FF9800")
    
    def run(self):
        """Main build process with automatic cleanup"""
        try:
            self.global_progress_signal.emit(0, "Initializing build")
            self.log("\nStarting AppImage build process", "#4CAF50")
            # Check disk space first
            self.verify_disk_space(500)  # Fixed method name
            # Create temporary directory
            temp_base = os.environ.get('TMPDIR', '/tmp')
            self.temp_build_dir = Path(tempfile.mkdtemp(
                prefix=f"appimage-build-{self.config.app_name}-",
                dir=temp_base
            ))
            self.log(f"Using temporary directory: {self.temp_build_dir}")
            # Build process steps with periodic space checks
            try:
                self.global_progress_signal.emit(10, "Analyzing dependencies")
                self.analyze_script()
                self.global_progress_signal.emit(20, "Creating virtual environment")
                venv_path = self.create_virtualenv()
                self.verify_disk_space(300)  # Fixed method name
                self.global_progress_signal.emit(30, "Installing packages")
                self.install_dependencies(venv_path)
                self.verify_disk_space(200)  # Fixed method name
                self.global_progress_signal.emit(50, "Running PyInstaller")
                executable_path = self.run_pyinstaller(venv_path)
                self.verify_disk_space(150)  # Fixed method name
                self.global_progress_signal.emit(70, "Creating AppDir")
                appdir_path = self.create_appdir(executable_path)
                self.verify_disk_space(100)  # Fixed method name
                self.global_progress_signal.emit(80, "Bundling libraries")
                self.bundle_additional_libraries(appdir_path)
                self.global_progress_signal.emit(90, "Building AppImage")
                # Build the AppImage using the AppImageBuilder's method
                if hasattr(self.parent(), 'build_appimage'):
                    appimage_path = self.parent().build_appimage(appdir_path)
                else:
                    # Fallback implementation
                    appimage_path = self._build_appimage_fallback(appdir_path)
                # Verify the AppImage was created
                if not appimage_path.exists():
                    raise RuntimeError(f"AppImage creation failed - file not found at {appimage_path}")
                self.global_progress_signal.emit(100, "Build complete")
                self.finished_signal.emit(True, str(appimage_path))
            except Exception as e:
                self.log(f"\nBuild failed: {str(e)}", "#F44336")
                self.log(traceback.format_exc())
                self.finished_signal.emit(False, "")
        finally:
            if hasattr(self, 'temp_build_dir') and Path(self.temp_build_dir).exists():
                try:
                    start_space = self.get_available_space()
                    shutil.rmtree(self.temp_build_dir, ignore_errors=True)
                    end_space = self.get_available_space()
                    recovered = (end_space - start_space) / (1024 * 1024)
                    if recovered > 0:
                        self.log(f"Recovered {recovered:.1f}MB disk space", "#4CAF50")
                except Exception as e:
                    self.log(f"Warning: Cleanup failed: {str(e)}", "#FF9800")

    def _build_appimage_fallback(self, appdir):
        """Fallback AppImage building implementation"""
        os.environ['APPIMAGE_EXTRACT_AND_RUN'] = '1'
        build_dir = Path(self.temp_build_dir)
        squashfs_path = build_dir / "squashfs-root"
        squashfs_img = build_dir / "squashfs.img"
        temp_final_path = build_dir / f"{self.config.app_name}-{self.config.version}.AppImage"
        try:
            # Ensure output directory exists
            output_dir = Path(self.config.output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)

            # Clean up any existing files
            for path in [squashfs_path, squashfs_img, temp_final_path]:
                if path.exists():
                    try:
                        if path.is_dir():
                            shutil.rmtree(path)
                        else:
                            path.unlink()
                    except Exception as e:
                        self.log(f"Warning: Could not clean {path}: {str(e)}", "#FF9800")

            # Verify disk space
            self.verify_disk_space(500)

            # Copy AppDir contents
            shutil.copytree(appdir, squashfs_path)

            # Compression settings
            compression_options = {
                'xz': ['-comp', 'xz', '-Xdict-size', '100%', '-Xbcj', 'x86'],
                'zstd': ['-comp', 'zstd', '-Xcompression-level', '19'],
                'lz4': ['-comp', 'lz4', '-Xhc'],
                'gzip': ['-comp', 'gzip', '-Xcompression-level', '9']
            }

            # Run mksquashfs
            cmd = [
                "mksquashfs",
                str(squashfs_path),
                str(squashfs_img),
                *compression_options.get(self.config.compression, ['-comp', 'xz']),
                "-all-root",
                "-noappend",
                "-no-xattrs",
                "-no-fragments",
                "-b", "1M",
            ]
            if not self.config.debug_mode:
                cmd.append("-quiet")
            subprocess.run(cmd, check=True)

            # Download AppImage runtime
            runtime_urls = [
                "https://github.com/AppImage/type2-runtime/releases/download/continuous/runtime-x86_64",
                "https://github.com/AppImage/type2-runtime/releases/download/continuous/runtime-x86_64"
            ]
            runtime_path = build_dir / "runtime"
            if runtime_path.exists():
                self.log("Using pre-downloaded runtime file", "#4CAF50")
            else:
                downloaded = False
                max_retries = 3
                for url in runtime_urls:
                    for attempt in range(max_retries):
                        try:
                            self.log(f"Trying to download runtime from: {url} (Attempt {attempt + 1})")
                            response = requests.get(url, stream=True, timeout=60)
                            response.raise_for_status()
                            with open(runtime_path, 'wb') as f:
                                for chunk in response.iter_content(chunk_size=8192):
                                    f.write(chunk)
                            runtime_path.chmod(0o755)
                            downloaded = True
                            break
                        except Exception as e:
                            self.log(f"Download failed: {str(e)}", "#FF9800")
                            time.sleep(5)  # Wait before retrying
                    if downloaded:
                        break
                if not downloaded:
                    raise RuntimeError("Failed to download AppImage runtime from all sources")

            # Build AppImage
            with open(temp_final_path, 'wb') as out:
                with open(runtime_path, 'rb') as runtime:
                    out.write(runtime.read())
                with open(squashfs_img, 'rb') as fs:
                    out.write(fs.read())
            temp_final_path.chmod(0o755)

            # Move to final location
            final_path = output_dir / f"{self.config.app_name}-{self.config.version}.AppImage"
            if final_path.exists():
                final_path.unlink()
            shutil.move(str(temp_final_path), str(final_path))

            return final_path
        except Exception as e:
            self.log(f"AppImage creation failed: {str(e)}", "#F44336")
            raise

    def verify_disk_space(self, required_mb):
        """Check disk space during build with automatic recovery"""
        try:
            stat = shutil.disk_usage(self.temp_build_dir.parent)
            available_mb = stat.free / (1024 * 1024)
            
            if available_mb < required_mb:
                self.log(f"Low disk space warning: {available_mb:.1f}MB available, {required_mb}MB recommended", "#FF9800")
                recovered = self.cleanup_temp_files((required_mb - available_mb) * 1024 * 1024)
                if recovered > 0:
                    self.log(f"Automatically recovered {recovered/(1024*1024):.1f}MB", "#2196F3")
        except Exception as e:
            self.log(f"Space verification failed: {str(e)}", "#FF9800")

    def get_available_space(self, path=None):
        """Return available space in bytes for given path"""
        path = path or self.temp_build_dir.parent
        return shutil.disk_usage(path).free

    def cleanup_temp_files(self, extra_space_needed=0):
        """Clean up temporary files to free up space"""
        temp_dir = Path(tempfile.gettempdir())
        freed_space = 0
        
        # Clean old AppImage build directories
        for item in temp_dir.glob("appimage-build-*"):
            try:
                if item.is_dir():
                    # Calculate space that would be freed
                    freed_space += sum(f.stat().st_size for f in item.glob('**/*') if f.is_file())
                    shutil.rmtree(item)
                else:
                    freed_space += item.stat().st_size
                    item.unlink()
                    
                self.log(f"Cleaned temporary file: {item}", "#2196F3")
                
                # Check if we've freed enough space
                if extra_space_needed > 0 and freed_space >= extra_space_needed:
                    break
                    
            except Exception as e:
                self.log(f"Warning: Could not delete {item}: {str(e)}", "#FF9800")
        
        return freed_space

    def analyze_script(self):
        """Analyze the Python script to detect imports and toolkit requirements"""
        try:
            stdlib_modules = set(sys.stdlib_module_names) if hasattr(sys, 'stdlib_module_names') else {
                'os', 're', 'sys', 'time', 'json', 'datetime', 'logging',
                'shutil', 'subprocess', 'urllib', 'pathlib', 'ast',
                'dataclasses', 'platform', 'tempfile', 'traceback', 'typing'
            }
            
            # Read script content
            with open(self.config.script_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Reset toolkit detection
            self.config.toolkit = "auto"
            self.detected_imports = set()
            self.config.qt_webengine_needed = False
            self.config.gtk_webkit_needed = False
            
            # Parse the script using AST
            tree = ast.parse(content)
            
            # Detect imports
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.detected_imports.add(alias.name.split('.')[0])
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        self.detected_imports.add(node.module.split('.')[0])
            
            # Detect dynamic imports using regex
            dynamic_patterns = [
                r'importlib\.import_module\(["\']([^"\']+)["\']\)',
                r'__import__\(["\']([^"\']+)["\']\)',
                r'exec\(["\']import ([^"\']+)["\']\)'
            ]
            for pattern in dynamic_patterns:
                for match in re.finditer(pattern, content):
                    self.detected_imports.add(match.group(1).split('.')[0])
            
            # Detect GUI toolkit
            qt_keywords = ['PyQt5', 'PySide2', 'PySide6', 'QtWidgets', 'QtCore']
            gtk_keywords = ['Gtk', 'gi.repository.Gtk', 'PyGObject']
            
            if any(kw in content for kw in qt_keywords):
                self.config.toolkit = "qt"
                self.log("Detected Qt application")
                    
            if any(kw in content for kw in gtk_keywords):
                self.config.toolkit = "gtk"
                self.log("Detected GTK application")
            
            # Detect GTK version
            if 'Gtk.init()' in content or 'Gtk.Application' in content:
                self.config.gtk_version = "4"
            elif 'Gtk.init_check()' in content:
                self.config.gtk_version = "3"
            
            # Detect web engine requirements
            if 'QtWebEngineWidgets' in content:
                self.config.qt_webengine_needed = True
            if 'WebKit2' in content or 'WebKit' in content:
                self.config.gtk_webkit_needed = True
            
            # Filter out stdlib modules
            self.detected_imports = {imp for imp in self.detected_imports if imp not in stdlib_modules}
            
            self.log(f"Detected imports: {', '.join(sorted(self.detected_imports))}")
            
        except SyntaxError as e:
            error_msg = f"Script syntax error: {e.msg} at line {e.lineno}"
            self.log(error_msg, "#F44336")
            raise RuntimeError(error_msg) from e
        except Exception as e:
            error_msg = f"Failed to analyze script: {str(e)}"
            self.log(error_msg, "#F44336")
            raise RuntimeError(error_msg) from e

    def detect_os(self):
        """Detect the current OS and package manager"""
        try:
            with open('/etc/os-release') as f:
                os_release = f.read()
            
            if 'ubuntu' in os_release.lower() or 'debian' in os_release.lower():
                return 'apt'
            elif 'arch' in os_release.lower() or 'manjaro' in os_release.lower():
                return 'pacman'
            elif 'fedora' in os_release.lower() or 'centos' in os_release.lower():
                return 'dnf'
            elif 'opensuse' in os_release.lower():
                return 'zypper'
            else:
                return 'unknown'
        except:
            return 'unknown'

    def log(self, message, color=None):
        if color:
            self.log_signal.emit(f"<font color='{color}'>{message}</font>")
        else:
            self.log_signal.emit(message)

    def clean_old_temp_files(self):
        """Automatically clean old AppImage build directories"""
        temp_dirs = [
            Path(os.environ.get('TMPDIR', '/tmp')),
            Path.home() / 'tmp',
            Path('/var/tmp')
        ]
        
        for temp_dir in temp_dirs:
            if temp_dir.exists():
                for old_dir in temp_dir.glob('appimage-build-*'):
                    if old_dir.is_dir():
                        try:
                            shutil.rmtree(old_dir, ignore_errors=True)
                            self.log(f"Cleaned old temp dir: {old_dir}", "#2196F3")
                        except Exception as e:
                            self.log(f"Could not clean {old_dir}: {str(e)}", "#FF9800")

    def get_required_packages(self):
        """Returns the list of required packages with improved conflict resolution"""
        package_map = {
            # Qt packages
            'PyQt5': 'PyQt5',
            'PyQt5.QtWebEngineWidgets': 'PyQt5-WebEngine',
            'PySide2': 'PySide2',
            'PySide6': 'PySide6',
            
            # GTK packages (handled separately in install_dependencies)
            'Gtk': None,  # Will be handled specially
            'gi': None,   # Will be handled specially
            
            # WebKit packages
            'webkit2gtk': None,  # Handled in GTK-specific install
            'webkitgtk': None,   # Handled in GTK-specific install
            
            # Common packages
            'requests': 'requests',
            'PIL': 'Pillow',
            'numpy': 'numpy',
            'pandas': 'pandas',
            'matplotlib': 'matplotlib',
            'sqlalchemy': 'SQLAlchemy',
            'yaml': 'PyYAML',
            'dateutil': 'python-dateutil',
            'lxml': 'lxml',
            'qtpy': 'QtPy',
            'qdarkstyle': 'qdarkstyle',
            
            # Additional common packages
            'bs4': 'beautifulsoup4',
            'keyring': 'keyring',
            'notify2': 'notify2',
            'secretstorage': 'secretstorage',
            'dbus': 'dbus-python',
            '_dbus_bindings': 'dbus-python',  # Required for compiled bindings
            '_dbus_glib_bindings': 'dbus-python'
        }
        
        # Package version constraints
        version_constraints = {
            'PyGObject': f"=={self.config.gtk_version}.*" if self.config.toolkit == "gtk" else "",
            'PyQt5': "" if self.config.use_system_qt else ">=5.15.0",
            'PyQt5-WebEngine': "" if self.config.use_system_qt else ">=5.15.0",
            'PySide2': ">=5.15.0",
            'PySide6': ">=6.0.0",
            'dbus-python': ""  # No version constraint by default
        }
        
        required = set()
        for imp in self.detected_imports:
            base_pkg = imp.split('.')[0]
            
            # Skip packages that will be handled specially
            if imp in package_map and package_map[imp] is None:
                continue
                
            if imp in package_map:
                pkg = package_map[imp]
                if version_constraints.get(pkg, ""):
                    pkg += version_constraints[pkg]
                required.add(pkg)
            elif base_pkg in package_map:
                pkg = package_map[base_pkg]
                if pkg and version_constraints.get(pkg, ""):
                    pkg += version_constraints[pkg]
                required.add(pkg)
            else:
                required.add(base_pkg)
        
        # Add extra packages (with version constraints if specified)
        for pkg in self.config.extra_packages:
            if "==" in pkg or ">=" in pkg or "<=" in pkg:  # Already has version spec
                required.add(pkg)
            else:
                base_pkg = pkg.split('[')[0]  # Handle extras like package[extra]
                if base_pkg in version_constraints:
                    pkg += version_constraints[base_pkg]
                required.add(pkg)
        
        # Always add PyInstaller (unless we're doing a GTK system install)
        if not (self.config.toolkit == "gtk" and self.config.use_system_gtk):
            required.add('PyInstaller')
        
        # Remove any excluded modules
        for mod in self.config.exclude_modules:
            base_mod = mod.split('.')[0]
            required.discard(base_mod)
            required.discard(mod)
        
        # Convert to sorted list and remove duplicates
        return sorted(list(required))
        
    def install_dependencies(self, venv_path):
        """Install all required Python dependencies in the virtual environment"""
        pip_path = venv_path / "bin" / "pip"
        python_path = venv_path / "bin" / "python"

        # First install dbus-python with --no-deps to prevent conflicts
        try:
            self.log("Installing dbus-python with --no-deps...")
            subprocess.run(
                [str(pip_path), "install", "--no-deps", "dbus-python"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
        except subprocess.CalledProcessError as e:
            self.log(f"Warning: dbus-python installation failed: {e.stderr.decode()}", "#FF9800")
            self.log("Trying to install dbus-python without --no-deps...", "#FF9800")
            subprocess.run(
                [str(pip_path), "install", "dbus-python"],
                check=False  # Don't fail build if this doesn't work
            )

        # Get all required packages except those handled specially
        packages = [pkg for pkg in self.get_required_packages() 
                   if pkg not in ('dbus-python', 'PyGObject', 'webkitgtk', 'webkit2gtk')]

        if packages:
            self.log(f"Installing main packages: {', '.join(packages)}")
            try:
                subprocess.run(
                    [str(pip_path), "install"] + packages,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
            except subprocess.CalledProcessError as e:
                self.log(f"Package installation failed: {e.stderr.decode()}", "#FF9800")
                raise RuntimeError("Failed to install required packages") from e

        # Handle GTK packages separately
        if self.config.toolkit == "gtk":
            self.install_gtk_dependencies(venv_path)

        # Handle QtWebEngine special case
        if self.config.qt_webengine_needed and not self.config.use_system_qt:
            self.handle_qtwebengine(venv_path)

    def install_gtk_dependencies(self, venv_path):
        """Install GTK-specific dependencies with OS detection"""
        pip_path = venv_path / "bin" / "pip"
        os_type = self.detect_os()
        
        try:
            if os_type == 'apt':
                packages = [
                    "python3-gi", 
                    f"gir1.2-gtk-{self.config.gtk_version}.0",
                    "libgirepository1.0-dev"
                ]
                subprocess.run(
                    ["sudo", "apt-get", "install", "-y"] + packages,
                    check=True
                )
            elif os_type == 'pacman':
                packages = [
                    "python-gobject",
                    f"gtk{self.config.gtk_version}",
                    "gobject-introspection"
                ]
                subprocess.run(
                    ["sudo", "pacman", "-S", "--noconfirm"] + packages,
                    check=True
                )
            elif os_type == 'dnf':
                packages = [
                    "python3-gobject",
                    f"gtk{self.config.gtk_version}-devel",
                    "gobject-introspection-devel"
                ]
                subprocess.run(
                    ["sudo", "dnf", "install", "-y"] + packages,
                    check=True
                )
            else:
                self.log("Warning: Unsupported OS for automatic GTK installation", "#FF9800")
                raise RuntimeError("Unsupported OS")
            
            # Install PyGObject
            gtk_pkg = f"PyGObject=={self.config.gtk_version}.*"
            self.log(f"Installing {gtk_pkg}")
            subprocess.run(
                [str(pip_path), "install", gtk_pkg],
                check=True
            )
            
        except Exception as e:
            self.log(f"Warning: GTK installation fallback: {str(e)}", "#FF9800")
            # Fallback to pip only
            subprocess.run(
                [str(pip_path), "install", "PyGObject"],
                check=False
            )

    def handle_qtwebengine(self, venv_path):
        """Special handling for QtWebEngine"""
        pip_path = venv_path / "bin" / "pip"
        python_path = venv_path / "bin" / "python"
        
        self.log("Setting up QtWebEngine...")
        try:
            sys_python_path = subprocess.run(
                [sys.executable, "-c", "import PyQt5, os; print(os.path.dirname(PyQt5.__file__))"],
                check=True,
                stdout=subprocess.PIPE,
                text=True
            ).stdout.strip()
            
            venv_site_packages = subprocess.run(
                [str(python_path), "-c", "import PyQt5, os; print(os.path.dirname(PyQt5.__file__))"],
                check=True,
                stdout=subprocess.PIPE,
                text=True
            ).stdout.strip()
            
            qt5_dir = Path(sys_python_path)
            venv_qt5_dir = Path(venv_site_packages)
            
            if qt5_dir.exists():
                if venv_qt5_dir.exists():
                    shutil.rmtree(venv_qt5_dir)
                venv_qt5_dir.symlink_to(qt5_dir)
                self.log(f"Created symlink: {venv_qt5_dir} -> {qt5_dir}")
            else:
                self.log("Warning: System PyQt5 not found - WebEngine may not work", "#FF9800")
                
        except Exception as e:
            self.log(f"Warning: Could not setup QtWebEngine: {str(e)}", "#FF9800")

    def create_virtualenv(self):
        """Create and configure a Python virtual environment"""
        venv_path = Path(self.temp_build_dir) / "venv"
        
        try:
            # Create the virtual environment
            self.log(f"Creating virtual environment at {venv_path}")
            subprocess.run([sys.executable, "-m", "venv", str(venv_path)], check=True)
            
            # Verify the virtual environment was created
            if not (venv_path / "bin" / "python").exists():
                raise RuntimeError("Virtual environment creation failed - python binary not found")
                
            return venv_path
            
        except subprocess.CalledProcessError as e:
            self.log(f"Virtual environment creation failed with error: {e}", "#FF0000")
            raise RuntimeError("Failed to create virtual environment") from e

    def run_pyinstaller(self, venv_path):
        python_path = venv_path / "bin" / "python"
        dist_path = Path(self.temp_build_dir) / "dist"
        
        # Base PyInstaller command
        cmd = [
            str(python_path), "-m", "PyInstaller",
            "--onefile",
            "--name", self.config.app_name,
            "--distpath", str(dist_path),
            "--workpath", str(Path(self.temp_build_dir) / "build"),
            "--specpath", str(self.temp_build_dir),
            "--clean",
            "--noconfirm",
            "--hidden-import", "PyQt5.sip",
        ]

        # Add icon if specified
        if self.config.icon_path:
            cmd.extend(["--icon", self.config.icon_path])

        # Debug mode options
        if self.config.debug_mode:
            cmd.append("--debug=all")
        else:
            cmd.append("--strip")  # Reduce binary size in production
            cmd.append("--noupx")  # Disable UPX for more reliable builds

        # Toolkit-specific options
        if self.config.toolkit == "qt" and not self.config.use_system_qt:
            cmd.extend(["--collect-all", "PyQt5"])
            if self.config.qt_webengine_needed:
                cmd.extend(["--collect-all", "PyQt5.QtWebEngineWidgets"])
        
        # Add the main script path
        cmd.append(self.config.script_path)

        # Run PyInstaller
        try:
            self.log("\nRunning PyInstaller with command:")
            self.log(" ".join(cmd), "#2196F3")
            
            subprocess.run(cmd, check=True)
            
            # Verify the executable was created
            executable = dist_path / self.config.app_name
            if not executable.exists():
                raise RuntimeError(f"PyInstaller failed to create {executable}")
            
            # Set executable permissions
            executable.chmod(0o755)
            self.log(f"\nSuccessfully created executable: {executable}")
            
            # Test the executable if enabled
            if self.config.test_after_build:
                self.test_executable(executable)
                
            return executable
            
        except subprocess.CalledProcessError as e:
            error_msg = f"PyInstaller failed with exit code {e.returncode}"
            if e.stdout:
                self.log(f"PyInstaller stdout:\n{e.stdout.decode()}", "#FF9800")
            if e.stderr:
                self.log(f"PyInstaller stderr:\n{e.stderr.decode()}", "#F44336")
            raise RuntimeError(error_msg) from e

    def test_executable(self, executable_path):
        """Test the generated executable with improved handling"""
        test_script = self.temp_build_dir / "test_script.py"
        test_script.write_text("print('EXECUTABLE_TEST_OK')\nimport sys; sys.exit(0)")
        
        try:
            self.log("\nTesting executable...")
            result = subprocess.run(
                [str(executable_path), str(test_script)],
                timeout=10,  # Reduced timeout from 15 to 10 seconds
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if "EXECUTABLE_TEST_OK" not in result.stdout:
                self.log(f"Unexpected test output:\n{result.stdout}", "#FF9800")
                self.log(f"Test errors:\n{result.stderr}", "#FF9800")
                raise RuntimeError("Executable test failed - unexpected output")
                
            self.log("Executable test passed", "#4CAF50")
            
        except subprocess.TimeoutExpired:
            self.log("Warning: Executable test timed out (may still work)", "#FF9800")
            if self.config.debug_mode:
                raise RuntimeError("Executable test timeout in debug mode")
                
        except Exception as e:
            self.log(f"Warning: Executable test failed: {str(e)}", "#FF9800")
            if self.config.debug_mode:
                raise RuntimeError("Executable test failed in debug mode") from e

    def create_appdir(self, executable_path):
        try:
            appdir = Path(self.temp_build_dir) / f"{self.config.app_name}.AppDir"
            
            # Create directory structure
            (appdir / "usr" / "bin").mkdir(parents=True, exist_ok=True)
            (appdir / "usr" / "share" / "applications").mkdir(parents=True, exist_ok=True)
            (appdir / "usr" / "share" / "icons").mkdir(parents=True, exist_ok=True)

            # Copy executable
            dest_executable = appdir / "usr" / "bin" / self.config.app_name
            shutil.copy(executable_path, dest_executable)
            dest_executable.chmod(0o755)

            # --- Key Fix: AppRun with Terminal Support ---
            apprun_path = appdir / "AppRun"
            apprun_content = f"""#!/bin/sh
            HERE="$(dirname "$(readlink -f "$0")")"
            export PATH="$HERE/usr/bin:$PATH"
            export LD_LIBRARY_PATH="$HERE/usr/lib:$LD_LIBRARY_PATH"
            exec "$HERE/usr/bin/{self.config.app_name}" "$@"
            """
            with open(apprun_path, 'w') as f:
                f.write(apprun_content)
            apprun_path.chmod(0o755)

            # --- Updated .desktop File ---
            desktop_path = appdir / f"{self.config.app_name}.desktop"
            desktop_content = f"""[Desktop Entry]
    Name={self.config.app_name}
    Exec={self.config.app_name}
    Icon={self.config.app_name}
    Type=Application
    Categories=Utility;
    StartupNotify=true
    """
            with open(desktop_path, 'w') as f:
                f.write(desktop_content)

            # Handle icon
            if self.config.icon_path:
                shutil.copy(self.config.icon_path, appdir / f"{self.config.app_name}.png")

            return appdir

        except Exception as e:
            self.log(f"Error creating AppDir: {str(e)}", "#F44336")
            raise

    def bundle_additional_libraries(self, appdir):
        lib_dir = appdir / "usr" / "lib"
        lib_dir.mkdir(parents=True, exist_ok=True)
        
        # Common libraries
        libraries = ['libssl.so', 'libcrypto.so']
        
        # Qt-specific
        if self.config.toolkit == "qt" and not self.config.use_system_qt:
            libraries.extend(['libQt5Core.so', 'libQt5Gui.so', 'libQt5Widgets.so'])
            if self.config.qt_webengine_needed:
                libraries.extend(['libQt5WebEngineCore.so', 'libQt5WebEngineWidgets.so'])
        
        # GTK-specific
        if self.config.toolkit == "gtk" and not self.config.use_system_gtk:
            version = self.config.gtk_version
            libraries.extend([
                f'libgtk-{version}.so',
                f'libgdk-{version}.so',
                'libglib-2.0.so',
                'libgobject-2.0.so',
                'libgmodule-2.0.so',
            ])
            if self.config.gtk_webkit_needed:
                libraries.append('libwebkit2gtk-4.0.so' if version == "4" else 'libwebkitgtk-3.0.so')
        
        # Copy libraries
        for lib in libraries:
            try:
                lib_path = Path(subprocess.run(
                    ['ldconfig', '-p'],
                    stdout=subprocess.PIPE,
                    text=True
                ).stdout.split(f'{lib} (')[0].split()[-1])
                
                if lib_path.exists():
                    shutil.copy(lib_path, lib_dir)
                    self.log(f"Bundled system library: {lib}")
            except Exception as e:
                self.log(f"Warning: Could not bundle {lib}: {str(e)}", "#FF9800")
        
        # GTK-specific additional files
        if self.config.toolkit == "gtk":
            # Add GTK schemas
            (appdir / "usr" / "share" / "glib-2.0" / "schemas").mkdir(parents=True)
            subprocess.run([
                "glib-compile-schemas",
                "/usr/share/glib-2.0/schemas",
                "--targetdir",
                str(appdir / "usr" / "share" / "glib-2.0" / "schemas")
            ])
            
            # Add GDK pixbuf loaders
            (appdir / "usr" / "lib" / "gdk-pixbuf-2.0" / "2.10.0" / "loaders").mkdir(parents=True)
            subprocess.run([
                "gdk-pixbuf-query-loaders",
                "--update-cache",
                str(appdir / "usr" / "lib" / "gdk-pixbuf-2.0" / "2.10.0" / "loaders.cache")
            ])

class AppImageBuilder(QMainWindow):
    def __init__(self):
        super().__init__()
        self.settings = QSettings("AppImageBuilder", "QtAppImageBuilder")
        self.config = BuildConfig()
        self.final_appimage_path = ""
        
        self.init_ui()
        self.load_settings()
    
    def init_ui(self):
        self.setWindowTitle("Universal AppImage Builder")
        self.setGeometry(100, 100, 1000, 800)
        
        self.init_global_progress()
        
        self.tabs = QTabWidget()
        
        # Basic Settings Tab
        self.basic_tab = QWidget()
        self.init_basic_tab()
        self.tabs.addTab(self.basic_tab, "Basic Settings")
        
        # Advanced Settings Tab
        self.advanced_tab = QWidget()
        self.init_advanced_tab()
        self.tabs.addTab(self.advanced_tab, "Advanced Settings")
        
        # Log Tab
        self.log_tab = QWidget()
        self.init_log_tab()
        self.tabs.addTab(self.log_tab, "Build Log")
        
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready")
        self.setCentralWidget(self.tabs)
        DarkTheme.apply(QApplication.instance())
    
    def init_global_progress(self):
        self.global_progress = QProgressBar()
        self.global_progress.setRange(0, 100)
        self.global_progress.setTextVisible(True)
        self.global_progress.hide()
        self.statusBar().addPermanentWidget(self.global_progress)
    
    def init_basic_tab(self):
        layout = QVBoxLayout()
        
        # App Info Group
        app_info_group = QGroupBox("Application Information")
        app_info_layout = QVBoxLayout()
        
        # App Name
        self.name_entry = QLineEdit()
        self.name_entry.setPlaceholderText("MyApp")
        app_info_layout.addWidget(QLabel("Application Name:"))
        app_info_layout.addWidget(self.name_entry)
        
        # Version
        self.version_entry = QLineEdit()
        self.version_entry.setPlaceholderText("1.0.0")
        app_info_layout.addWidget(QLabel("Version:"))
        app_info_layout.addWidget(self.version_entry)
        
        # Script Selection
        self.script_btn = QPushButton("Select Python Script")
        self.script_btn.clicked.connect(self.select_script)
        self.script_path_label = QLabel("No script selected")
        app_info_layout.addWidget(QLabel("Main Script:"))
        app_info_layout.addWidget(self.script_btn)
        app_info_layout.addWidget(self.script_path_label)
        
        app_info_group.setLayout(app_info_layout)
        layout.addWidget(app_info_group)
        
        # Toolkit Selection
        toolkit_group = QGroupBox("Toolkit")
        toolkit_layout = QHBoxLayout()
        
        self.toolkit_combo = QComboBox()
        self.toolkit_combo.addItems(["Auto-detect", "Qt", "GTK"])
        toolkit_layout.addWidget(QLabel("Toolkit:"))
        toolkit_layout.addWidget(self.toolkit_combo)
        
        self.gtk_version_combo = QComboBox()
        self.gtk_version_combo.addItems(["GTK 3", "GTK 4"])
        toolkit_layout.addWidget(QLabel("GTK Version:"))
        toolkit_layout.addWidget(self.gtk_version_combo)
        self.gtk_version_combo.setEnabled(False)
        
        toolkit_group.setLayout(toolkit_layout)
        layout.addWidget(toolkit_group)
        
        # Output Group
        output_group = QGroupBox("Output Settings")
        output_layout = QVBoxLayout()
        
        # Output Directory
        self.output_btn = QPushButton("Select Output Directory")
        self.output_btn.clicked.connect(self.select_output)
        self.output_path_label = QLabel("No directory selected")
        output_layout.addWidget(QLabel("Output Directory:"))
        output_layout.addWidget(self.output_btn)
        output_layout.addWidget(self.output_path_label)
        
        # Icon Selection
        self.icon_btn = QPushButton("Select Icon")
        self.icon_btn.clicked.connect(self.select_icon)
        self.icon_path_label = QLabel("No icon selected")
        output_layout.addWidget(QLabel("Application Icon:"))
        output_layout.addWidget(self.icon_btn)
        output_layout.addWidget(self.icon_path_label)
        
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        
        # Options Group
        options_group = QGroupBox("Options")
        options_layout = QVBoxLayout()
        
        self.test_checkbox = QCheckBox("Test AppImage after build")
        self.test_checkbox.setChecked(True)
        options_layout.addWidget(self.test_checkbox)

        self.terminal_checkbox = QCheckBox("Run AppImage in terminal (for CLI apps)")
        self.terminal_checkbox.setChecked(True)  # Default enabled
        options_layout.addWidget(self.terminal_checkbox)

        self.debug_checkbox = QCheckBox("Enable debug mode")
        options_layout.addWidget(self.debug_checkbox)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Build Button
        self.build_btn = QPushButton("Build AppImage")
        self.build_btn.clicked.connect(self.start_build)
        self.build_btn.setStyleSheet("font-weight: bold;")
        layout.addWidget(self.build_btn)
        
        # Progress Bar
        self.basic_progress = QProgressBar()
        layout.addWidget(self.basic_progress)
        
        self.basic_tab.setLayout(layout)
        
        # Connect signals
        self.toolkit_combo.currentTextChanged.connect(self.update_toolkit_ui)

    def check_disk_space(self, required_mb):
        """Check disk space using parent's method if available, otherwise use local implementation"""
        if hasattr(self.parent(), 'check_disk_space'):
            return self.parent().check_disk_space(required_mb)
        else:
            # Fallback implementation
            try:
                temp_dir = Path(tempfile.gettempdir())
                stat = shutil.disk_usage(temp_dir)
                available_mb = stat.free / (1024 * 1024)
                return available_mb >= required_mb
            except Exception as e:
                self.log(f"Disk space check failed: {str(e)}", "#F44336")
                return False
    
    def update_toolkit_ui(self, toolkit):
        is_gtk = toolkit == "GTK"
        self.gtk_version_combo.setEnabled(is_gtk)
    
    def init_advanced_tab(self):
        layout = QVBoxLayout()
        
        # Compression Settings
        compression_group = QGroupBox("Compression Settings")
        compression_layout = QHBoxLayout()
        
        self.compression_combo = QComboBox()
        self.compression_combo.addItems(["xz", "gzip", "lzo", "lz4", "zstd"])
        self.compression_combo.setCurrentText("xz")
        compression_layout.addWidget(QLabel("Compression:"))
        compression_layout.addWidget(self.compression_combo)
        compression_layout.addStretch()
        
        compression_group.setLayout(compression_layout)
        layout.addWidget(compression_group)
        
        # Dependency Settings
        dep_group = QGroupBox("Dependency Management")
        dep_layout = QVBoxLayout()
        
        self.system_qt_check = QCheckBox("Use system Qt libraries (smaller size but less portable)")
        dep_layout.addWidget(self.system_qt_check)
        
        self.system_gtk_check = QCheckBox("Use system GTK libraries (smaller size but less portable)")
        dep_layout.addWidget(self.system_gtk_check)
        
        # Extra Packages
        self.extra_pkg_entry = QLineEdit()
        self.extra_pkg_entry.setPlaceholderText("comma-separated packages (numpy,pandas,etc.)")
        dep_layout.addWidget(QLabel("Extra Python Packages:"))
        dep_layout.addWidget(self.extra_pkg_entry)
        
        # Exclude Modules
        self.exclude_mod_entry = QLineEdit()
        self.exclude_mod_entry.setPlaceholderText("dbus,notify2")
        dep_layout.addWidget(QLabel("Exclude Modules:"))
        dep_layout.addWidget(self.exclude_mod_entry)
        
        dep_group.setLayout(dep_layout)
        layout.addWidget(dep_group)
        
        # Test Button
        self.test_btn = QPushButton("Test Last AppImage")
        self.test_btn.clicked.connect(self.test_appimage)
        self.test_btn.hide()
        layout.addWidget(self.test_btn)
        
        # Add self-build button
        self.self_build_btn = QPushButton("Build This App as AppImage")
        self.self_build_btn.clicked.connect(self.build_self)
        layout.addWidget(self.self_build_btn)

        # Progress Bar
        self.advanced_progress = QProgressBar()
        layout.addWidget(self.advanced_progress)
        
        layout.addStretch()
        self.advanced_tab.setLayout(layout)

    def build_self(self):
        """Build this AppImage builder as an AppImage with terminal support"""
        # Skip if already running as AppImage
        if 'APPIMAGE' in os.environ:
            QMessageBox.warning(self, "Warning", 
                "Cannot build AppImage while running as an AppImage.")
            return

        self.self_building = True
        try:
            # Set build parameters
            self.config.script_path = os.path.abspath(__file__)
            self.config.app_name = "AppImageBuilder"
            self.config.version = __version__
            
            # Configure for terminal-friendly build
            self.config.test_after_build = True
            self.config.debug_mode = True  # Get more verbose output
            
            # Find an icon - fixed syntax and added more possible locations
            icon_candidates = [
                os.path.join(os.path.dirname(__file__), "icon.png"),
                os.path.join(os.path.dirname(__file__), "appimage-builder.png"),
                "/usr/share/icons/hicolor/256x256/apps/utilities-terminal.png",
                "/usr/share/pixmaps/python.xpm",
                "/usr/share/icons/hicolor/scalable/apps/terminal.svg"
            ]
            
            for icon in icon_candidates:
                try:
                    if isinstance(icon, (list, tuple)):  # Handle path components
                        icon = os.path.join(*icon)
                    if icon and os.path.exists(icon):
                        self.config.icon_path = icon
                        self.log(f"Using icon: {icon}", "#4CAF50")
                        break
                except Exception as e:
                    self.log(f"Warning: Could not access icon candidate {icon}: {str(e)}", "#FF9800")

            # Set output directory
            self.config.output_dir = os.getcwd()
            
            # Configure build settings
            self.config.toolkit = "qt"
            self.config.use_system_qt = False
            self.config.compression = "zstd"  # Faster compression for self-build
            
            self.log("\n=== STARTING SELF-BUILD ===", "#4CAF50")
            self.log(f"Building version {__version__}", "#2196F3")
            self.log(f"Source: {self.config.script_path}")
            self.log(f"Output: {self.config.output_dir}")
            
            # Disable buttons during build
            self.build_btn.setEnabled(False)
            self.self_build_btn.setEnabled(False)
            
            # Start build
            self.start_build()
            
        except Exception as e:
            error_msg = f"CRITICAL ERROR: {str(e)}"
            self.log(error_msg, "#FF0000")
            self.log(traceback.format_exc(), "#FF0000")
            
            # Keep terminal open on crash
            if platform.system() != 'Windows':
                try:
                    print("\n\n=== BUILD FAILED ===")
                    print("The terminal will remain open so you can see the error.")
                    print("Close it manually when ready.\n")
                    input("Press Enter to exit...")
                except:
                    pass  # Fallback if input fails
            else:
                # On Windows, show message box with error
                QMessageBox.critical(self, "Build Failed", 
                    f"The build failed with error:\n\n{str(e)}\n\n"
                    "Check the log tab for details.")
                    
        finally:
            self.self_build_btn.setEnabled(True)
            self.build_btn.setEnabled(True)
            self.self_building = False
            self.log("=== SELF-BUILD COMPLETED ===", "#4CAF50")

    def _ensure_temp_space(self, min_gb):
        """Ensure a temp directory with at least `min_gb` GB free space exists."""
        candidates = [
            os.environ.get('TMPDIR', '/tmp'),  # Default temp
            '/var/tmp',                        # Usually larger
            os.path.expanduser('~/tmp'),       # User's home
            '/mnt/tmp'                         # Custom mount
        ]
        
        for temp_dir in candidates:
            try:
                # Check space
                stat = shutil.disk_usage(temp_dir)
                free_gb = stat.free / (1024 ** 3)
                
                if free_gb >= min_gb:
                    return temp_dir  # Suitable directory found
                
                # Try to clean old files
                self._clean_temp_files(temp_dir)
                stat = shutil.disk_usage(temp_dir)
                free_gb = stat.free / (1024 ** 3)
                
                if free_gb >= min_gb:
                    return temp_dir
                    
            except Exception:
                continue
        
        # No suitable directory found
        raise RuntimeError(
            f"Could not find a temp directory with {min_gb}GB free space.\n"
            f"Tried: {', '.join(candidates)}\n"
            "Please free up space or set TMPDIR manually."
        )

    def _clean_temp_files(self, temp_dir):
        """Clean old AppImage build files in `temp_dir`."""
        temp_path = Path(temp_dir)
        for item in temp_path.glob('appimage-build-*'):
            try:
                if item.is_dir():
                    shutil.rmtree(item, ignore_errors=True)
                else:
                    item.unlink()
            except Exception:
                pass
    
    def init_log_tab(self):
        layout = QVBoxLayout()
        
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setStyleSheet("""
            font-family: 'Courier New', monospace;
            font-size: 12px;
            background-color: #252525;
            color: #e0e0e0;
        """)
        
        # Log controls
        log_controls = QHBoxLayout()
        self.clear_log_btn = QPushButton("Clear Log")
        self.clear_log_btn.clicked.connect(self.log_output.clear)
        self.save_log_btn = QPushButton("Save Log")
        self.save_log_btn.clicked.connect(self.save_log)
        
        log_controls.addWidget(self.clear_log_btn)
        log_controls.addWidget(self.save_log_btn)
        log_controls.addStretch()
        
        layout.addLayout(log_controls)
        layout.addWidget(self.log_output)
        
        # Progress Bar
        self.log_progress = QProgressBar()
        layout.addWidget(self.log_progress)
        
        self.log_tab.setLayout(layout)
    
    def update_global_progress(self, value, message):
        self.global_progress.setValue(value)
        self.global_progress.setFormat(f"{message} ({value}%)")
        
        self.basic_progress.setValue(value)
        self.advanced_progress.setValue(value)
        self.log_progress.setValue(value)
        
        if value >= 100:
            QTimer.singleShot(2000, self.global_progress.hide)
    
    def load_settings(self):
        self.settings.beginGroup("MainWindow")
        self.resize(self.settings.value("size", self.size()))
        self.move(self.settings.value("pos", self.pos()))
        self.settings.endGroup()
        
        self.settings.beginGroup("Config")
        self.name_entry.setText(self.settings.value("app_name", ""))
        self.version_entry.setText(self.settings.value("version", "1.0.0"))
        
        # Load script path and update name if script exists
        script_path = self.settings.value("script_path", "")
        self.script_path_label.setText(script_path if script_path else "No script selected")
        if script_path and not self.name_entry.text():
            self.name_entry.setText(Path(script_path).stem)
        
        self.output_path_label.setText(self.settings.value("output_dir", "No directory selected"))
        self.icon_path_label.setText(self.settings.value("icon_path", "No icon selected"))
        
        # Toolkit settings
        toolkit_map = {"qt": "Qt", "gtk": "GTK", "auto": "Auto-detect"}
        self.toolkit_combo.setCurrentText(
            toolkit_map.get(self.settings.value("toolkit", "auto"), "Auto-detect")
        )
        self.gtk_version_combo.setCurrentText(
            f"GTK {self.settings.value('gtk_version', '3')}"
        )
        
        self.terminal_checkbox.setChecked(
            self.settings.value("run_in_terminal", True, type=bool)
        )

        self.test_checkbox.setChecked(self.settings.value("test_after_build", True, type=bool))
        self.debug_checkbox.setChecked(self.settings.value("debug_mode", False, type=bool))
        self.compression_combo.setCurrentText(self.settings.value("compression", "xz"))
        self.system_qt_check.setChecked(self.settings.value("use_system_qt", False, type=bool))
        self.system_gtk_check.setChecked(self.settings.value("use_system_gtk", False, type=bool))
        self.extra_pkg_entry.setText(self.settings.value("extra_packages", ""))
        self.exclude_mod_entry.setText(self.settings.value("exclude_modules", ""))
        self.settings.endGroup()
        
        self.update_config_from_ui()
        self.update_toolkit_ui(self.toolkit_combo.currentText())
    
    def save_settings(self):
        self.settings.beginGroup("MainWindow")
        self.settings.setValue("size", self.size())
        self.settings.setValue("pos", self.pos())
        self.settings.endGroup()
        
        self.settings.beginGroup("Config")
        self.settings.setValue("app_name", self.config.app_name)
        self.settings.setValue("version", self.config.version)
        self.settings.setValue("script_path", self.config.script_path)
        self.settings.setValue("output_dir", self.config.output_dir)
        self.settings.setValue("icon_path", self.config.icon_path)
        self.settings.setValue("toolkit", self.config.toolkit)
        self.settings.setValue("gtk_version", self.config.gtk_version)
        self.settings.setValue("test_after_build", self.config.test_after_build)
        self.settings.setValue("debug_mode", self.config.debug_mode)
        self.settings.setValue("compression", self.config.compression)
        self.settings.setValue("use_system_qt", self.config.use_system_qt)
        self.settings.setValue("use_system_gtk", self.config.use_system_gtk)
        self.settings.setValue("extra_packages", ",".join(self.config.extra_packages))
        self.settings.setValue("exclude_modules", ",".join(self.config.exclude_modules))
        self.settings.setValue("run_in_terminal", self.config.run_in_terminal)
        self.settings.endGroup()
    
    def update_config_from_ui(self):
        self.config.app_name = self.name_entry.text().strip()
        self.config.version = self.version_entry.text().strip()
        self.config.script_path = self.script_path_label.text() if self.script_path_label.text() != "No script selected" else ""
        self.config.output_dir = self.output_path_label.text() if self.output_path_label.text() != "No directory selected" else ""
        self.config.icon_path = self.icon_path_label.text() if self.icon_path_label.text() != "No icon selected" else ""
        self.config.run_in_terminal = self.terminal_checkbox.isChecked()

        # Toolkit settings
        toolkit_map = {"Auto-detect": "auto", "Qt": "qt", "GTK": "gtk"}
        self.config.toolkit = toolkit_map.get(self.toolkit_combo.currentText(), "auto")
        self.config.gtk_version = self.gtk_version_combo.currentText()[-1]  # "3" or "4"
        
        self.config.test_after_build = self.test_checkbox.isChecked()
        self.config.debug_mode = self.debug_checkbox.isChecked()
        self.config.compression = self.compression_combo.currentText()
        self.config.use_system_qt = self.system_qt_check.isChecked()
        self.config.use_system_gtk = self.system_gtk_check.isChecked()
        self.config.extra_packages = [pkg.strip() for pkg in self.extra_pkg_entry.text().split(",") if pkg.strip()]
        self.config.exclude_modules = [mod.strip() for mod in self.exclude_mod_entry.text().split(",") if mod.strip()]
    
    def log(self, message, color=None):
        if color:
            self.log_output.setTextColor(QColor(color))
        self.log_output.append(message)
        if color:
            self.log_output.setTextColor(QColor("#e0e0e0"))  # Reset to default
        
        self.log_output.moveCursor(QTextCursor.End)
        self.log_output.ensureCursorVisible()
        
        if message.startswith("ERROR:") or message.startswith("Warning:"):
            self.status_bar.showMessage(message, 5000)
    
    def select_script(self):
        path, _ = QFileDialog.getOpenFileName(
            self, 
            "Select Python Script", 
            self.config.script_path or str(Path.home()),
            "Python Files (*.py)"
        )
        if path:
            self.config.script_path = path
            self.script_path_label.setText(path)
            
            # Always update the app name based on script filename
            script_name = Path(path).stem
            self.name_entry.setText(script_name)
            self.config.app_name = script_name
            
            self.log(f"Selected script: {path}")
    
    def select_output(self):
        path = QFileDialog.getExistingDirectory(
            self, 
            "Select Output Directory", 
            self.config.output_dir or str(Path.home())
        )
        if path:
            self.config.output_dir = path
            self.output_path_label.setText(path)
            self.log(f"Output directory: {path}")
    
    def select_icon(self):
        path, _ = QFileDialog.getOpenFileName(
            self, 
            "Select Icon", 
            self.config.icon_path or str(Path.home()),
            "Image Files (*.png *.svg *.ico)"
        )
        if path:
            self.config.icon_path = path
            self.icon_path_label.setText(path)
            self.log(f"Selected icon: {path}")
    
    def save_log(self):
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Log File",
            str(Path.home() / f"{self.config.app_name or 'appimage'}_build.log"),
            "Log Files (*.log);;All Files (*)"
        )
        if path:
            try:
                with open(path, 'w') as f:
                    f.write(self.log_output.toPlainText())
                self.log(f"Log saved to: {path}", "#4CAF50")
            except Exception as e:
                self.log(f"ERROR: Failed to save log: {str(e)}", "#F44336")
    
    def validate_inputs(self):
        """Validate all build inputs with comprehensive checks"""
        self.update_config_from_ui()

        # Basic field validation
        validation_checks = [
            (not self.config.app_name, "Application name is required"),
            (not self.config.script_path, "Python script is required"),
            (not Path(self.config.script_path).exists(), "Selected script does not exist"),
            (not self.config.output_dir, "Output directory is required"),
        ]
        for condition, error_msg in validation_checks:
            if condition:
                self.show_error(error_msg)
                return False

        # Output directory validation
        try:
            output_path = Path(self.config.output_dir)
            if not output_path.exists():
                output_path.mkdir(parents=True, exist_ok=True)
            if not os.access(output_path, os.W_OK):
                raise PermissionError(f"No write permission for directory: {output_path}")
        except Exception as e:
            self.show_error(f"Cannot access output directory: {str(e)}")
            return False

        # Script content validation
        try:
            with open(self.config.script_path, 'r') as f:
                if not f.read(1):  # Check if file is empty
                    self.show_warning("Script file appears to be empty")
        except Exception as e:
            self.show_error(f"Cannot read script file: {str(e)}")
            return False

        # Disk space check (minimum 500MB free)
        if not self.check_disk_space(500):  # Fixed method name
            self.show_warning("Low disk space warning - at least 500MB recommended for building")
            return False

        # Toolkit-specific validation
        if not self.validate_toolkit_environment():
            return False

        # System tool validation
        if not self.validate_system_tools():
            return False

        # FUSE configuration check
        if not shutil.which('fusermount3') and 'APPIMAGE_EXTRACT_AND_RUN' not in os.environ:
            self.show_warning(
                "FUSE not configured properly. AppImages will use extract-and-run mode."
                "For better performance, install fuse packages (usually 'fuse' or 'fuse3')."
            )
        return True

    def validate_toolkit_environment(self):
        """Validate toolkit-specific requirements"""
        # Skip validation if we're building ourselves
        if hasattr(self, 'self_building') and self.self_building:
            return True
            
        if self.config.toolkit == "gtk":
            try:
                # Check for GI availability
                subprocess.run(
                    ["python", "-c", 
                     f"import gi; gi.require_version('Gtk', '{self.config.gtk_version}.0'); "
                     f"from gi.repository import Gtk"],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=5
                )
            except subprocess.TimeoutExpired:
                self.show_error("GTK environment check timed out")
                return False
            except Exception as e:
                error_msg = (
                    "GTK development environment not properly configured.\n\n"
                    "For Arch Linux, please install these packages:\n\n"
                    "sudo pacman -S python-gobject gtk3 webkit2gtk gobject-introspection\n"
                    "For GTK4 support: sudo pacman -S gtk4\n\n"
                    f"Original error: {str(e)}"
                )
                self.show_error(error_msg)
                return False
        return True

    def validate_system_tools(self):
        """Validate required system tools are available"""
        required_tools = {
            'python3': "Python interpreter",
            'pip3': "Python package manager",
            'mksquashfs': "SquashFS tools (install 'squashfs-tools' package)",
            'wget': "Download utility",
            'patchelf': "ELF binary patcher"
        }
        
        # Toolkit-specific tools
        if self.config.toolkit == "gtk":
            required_tools.update({
                'glib-compile-schemas': "GLib schemas compiler (part of 'libglib2.0-dev' package)",
                'gdk-pixbuf-query-loaders': "GDK pixbuf utility (part of 'libgdk-pixbuf2.0-dev' package)"
            })
        
        missing_tools = []
        for tool, description in required_tools.items():
            if not shutil.which(tool):
                missing_tools.append(f"{tool} - {description}")
        
        if missing_tools:
            self.show_error(
                "Missing required system tools:\n\n" +
                "\n".join(f"• {tool}" for tool in missing_tools) +
                "\n\nPlease install them using your system package manager."
            )
            return False
        
        return True

    def cleanup_temp_files(self, extra_space_needed=0):
        """Clean up temporary files to free up space"""
        temp_dir = Path(tempfile.gettempdir())
        freed_space = 0
        
        # Clean old AppImage build directories
        for item in temp_dir.glob('appimage-build-*'):
            try:
                if item.is_dir():
                    # Calculate space that would be freed
                    freed_space += sum(f.stat().st_size for f in item.glob('**/*') if f.is_file())
                    shutil.rmtree(item)
                else:
                    freed_space += item.stat().st_size
                    item.unlink()
                    
                self.log(f"Cleaned temporary file: {item}", "#2196F3")
                
                # Check if we've freed enough space
                if extra_space_needed > 0 and freed_space >= extra_space_needed:
                    break
                    
            except Exception as e:
                self.log(f"Warning: Could not delete {item}: {str(e)}", "#FF9800")
        
        return freed_space
    
    def show_error(self, message):
        QMessageBox.critical(self, "Error", message)
        self.log(f"ERROR: {message}", "#F44336")
    
    def show_warning(self, message):
        QMessageBox.warning(self, "Warning", message)
        self.log(f"Warning: {message}", "#FF9800")
    
    def start_build(self):
        if not self.validate_inputs():
            return
            
        self.build_btn.setEnabled(False)
        self.test_btn.hide()
        self.log_output.clear()
        self.global_progress.show()
        
        self.log("Starting AppImage build process...", "#4CAF50")
        
        self.build_thread = BuildThread(self.config)
        # Connect all signals
        self.build_thread.log_signal.connect(self.log)
        self.build_thread.progress_signal.connect(self.update_progress)
        self.build_thread.global_progress_signal.connect(self.update_global_progress)
        self.build_thread.finished_signal.connect(self.build_finished)
        self.build_thread.start()
        
    def update_progress(self, value, message):
        self.basic_progress.setValue(value)
        self.advanced_progress.setValue(value)
        self.log_progress.setValue(value)
        
        if message:
            self.log(message)
    
    def build_finished(self, success, output_path):
        self.build_btn.setEnabled(True)
        
        if success:
            self.final_appimage_path = output_path
            self.log(f"\nBuild successful! AppImage created at:\n{output_path}", "#4CAF50")
            self.test_btn.show()
            
            if self.config.test_after_build:
                self.test_appimage()
        else:
            self.log("\nBuild failed!", "#F44336")
        
        self.status_bar.showMessage("Build complete" if success else "Build failed", 5000)
    
    def test_appimage(self):
        if not self.final_appimage_path or not Path(self.final_appimage_path).exists():
            self.show_error("No valid AppImage to test")
            return
            
        self.log(f"\nTesting AppImage: {self.final_appimage_path}", "#2196F3")
        
        try:
            process = subprocess.Popen(
                [self.final_appimage_path, "--help"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait for a short time to capture some output
            time.sleep(2)
            
            if process.poll() is None:
                # Still running - probably good
                self.log("AppImage launched successfully (still running)", "#4CAF50")
                process.terminate()
            else:
                # Process ended - check output
                stdout, stderr = process.communicate()
                if stdout:
                    self.log(f"AppImage output:\n{stdout}", "#4CAF50")
                if stderr:
                    self.log(f"AppImage errors:\n{stderr}", "#FF9800")
                
                if process.returncode == 0:
                    self.log("AppImage test completed successfully", "#4CAF50")
                else:
                    self.log(f"AppImage test failed with code {process.returncode}", "#F44336")
                    
        except Exception as e:
            self.log(f"Error testing AppImage: {str(e)}", "#F44336")
    
    def closeEvent(self, event):
        self.save_settings()
        
        if hasattr(self, 'build_thread') and self.build_thread.isRunning():
            reply = QMessageBox.question(
                self,
                "Build in Progress",
                "A build is currently running. Are you sure you want to quit?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                self.build_thread.terminate()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()

def main():
    def exception_handler(exctype, value, tb):
        """Keeps terminal open on crash"""
        import traceback
        traceback.print_exception(exctype, value, tb)
        print("\n\n=== CRASH DETECTED ===")
        print("The terminal will remain open for 5 minutes so you can read errors.")
        print("Close it manually when done.\n")
        input("Press Enter to exit...")  # Pause until user input
        sys.exit(1)

    # Install crash handler
    sys.excepthook = exception_handler    
    app = QApplication(sys.argv)
    app.setApplicationName("Universal AppImage Builder")
    app.setApplicationVersion(__version__)
    
    # Check for required tools early
    required_tools = ['python3', 'pip3', 'mksquashfs', 'wget', 'patchelf']
    missing_tools = [tool for tool in required_tools if not shutil.which(tool)]
    
    if missing_tools:
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Critical)
        msg.setText("Missing Required Tools")
        msg.setInformativeText(
            "The following required tools are missing:\n\n" +
            "\n".join(f"• {tool}" for tool in missing_tools) +
            "\n\nPlease install them before running this application."
        )
        msg.setWindowTitle("Error")
        msg.exec_()
        sys.exit(1)
    
    builder = AppImageBuilder()
    builder.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()