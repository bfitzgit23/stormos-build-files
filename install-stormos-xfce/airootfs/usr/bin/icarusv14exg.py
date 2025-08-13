#!/usr/bin/env python3
import sys
import os


# =============================================
# MUST BE SET BEFORE ANY QT IMPORTS
# =============================================
os.environ["QT_VAAPI_ENABLED"] = "1"
os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = "--enable-features=WebRTC"
os.environ["LIBVA_DRIVER_NAME"] = "iHD"  # Intel: 'iHD' | AMD: 'radeonsi' | Nvidia: 'nvidia'
os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = (
    "--enable-features=Widevine,PlatformEncryptedDolbyVision "
    "--disable-features=UseChromeOSDirectVideoDecoder "
    "--enable-ac3-eac3-audio "
    "--enable-mse-mp2t-streaming "
    "--no-sandbox "
    "--widevine-cdm-path=/usr/lib/chromium/WidevineCdm"
)

os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = (
    "--enable-features=Widevine,PlatformEncryptedDolbyVision "
    "--disable-features=UseChromeOSDirectVideoDecoder "
    "--enable-ac3-eac3-audio "
    "--enable-mse-mp2t-streaming "
    "--no-sandbox "
    "--widevine-cdm-path=/usr/lib/chromium/WidevineCdm "
    "--enable-features=WebRTC "
    "--use-fake-ui-for-media-stream "  # Auto-accept media permission prompts
    "--enable-features=WebRTC-EchoCancellation "
    "--disable-features=WebRtcHideLocalIpsWithMdns"
    
    "--enable-media-stream "
    "--enable-webrtc "

    "--ignore-gpu-blocklist "  # Important for some DRM content
    "--use-gl=desktop "       # May help with GPU acceleration



    "--enable-gpu-rasterization "
    "--enable-accelerated-video-decode "
    "--enable-accelerated-video-encode "

)
from PyQt5.QtCore import QSysInfo
import sys
import json
import time
import sqlite3
import platform
from datetime import datetime
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtNetwork import *
from PyQt5.QtWebEngineWidgets import *
from PyQt5.QtWebEngineCore import *  # Try this for all WebEngineCore components
import re
from PyQt5.QtWebEngineCore import QWebEngineUrlRequestInterceptor
from urllib.parse import quote_plus  # Add this import at the top
import logging
import subprocess
import time
import re
from PyQt5.QtCore import QSettings, QByteArray
from PyQt5.QtGui import QGuiApplication
from PyQt5.QtWidgets import QMessageBox
import hashlib
import base64
import traceback
from datetime import datetime
import logging
from PyQt5.QtWidgets import (QCalendarWidget, QListWidget, QInputDialog)
from PyQt5.QtCore import QDate, QDateTime
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
import shutil
import sqlite3
from PyQt5.QtWidgets import QFileDialog, QMessageBox
from PyQt5.QtCore import (
    QUrl, Qt, QTimer, pyqtSignal, QObject, QRect, QThread, QSize,
    QCoreApplication, QStandardPaths, QEvent # Added QStandardPaths for better default download folder
)
from PyQt5.QtGui import (
    QIcon, QFontMetrics, QPalette, QColor, QKeySequence, QPainter,
    QGuiApplication, QDesktopServices, QCursor
)
import tempfile
from PyQt5.QtCore import QUrl, QStandardPaths, QDir
from PyQt5.QtGui import QIcon, QPixmap
from PyQt5.QtNetwork import QNetworkAccessManager, QNetworkRequest
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QVBoxLayout, QHBoxLayout,
    QLineEdit, QPushButton, QWidget, QLabel, QProgressBar,
    QToolBar, QAction, QDialog, QListWidget, QListWidgetItem,
    QMessageBox, QFileDialog, QScrollArea, QFrame, QInputDialog, QMenu,
    QDialogButtonBox, QToolButton, QTabBar, QTextEdit, QSpacerItem,
    QStatusBar # Explicitly import QStatusBar for clarity
)
from PyQt5.QtWebEngineWidgets import QWebEngineView, QWebEnginePage, QWebEngineProfile, QWebEngineDownloadItem, QWebEngineSettings
from PyQt5.QtPrintSupport import QPrinter, QPrintDialog
from PyQt5.QtWidgets import QDockWidget
from PyQt5.QtGui import QImage, QPainter, QPixmap
from PyQt5.QtWidgets import QMenu, QFileDialog
from PyQt5.QtCore import QPoint
from PyQt5.QtCore import QTimer
from datetime import datetime
from PyQt5.QtCore import QObject, pyqtSignal, QProcess
from PyQt5.QtWidgets import QAction
from PyQt5.QtCore import QStandardPaths
from PyQt5.QtCore import QThread
from PyQt5.QtWidgets import (
    QGroupBox,  # Add this
    QVBoxLayout,  # Probably already there
    QRadioButton,  # Add this
    QDialog,  # Probably already there
    QFileDialog,  # Probably already there
    QMessageBox  # Probably already there
)
from PyQt5.QtWidgets import QLayout  # Add this import
from PyQt5.QtCore import QUrl, Qt, QTimer, pyqtSignal, QObject, QRect, QThread, QSize,QCoreApplication, QStandardPaths, QEvent, QDateTime, QPoint  # Added QDateTime here


from PyQt5 import QtWidgets, QtGui, QtCore
from PyQt5.QtCore import Qt, QUrl, QTimer, pyqtSignal, QObject, QEvent, QDateTime, QPoint
from PyQt5.QtGui import QFont, QIcon, QTextCursor, QTextCharFormat
from PyQt5.QtWidgets import (
    QApplication, QWidget, QPushButton, QLabel, QHBoxLayout, QVBoxLayout,
    QTextBrowser, QListWidget, QFileDialog, QDialog, QTabWidget, QCalendarWidget,
    QListWidgetItem, QRubberBand, QColorDialog  # Moved QColorDialog here
)
from PyQt5.QtWebEngineWidgets import QWebEngineView, QWebEnginePage, QWebEngineProfile, QWebEngineDownloadItem
from PyQt5.QtPrintSupport import QPrinter, QPrintDialog

from PyQt5.QtWebEngineWidgets import QWebEngineFullScreenRequest
from PyQt5.QtGui import QTextCharFormat
from PyQt5.QtWidgets import QWidget, QPushButton, QListWidget
import weakref
import urllib.parse
from PyQt5.QtCore import QUrl
# ====================== CONSTANTS ======================
DEFAULT_HOME_PAGE = "https://www.google.com"
DOWNLOAD_DIR = os.path.expanduser("~/Downloads")
CONFIG_DIR = os.path.expanduser("~/.config/storm_browser")
BOOKMARKS_FILE = os.path.join(CONFIG_DIR, "bookmarks.json")
HISTORY_FILE = os.path.join(CONFIG_DIR, "history.json")
SETTINGS_FILE = os.path.join(CONFIG_DIR, "settings.json")
DRM_ENABLED = True  # Enable Widevine DRM support
HLS_ENABLED = True  # Enable HLS streaming support
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.6778.85 Safari/537.36"  # Use latest Chrome

# ====================== UTILITIES ======================
def ensure_config_dir():
    if not os.path.exists(CONFIG_DIR):
        os.makedirs(CONFIG_DIR)

def load_json_file(file_path, default=None):
    if default is None:
        default = {}
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default

def save_json_file(file_path, data):
    with open(file_path, "w") as f:
        json.dump(data, f, indent=4)

def format_size(bytes):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes < 1024.0:
            return f"{bytes:.2f} {unit}"
        bytes /= 1024.0
    return f"{bytes:.2f} TB"

def format_time(seconds):
    """Format seconds into a human-readable time string (e.g., 1h 20m 30s)."""
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    time_str = ""
    if h > 0:
        time_str += f"{h}h "
    if m > 0:
        time_str += f"{m}m "
    if s > 0:
        time_str += f"{s}s"
    return time_str.strip()


#++++++++++++++++++++++++++++++++++++++++++++++++++++++++



# Add this near your other imports at the top
import subprocess
import tempfile
import threading
from PyQt5.QtCore import QTimer, QDateTime

# ====================== SCREEN RECORDER ======================
import os
import sys
import subprocess
import tempfile
from PyQt5.QtCore import QObject, QTimer, pyqtSignal, QDateTime


import sys
import subprocess
import traceback
from PyQt5.QtCore import QObject, QTimer, pyqtSignal, QDateTime, QRect



from PyQt5.QtWebEngineWidgets import QWebEnginePage

#!/usr/bin/env python3
"""
webrtc_webpage.py

Drop-in WebPage class for PyQt5.QtWebEngineWidgets.QWebEnginePage with:
 - prepare_environment() to set QTWEBENGINE_CHROMIUM_FLAGS & PipeWire envs (call BEFORE Qt import)
 - robust getUserMedia wrapper (uses 'ideal' constraints)
 - logging of resulting MediaTrackSettings
 - WebAudio DSP chain: high-pass + compressor + optional gating + short delay comb feedback
 - device enumeration warning when input/output likely same device
 - optional whitelist for auto-granting mic/camera permissions
"""

#------------------------------------------------------------
#!/usr/bin/env python3
"""
chrome_profile_importer.py

A reusable class/dialog for importing Chrome profiles into QtWebEngine.

Run on Arch with google-chrome installed.

What it does:
- Launches Google Chrome with a temporary user-data-dir and opens accounts.google.com
- After you log in in Chrome, click "Import profile" in the GUI
- The code copies the logged-in temporary Chrome profile into an app profile folder
- Emits a signal with the path to the copied profile directory

Limitations:
- Copying may take some time for large profiles
- If Google applies further fingerprint checks you may still see issues
- Use responsibly (don't share credentials)
"""
import sys
import os
import shutil
import tempfile
import subprocess
import time
from pathlib import Path

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QLabel,
    QMessageBox, QDialog # Ensure QDialog is imported
)
from PyQt5.QtCore import QUrl, Qt, pyqtSignal # Ensure pyqtSignal is imported

# Note: QWebEngineView, QWebEngineProfile, QWebEnginePage are used for the example main(),
# but the core importer class doesn't strictly require them for the import process itself.
# They might be needed if you use get_preview_widget() or similar methods.
# from PyQt5.QtWebEngineWidgets import QWebEngineView, QWebEngineProfile, QWebEnginePage


#---------------------------------------------------------------------

class NetflixDRMHandler:
    """
    Enhanced Netflix DRM (Widevine) setup and configuration for QtWebEngine.
    """
    def __init__(self):
        self.widevine_available = False
        self.netflix_profile = None
        self.widevine_path = None
        self.initialize_widevine()
    
    def initialize_widevine(self):
        """
        Initialize Widevine CDM by finding Chrome's installation and setting up environment variables.
        Must be called before creating any QtWebEngine components.
        """
        import os
        import subprocess
        import shutil
        from pathlib import Path
        
        print("[INFO] Initializing Widevine CDM...")
        
        # Try to find Chrome installation automatically
        chrome_paths = [
            "/usr/bin/google-chrome-stable",
            "/usr/bin/google-chrome",
            "/opt/google/chrome/chrome"
        ]
        
        widevine_path = None
        chrome_path = None
        
        # Find Chrome installation
        for path in chrome_paths:
            if os.path.exists(path):
                chrome_path = path
                print(f"[INFO] Found Chrome at: {chrome_path}")
                break
        
        if chrome_path:
            try:
                # Get Chrome installation directory
                chrome_dir = os.path.dirname(os.path.realpath(chrome_path))
                
                # Look for Widevine in the expected location
                possible_widevine_paths = [
                    os.path.join(chrome_dir, "WidevineCdm/_platform_specific/linux_x64/libwidevinecdm.so"),
                    os.path.join(chrome_dir, "WidevineCdm", "libwidevinecdm.so"),
                    "/opt/google/chrome/WidevineCdm/_platform_specific/linux_x64/libwidevinecdm.so",
                    "/usr/lib/chromium/WidevineCdm/_platform_specific/linux_x64/libwidevinecdm.so",
                    "/usr/lib/widevine/libwidevinecdm.so"
                ]
                
                for path in possible_widevine_paths:
                    if os.path.exists(path):
                        widevine_path = path
                        print(f"[INFO] Found Widevine CDM at: {widevine_path}")
                        break
                
                # If not found, try to find it using pacman
                if not widevine_path:
                    try:
                        # Get package files for google-chrome
                        result = subprocess.run(
                            ["pacman", "-Ql", "google-chrome"],
                            capture_output=True, text=True, check=True
                        )
                        
                        # Parse output to find Widevine
                        for line in result.stdout.splitlines():
                            if "libwidevinecdm.so" in line:
                                widevine_path = line.split()[-1]
                                print(f"[INFO] Found Widevine CDM via pacman: {widevine_path}")
                                break
                    except (subprocess.CalledProcessError, FileNotFoundError) as e:
                        print(f"[WARNING] Error finding Widevine via pacman: {e}")
            except Exception as e:
                print(f"[WARNING] Error finding Widevine: {e}")
        
        if widevine_path:
            # Create a copy of Widevine in QtWebEngine's expected location
            try:
                # Get QtWebEngine's path
                qtwebengine_path = os.path.join(os.path.expanduser("~"), ".config", "qtwebengine", "WidevineCdm")
                os.makedirs(qtwebengine_path, exist_ok=True)
                
                # Copy Widevine to QtWebEngine's expected location
                target_path = os.path.join(qtwebengine_path, "_platform_specific", "linux_x64")
                os.makedirs(target_path, exist_ok=True)
                target_file = os.path.join(target_path, "libwidevinecdm.so")
                
                if not os.path.exists(target_file):
                    shutil.copy2(widevine_path, target_file)
                    print(f"[INFO] Copied Widevine CDM to: {target_file}")
                
                # Store the path for later use
                self.widevine_path = target_file
                
                # Set Widevine path via environment variable
                flags = os.environ.get("QTWEBENGINE_CHROMIUM_FLAGS", "")
                additional_flags = [
                    "--enable-widevine-cdm",
                    f"--widevine-cdm-path={target_file}",
                    "--enable-features=VaapiVideoDecoder,PlatformEncryptedDolbyVision",
                    "--disable-features=UseChromeOSDirectVideoDecoder",
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-accelerated-2d-canvas",
                    "--no-first-run",
                    "--no-default-browser-check",
                    "--disable-background-mode",
                    "--disable-background-timer-throttling",
                    "--disable-renderer-backgrounding"
                ]
                
                os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = flags + " " + " ".join(additional_flags)
                print(f"[INFO] Set Widevine environment flags")
                
                self.widevine_available = True
                return True
            except Exception as e:
                print(f"[ERROR] Failed to copy Widevine CDM: {e}")
        else:
            print("[WARNING] Widevine CDM not found. Netflix playback may not work.")
        
        self.widevine_available = False
        return False
    
    def get_netflix_profile(self):
        """
        Create and return a dedicated profile for Netflix with DRM support.
        """
        if self.netflix_profile is None:
            import os
            from PyQt5.QtWebEngineWidgets import QWebEngineProfile, QWebEngineSettings
            
            self.netflix_profile = QWebEngineProfile()
            self.netflix_profile.setHttpCacheType(QWebEngineProfile.HttpCacheType.DiskHttpCache)
            self.netflix_profile.setPersistentCookiesPolicy(QWebEngineProfile.PersistentCookiesPolicy.ForcePersistentCookies)
            self.netflix_profile.setHttpCacheMaximumSize(1024 * 1024 * 100)  # 100MB
            
            # Enable DRM for Netflix (Widevine)
            settings = self.netflix_profile.settings()
            settings.setAttribute(QWebEngineSettings.PluginsEnabled, True)
            settings.setAttribute(QWebEngineSettings.DnsPrefetchEnabled, True)
            settings.setAttribute(QWebEngineSettings.FullScreenSupportEnabled, True)
            settings.setAttribute(QWebEngineSettings.ScreenCaptureEnabled, True)
            settings.setAttribute(QWebEngineSettings.WebGLEnabled, True)
            settings.setAttribute(QWebEngineSettings.LocalStorageEnabled, True)
            settings.setAttribute(QWebEngineSettings.JavascriptEnabled, True)
            
            # Set up storage paths
            storage_path = os.path.join(os.path.expanduser("~"), ".config", "storm_browser", "netflix_storage")
            os.makedirs(storage_path, exist_ok=True)
            self.netflix_profile.setPersistentStoragePath(storage_path)
            self.netflix_profile.setCachePath(os.path.join(storage_path, "cache"))
            
            # Set HTTP user agent to a Chrome one that's known to work with Netflix
            self.netflix_profile.setHttpUserAgent(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
            )
            
            print("[INFO] Netflix profile created with DRM support")
        
        return self.netflix_profile
    
    def verify_widevine_support(self, callback=None):
        """
        Check if Widevine CDM is properly loaded and supported.
        """
        from PyQt5.QtWebEngineWidgets import QWebEnginePage
        from PyQt5.QtCore import QUrl
        
        # Create a test page to check DRM support
        test_page = QWebEnginePage(self.get_netflix_profile())
        
        def check_drm_support(ok):
            if ok:
                test_page.runJavaScript("""
                    (async () => {
                        try {
                            if (navigator.requestMediaKeySystemAccess) {
                                const access = await navigator.requestMediaKeySystemAccess('com.widevine.alpha', [{
                                    initDataTypes: ['cenc'],
                                    videoCapabilities: [{
                                        contentType: 'video/mp4; codecs="avc1.42E01E"',
                                        robustness: 'SW_SECURE_CRYPTO'
                                    }]
                                }]);
                                return true;
                            } else {
                                return false;
                            }
                        } catch (e) {
                            console.error('Widevine check error:', e);
                            return false;
                        }
                    })()
                """, lambda result: self._on_widevine_check_result(result, callback))
        
        test_page.loadFinished.connect(check_drm_support)
        test_page.load(QUrl("about:blank"))
    
    def _on_widevine_check_result(self, result, callback=None):
        """Handle the result of Widevine support check."""
        print(f"[INFO] Widevine support check result: {result}")
        if callback:
            callback(result)
    
    def get_netflix_js_injection(self):
        """
        Return JavaScript code to inject for Netflix compatibility.
        """
        return """
            console.log("Netflix site detected, enabling DRM fixes");
            
            // Ensure EME support
            if (!window.navigator.requestMediaKeySystemAccess) {
                console.log("Adding EME polyfill");
                window.navigator.requestMediaKeySystemAccess = (keySystem, supportedConfigurations) => {
                    return Promise.resolve({
                        getConfiguration: () => supportedConfigurations[0],
                        createMediaKeys: () => {
                            return Promise.resolve({
                                createSession: () => {
                                    return Promise.resolve({
                                        generateRequest: () => Promise.resolve(),
                                        update: () => Promise.resolve(),
                                        close: () => Promise.resolve(),
                                        remove: () => Promise.resolve()
                                    });
                                },
                                setServerCertificate: () => Promise.resolve()
                            });
                        }
                    });
                };
            }
            
            // Fix for potential Netflix playback issues
            document.addEventListener('DOMContentLoaded', () => {
                // Force enable DRM components
                if (window.netflix) {
                    console.log("Netflix object found, enabling DRM");
                    if (window.netflix.reactContext && window.netflix.reactContext.models && window.netflix.reactContext.models.playerModel) {
                        window.netflix.reactContext.models.playerModel.setDrmSupported(true);
                    }
                }
                
                // Additional Netflix fixes
                const originalCreateElement = document.createElement;
                document.createElement = function(tagName) {
                    const element = originalCreateElement.call(document, tagName);
                    if (tagName === 'video') {
                        element.addEventListener('encrypted', (event) => {
                            console.log('Video encrypted event detected');
                        });
                    }
                    return element;
                };
                
                // Override MediaKeys if needed
                if (window.MediaKeys) {
                    const originalCreateMediaKeys = window.MediaKeys;
                    window.MediaKeys = function() {
                        console.log("MediaKeys instantiated");
                        return originalCreateMediaKeys();
                    };
                }
            });
            
            // Fix for potential issues with video elements
            const originalPlay = HTMLVideoElement.prototype.play;
            HTMLVideoElement.prototype.play = function() {
                console.log("Video play called");
                return originalPlay.apply(this, arguments);
            };
            
            // Fix for potential issues with setting src
            const originalSetSrc = Object.getOwnPropertyDescriptor(HTMLMediaElement.prototype, 'src').set;
            Object.defineProperty(HTMLMediaElement.prototype, 'src', {
                set: function(value) {
                    console.log("Setting video src to:", value);
                    originalSetSrc.call(this, value);
                }
            });
        """
    
    def debug_widevine_status(self):
        """
        Print debugging information about Widevine status.
        """
        import os
        print("[DEBUG] Widevine Status:")
        print(f"  - Widevine available: {self.widevine_available}")
        print(f"  - Widevine path: {self.widevine_path}")
        print(f"  - Netflix profile exists: {self.netflix_profile is not None}")
        
        if self.widevine_path:
            print(f"  - Widevine file exists: {os.path.exists(self.widevine_path)}")
            if os.path.exists(self.widevine_path):
                import stat
                file_stat = os.stat(self.widevine_path)
                print(f"  - File size: {file_stat.st_size} bytes")
                print(f"  - File permissions: {oct(file_stat.st_mode)[-3:]}")
        
        # Print environment variables
        print(f"  - QTWEBENGINE_CHROMIUM_FLAGS: {os.environ.get('QTWEBENGINE_CHROMIUM_FLAGS', 'Not set')}")
#---------------------------------------------------------------------

from PyQt5.QtWebEngineCore import QWebEngineUrlRequestInterceptor

class ForcedUserAgentInterceptor(QWebEngineUrlRequestInterceptor):
    def __init__(self, user_agent):
        super().__init__()
        self.user_agent = user_agent

    def interceptRequest(self, info):
        info.setHttpHeader(b"User-Agent", self.user_agent.encode("utf-8"))




class ChromeProfileImporter(QDialog):
    """
    A reusable dialog for importing Chrome profiles into QtWebEngine.
    Emits signals upon successful import or failure.
    """

    # Signal emitted when a profile is successfully imported.
    # Provides the *path* to the imported profile directory as a string.
    profile_imported = pyqtSignal(str)
    # Signal emitted if the import process fails.
    # Provides the error message as a string.
    import_failed = pyqtSignal(str)
    # Signal emitted when Chrome is launched for login.
    # Provides the temporary profile path as a string.
    login_initiated = pyqtSignal(str)

    def __init__(self, parent=None, chrome_path=None, destination_dir=None):
        """
        Initializes the ChromeProfileImporter dialog.

        Args:
            parent (QWidget, optional): Parent widget. Defaults to None.
            chrome_path (str, optional): Path to the Chrome executable.
                                         If None, it will be searched for.
            destination_dir (str, optional): Base directory where imported profiles
                                             will be stored. Defaults to a standard
                                             user data location.
        """
        super().__init__(parent)
        self.setWindowTitle("Import Chrome Profile")
        self.resize(500, 300)

        # Allow customization of paths
        self.chrome_exe = chrome_path if chrome_path else self._find_chrome_executable()
        self.destination_base_dir = destination_dir if destination_dir else os.path.expanduser("~/.local/share/pyqt_chrome_profiles")
        os.makedirs(self.destination_base_dir, exist_ok=True)

        # Internal state
        self._tmp_user_data_dir = None
        self._tmp_profile_dir = None

        self.setup_ui()

    def _find_chrome_executable(self):
        """Try to locate Chrome executable on the system."""
        common_paths = [
            "/usr/bin/google-chrome-stable",
            "/usr/bin/google-chrome",
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser"
        ]
        for path in common_paths:
            if os.path.exists(path):
                return path
        return None # Not found

    def setup_ui(self):
        """Sets up the user interface for the dialog."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        self.instructions = QLabel(
            "<ol>"
            "<li>Click 'Open Chrome for Login' — a Chrome window will open.</li>"
            "<li>Log into your Google account there.</li>"
            "<li><b>Close that Chrome window</b> when done.</li>"
            "<li>Come back here and click 'Import Profile'.</li>"
            "</ol>"
            "<p><b>Note:</b> This creates a temporary Chrome profile just for login. "
            "Your main Chrome profile is not affected.</p>"
        )
        self.instructions.setWordWrap(True)
        self.instructions.setTextFormat(Qt.RichText) # Enable HTML
        self.instructions.setOpenExternalLinks(True)
        layout.addWidget(self.instructions)

        self.open_btn = QPushButton("Open Chrome for Login")
        self.open_btn.clicked.connect(self.open_chrome_for_login)
        layout.addWidget(self.open_btn)

        self.import_btn = QPushButton("Import Profile (after closing Chrome)")
        self.import_btn.clicked.connect(self.import_profile_into_qt)
        self.import_btn.setEnabled(False)
        layout.addWidget(self.import_btn)

        self.status_label = QLabel("Status: Ready")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        self.launch_info = QLabel("")
        self.launch_info.setWordWrap(True)
        layout.addWidget(self.launch_info)

        # Add QDialogButtonBox for standard OK/Cancel (optional, or use custom logic)
        # from PyQt5.QtWidgets import QDialogButtonBox
        # button_box = QDialogButtonBox(QDialogButtonBox.Close)
        # button_box.rejected.connect(self.reject) # Or close the dialog
        # layout.addWidget(button_box)

        # For this dialog, closing it signifies finishing the process (successful or not)
        # The main logic is driven by the buttons and signals.

    def open_chrome_for_login(self):
        """
        Launch Chrome with an isolated temporary user-data-dir so user can login.
        We store the user-data-dir path to later copy it.
        """
        if not self.chrome_exe or not os.path.exists(self.chrome_exe):
            error_msg = f"Chrome executable not found at '{self.chrome_exe}'. Please check the path."
            QMessageBox.critical(self, "Chrome Not Found", error_msg)
            self.import_failed.emit(error_msg)
            return

        # Create temporary user-data-dir
        try:
            tmp_dir = tempfile.mkdtemp(prefix="pyqt_chrome_profile_import_")
            self._tmp_user_data_dir = tmp_dir
            # Chrome typically stores the Default profile under <user-data-dir>/Default
            tmp_default_profile = os.path.join(tmp_dir, "Default")
            self._tmp_profile_dir = tmp_default_profile
        except Exception as e:
            error_msg = f"Failed to create temporary directory: {e}"
            QMessageBox.critical(self, "Temp Dir Error", error_msg)
            self.import_failed.emit(error_msg)
            return

        # Build command to start Chrome
        # --no-first-run and --no-default-browser-check reduce startup prompts
        cmd = [
            self.chrome_exe,
            f"--user-data-dir={tmp_dir}",
            "--no-first-run",
            "--no-default-browser-check",
            "https://accounts.google.com/"
        ]

        try:
            # Start Chrome detached so this Python process doesn't block
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.status_label.setText(f"Status: Chrome launched with temporary profile.")
            self.launch_info.setText(f"<b>Temporary Profile Path:</b> {tmp_dir}<br>"
                                     f"Please log in and then close Chrome.")
            self.import_btn.setEnabled(True)
            self.open_btn.setEnabled(False) # Prevent launching multiple instances
            self.login_initiated.emit(tmp_dir) # Notify that login has started
        except Exception as e:
            error_msg = f"Error launching Chrome: {e}"
            QMessageBox.critical(self, "Failed to Launch Chrome", error_msg)
            self.import_failed.emit(error_msg)

    def import_profile_into_qt(self):
        """
        Copy the temporary Chrome profile into the application's profile folder.
        Emits profile_imported(profile_path) on success or import_failed(error_msg) on failure.
        """
        if not self._tmp_profile_dir or not os.path.exists(self._tmp_user_data_dir):
            error_msg = "No temporary Chrome profile found. Click 'Open Chrome for Login' first."
            QMessageBox.warning(self, "No Profile", error_msg)
            self.import_failed.emit(error_msg)
            return

        # Ensure Chrome's profile actually exists (user may not have finished login yet)
        if not os.path.isdir(self._tmp_profile_dir):
            # maybe Chrome hasn't created Default subfolder yet; wait a sec
            self.status_label.setText("Status: Waiting for Chrome to create profile data...")
            QApplication.processEvents() # Update UI
            wait_seconds = 0
            max_wait_seconds = 15 # Increased wait time slightly
            while wait_seconds < max_wait_seconds and not os.path.isdir(self._tmp_profile_dir):
                time.sleep(0.5)
                QApplication.processEvents() # Keep UI responsive
                wait_seconds += 0.5

            if not os.path.isdir(self._tmp_profile_dir):
                error_msg = ("Temporary Chrome profile folder not ready. "
                             "Ensure Chrome finished initial setup/login and was closed.")
                QMessageBox.warning(self, "Profile Not Ready", error_msg)
                self.import_failed.emit(error_msg)
                return

        # Choose a unique destination directory (we'll remove any existing)
        dest_base = Path(self.destination_base_dir)
        # Use a fixed name or make it configurable/unique if needed
        dest_profile_name = "ImportedProfile"
        dest_profile = dest_base / dest_profile_name

        # Remove previous if exists
        if dest_profile.exists():
            try:
                shutil.rmtree(dest_profile)
                print(f"Removed old imported profile at {dest_profile}")
            except Exception as e:
                error_msg = f"Could not remove old profile at {dest_profile}: {e}"
                QMessageBox.critical(self, "Failed to Clear Old Profile", error_msg)
                self.import_failed.emit(error_msg)
                return

        # Copy tree
        self.status_label.setText("Status: Copying profile (may take a while)...")
        self.launch_info.setText("")
        QApplication.processEvents() # Update UI to show copying status
        try:
            shutil.copytree(self._tmp_profile_dir, dest_profile)
            print(f"Profile successfully copied to {dest_profile}")
        except Exception as e:
            error_msg = f"Failed to copy profile from {self._tmp_profile_dir} to {dest_profile}: {e}"
            QMessageBox.critical(self, "Copy Failed", error_msg)
            self.import_failed.emit(error_msg)
            return

        self.status_label.setText(f"Status: Profile imported successfully.")
        self.launch_info.setText(f"<b>Imported Profile Path:</b> {dest_profile}")

        # Clean up temporary directory
        try:
            shutil.rmtree(self._tmp_user_data_dir)
            print(f"Cleaned up temporary directory {self._tmp_user_data_dir}")
        except Exception as e:
            print(f"Warning: Could not clean up temporary directory {self._tmp_user_data_dir}: {e}")
            # Not critical, continue

        # Disable buttons as process is complete
        self.import_btn.setEnabled(False)
        self.open_btn.setEnabled(False)

        # Emit the signal with the path to the *copied* profile directory
        imported_profile_path_str = str(dest_profile)
        self.profile_imported.emit(imported_profile_path_str)
        print(f"Emitting profile_imported signal with path: {imported_profile_path_str}")

        # Optionally, close the dialog automatically after success
        # self.accept() # Or self.close() or self.done(QDialog.Accepted)
        # Or let the user close it manually.





#_____________________________________________________________




import os
from PyQt5.QtCore import QUrl, pyqtSignal
from PyQt5.QtWebEngineWidgets import QWebEnginePage, QWebEngineSettings, QWebEngineProfile, QWebEngineView
from PyQt5.QtWebEngineCore import QWebEngineUrlRequestInterceptor, QWebEngineNotification


class DiscordUrlInterceptor(QWebEngineUrlRequestInterceptor):
    def interceptRequest(self, info):
        # Allow all blob URLs and WebSocket connections needed for Discord
        url = info.requestUrl()
        if url.scheme() == 'blob' or url.scheme() == 'wss':
            info.setAllowed(True)


class DiscordWebPage(QWebEnginePage):
    # Enhanced Chromium flags for WebRTC and hardware acceleration
    CHROMIUM_FLAGS = (
        "--enable-features="
        "WebRTC-H264WithOpenH264FFmpeg,"
        "WebRtcRemoteEventLog,"
        "WebRTC-StunOrigin,"
        "WebRTC-SupportVP9SVC,"
        "WebRTC-Vp9DependencyDescriptor,"
        "ScreenCapture,"
        "GetDisplayMedia,"
        "HardwareMediaKeyHandling,"
        "WebRTC-HardwareVideoDecoding,"
        "WebRTC-HybridAgc,"
        "WebRTC-UseEchoCanceller3,"
        "OverlayScrollbar,"
        "UseOzonePlatform "
        "--enable-webrtc-srtp-aes-gcm "
        "--enable-webrtc-stun-origin "
        "--enable-accelerated-video-decode "
        "--enable-accelerated-mjpeg-decode "
        "--ignore-gpu-blocklist "
        "--enable-gpu-rasterization "
        "--enable-zero-copy "
        "--enable-oop-rasterization "
        "--use-gl=egl "
        "--enable-hardware-overlays "
        "--use-fake-ui-for-media-stream "
        "--enable-gpu-rasterization "
        "--enable-oop-rasterization "
        "--enable-skia-renderer "
        "--disable-features=UseChromeOSDirectVideoDecoder "
        "--num-raster-threads=4 "
    )

    console_message = pyqtSignal(str, int, str)
    notification_requested = pyqtSignal(QWebEngineNotification)

    @staticmethod
    def prepare_environment():
        """Configure environment for optimal WebRTC performance"""
        os.environ.update({
            "QTWEBENGINE_CHROMIUM_FLAGS": DiscordWebPage.CHROMIUM_FLAGS.strip(),
            "LIBVA_DRIVER_NAME": "iHD",
            "QT_XCB_GL_INTEGRATION": "xcb_egl",
            "PULSE_PROP": "media.role=voip",
            "WEBRTC_LOGGING": "1",
            "WEBRTC_MODULE_LOG_LEVEL": "3",  # Verbose logging
            "QTWEBENGINE_REMOTE_DEBUGGING": "9222"
        })

    def __init__(self, profile=None, parent=None):
        profile = profile or QWebEngineProfile("DiscordProfile")
        profile.setUrlRequestInterceptor(DiscordUrlInterceptor())
        
        # Configure persistent storage for cookies/session
        profile.setPersistentCookiesPolicy(QWebEngineProfile.AllowPersistentCookies)
        profile.setCachePath(os.path.expanduser("~/.cache/discord_browser"))
        profile.setPersistentStoragePath(os.path.expanduser("~/.local/share/discord_browser"))

        # Set Chrome user agent
        profile.setHttpUserAgent(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.6778.85 Safari/537.36"
        )

        # Configure WebEngine settings
        settings = profile.settings()
        settings.setAttribute(QWebEngineSettings.PlaybackRequiresUserGesture, False)
        settings.setAttribute(QWebEngineSettings.WebRTCPublicInterfacesOnly, False)
        settings.setAttribute(QWebEngineSettings.AllowRunningInsecureContent, True)
        settings.setAttribute(QWebEngineSettings.LocalContentCanAccessRemoteUrls, True)
        settings.setAttribute(QWebEngineSettings.ScreenCaptureEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebGLEnabled, True)
        settings.setAttribute(QWebEngineSettings.Accelerated2dCanvasEnabled, True)
        settings.setAttribute(QWebEngineSettings.JavascriptCanAccessClipboard, True)
        settings.setAttribute(QWebEngineSettings.JavascriptCanPaste, True)

        super().__init__(profile, parent)
        
        # Connect signals
        self.featurePermissionRequested.connect(self.handle_permission_request)
        self.windowCloseRequested.connect(self.cleanup_resources)
        self.loadFinished.connect(self.on_load_finished)
        self.loadStarted.connect(self.on_load_started)
        
        # JavaScript console logging
        self.javaScriptConsoleMessage = self.handle_console_message

    def handle_console_message(self, level, message, line, source):
        """Handle JavaScript console messages"""
        level_str = {
            0: "DEBUG",
            1: "LOG",
            2: "WARNING",
            3: "ERROR"
        }.get(level, "UNKNOWN")
        self.console_message.emit(f"[JS {level_str}] {message}", line, source)

    def on_load_started(self):
        """Called when page starts loading"""
        self.runJavaScript("""
            window._discordWebRTCState = {
                streams: new Set(),
                connections: new Set(),
                pendingOperations: 0
            };
        """)

    def on_load_finished(self, ok):
        """Called when page finishes loading"""
        if ok:
            self.inject_resize_observer_fix()
            self.initialize_webrtc()
            self.inject_webrtc_monitoring()
            self.inject_discord_specific_fixes()

    def inject_resize_observer_fix(self):
        """Prevent ResizeObserver loop errors"""
        self.runJavaScript("""
            const originalResizeObserver = window.ResizeObserver;
            window.ResizeObserver = class extends originalResizeObserver {
                constructor(callback) {
                    callback = (entries, observer) => {
                        window.requestAnimationFrame(() => {
                            try {
                                callback(entries, observer);
                            } catch (e) {
                                console.error('ResizeObserver callback error:', e);
                            }
                        });
                    };
                    super(callback);
                }
            };
        """)

    def initialize_webrtc(self):
        """Initialize WebRTC with error handling"""
        self.runJavaScript("""
            // Backup original functions
            navigator.mediaDevices._originalGetUserMedia = navigator.mediaDevices.getUserMedia;
            navigator.mediaDevices._originalEnumerateDevices = navigator.mediaDevices.enumerateDevices;
            
            // Enhanced getUserMedia with fallback
            navigator.mediaDevices.getUserMedia = async function(constraints) {
                try {
                    window._discordWebRTCState.pendingOperations++;
                    const stream = await navigator.mediaDevices._originalGetUserMedia(constraints);
                    window._discordWebRTCState.streams.add(stream);
                    
                    stream.getTracks().forEach(track => {
                        track.addEventListener('ended', () => {
                            window._discordWebRTCState.streams.delete(stream);
                        });
                    });
                    
                    return stream;
                } catch (error) {
                    console.error('getUserMedia error:', error);
                    
                    // Fallback for NotReadableError
                    if (error.name === 'NotReadableError') {
                        console.log('Attempting fallback for video device');
                        const devices = await navigator.mediaDevices._originalEnumerateDevices();
                        const videoDevices = devices.filter(d => d.kind === 'videoinput');
                        
                        if (videoDevices.length > 0) {
                            const newConstraints = {
                                ...constraints,
                                video: { deviceId: { exact: videoDevices[0].deviceId } }
                            };
                            return navigator.mediaDevices._originalGetUserMedia(newConstraints);
                        }
                    }
                    
                    throw error;
                } finally {
                    window._discordWebRTCState.pendingOperations--;
                }
            };
        """)

    def inject_webrtc_monitoring(self):
        """Monitor WebRTC connections and state"""
        self.runJavaScript("""
            // Monitor RTCPeerConnection
            const originalRTCPeerConnection = window.RTCPeerConnection;
            window.RTCPeerConnection = function(config) {
                const pc = new originalRTCPeerConnection(config);
                window._discordWebRTCState.connections.add(pc);
                
                // Add event listeners
                const events = [
                    'iceconnectionstatechange',
                    'icegatheringstatechange',
                    'signalingstatechange',
                    'connectionstatechange',
                    'negotiationneeded',
                    'track'
                ];
                
                events.forEach(event => {
                    pc.addEventListener(event, (e) => {
                        console.debug(`RTCPeerConnection ${event}:`, pc[event.replace('change', 'State')], e);
                    });
                });
                
                pc.addEventListener('icecandidateerror', (e) => {
                    console.error('ICE candidate error:', e);
                });
                
                pc.addEventListener('close', () => {
                    window._discordWebRTCState.connections.delete(pc);
                });
                
                return pc;
            };
            
            // Override addTrack/removeTrack for monitoring
            const originalAddTrack = RTCPeerConnection.prototype.addTrack;
            RTCPeerConnection.prototype.addTrack = function(track, ...args) {
                console.debug('Adding track:', track.kind, track.id);
                window._discordWebRTCState.streams.add(track);
                return originalAddTrack.call(this, track, ...args);
            };
            
            const originalRemoveTrack = RTCPeerConnection.prototype.removeTrack;
            RTCPeerConnection.prototype.removeTrack = function(sender) {
                console.debug('Removing track:', sender.track?.kind, sender.track?.id);
                return originalRemoveTrack.call(this, sender);
            };
        """)

    def inject_discord_specific_fixes(self):
        """Discord-specific workarounds"""
        self.runJavaScript("""
            // Fix for Discord's screen sharing
            if (window.DiscordNative) {
                // Ensure screen sharing is available
                DiscordNative.desktopCapture = {
                    getSources: (options, callback) => {
                        console.log('Intercepted getSources', options);
                        window.navigator.mediaDevices.getDisplayMedia(options)
                            .then(stream => {
                                const sources = stream.getVideoTracks().map(track => ({
                                    id: track.id,
                                    name: track.label || 'Screen',
                                    thumbnail: null
                                }));
                                callback(sources);
                            })
                            .catch(err => {
                                console.error('getDisplayMedia error:', err);
                                callback([]);
                            });
                    }
                };
                
                // Fix for notifications
                DiscordNative.notifications = {
                    getPermission: () => 'granted',
                    requestPermission: (cb) => cb('granted')
                };
            }
            
            // Ensure WebAudio is available
            if (!window.AudioContext && window.webkitAudioContext) {
                window.AudioContext = window.webkitAudioContext;
            }
        """)

    def handle_permission_request(self, origin, feature):
        """Handle permission requests for WebRTC features"""
        trusted_hosts = (
            'discord.com', 
            'www.discord.com', 
            'discordapp.com',
            'cdn.discordapp.com',
            'media.discordapp.net'
        )
        
        if origin.host().endswith(trusted_hosts):
            self.setFeaturePermission(
                origin,
                feature,
                QWebEnginePage.PermissionGrantedByUser
            )
        else:
            self.setFeaturePermission(
                origin,
                feature,
                QWebEnginePage.PermissionDeniedByUser
            )

    def cleanup_resources(self):
        """Clean up all WebRTC resources"""
        self.runJavaScript("""
            // Stop all media tracks
            if (window._discordWebRTCState) {
                window._discordWebRTCState.streams.forEach(stream => {
                    stream.getTracks().forEach(track => track.stop());
                });
                
                window._discordWebRTCState.connections.forEach(pc => {
                    try {
                        pc.close();
                    } catch (e) {
                        console.error('Error closing RTCPeerConnection:', e);
                    }
                });
                
                // Reset state
                window._discordWebRTCState.streams.clear();
                window._discordWebRTCState.connections.clear();
            }
            
            // Discord-specific cleanup
            if (window.DiscordNative && window.DiscordNative.webrtc) {
                try {
                    window.DiscordNative.webrtc.closeAllConnections();
                } catch (e) {
                    console.error('Error closing Discord WebRTC:', e);
                }
            }
        """)


class DiscordWebView(QWebEngineView):
    def __init__(self, url=None, parent=None):
        super().__init__(parent)
        
        # Create dedicated profile
        self.profile = QWebEngineProfile("DiscordProfile", self)
        self.profile.setPersistentCookiesPolicy(QWebEngineProfile.AllowPersistentCookies)
        
        # Create custom page
        self.page = DiscordWebPage(self.profile, self)
        self.setPage(self.page)
        
        # Connect signals
        self.page.console_message.connect(self.handle_console_message)
        
        if url:
            self.load_url(url)

    def load_url(self, url):
        """Load a URL with proper type handling"""
        if isinstance(url, str):
            url = QUrl(url)
        self.load(url)

    def handle_console_message(self, message, line, source):
        """Handle JavaScript console messages"""
        print(f"Console: {message} (Line {line} in {source})")


#_____________________________________________________________

import os
import sys
import subprocess
from PyQt5.QtWebEngineWidgets import QWebEnginePage, QWebEngineProfile
from PyQt5.QtCore import QUrl, QTimer

class WebPage(QWebEnginePage):
    CHROMIUM_FLAGS = (
        "--enable-features=WebRtcUseEchoCanceller3,WebRtcHideLocalIpsWithMdns,"
        "HardwareMediaKeyHandling,WebRtcHybridAgc "
        "--disable-features=WebRtcAnalogAgcClippingControl "
        "--disable-webrtc-hw-decoding=false "
        "--disable-webrtc-hw-encoding=false "
        "--enable-webrtc-srtp-aes-gcm "
        "--enable-webrtc-stun-origin "
        "--force-webrtc-ip-handling-policy=default_public_interface_only "
        "--enable-features=ScreenCapture,GetDisplayMedia"
    )

    PIPEWIRE_ENV = {
        "PIPEWIRE_LATENCY": "256/48000",
        "PIPEWIRE_DEBUG": "0",
        "PIPEWIRE_PROPFILTER": "media.class=Audio/Source",
        "WEBRTC_AGC": "3",
        "WEBRTC_NS": "3",
        "WEBRTC_ECHO_CANCEL": "1",
        "WEBRTC_VAD": "1",
        "PULSE_PROP": "filter.want=echo-cancel",
        "PULSE_SOURCE": "echoCancel_source"
    }

    @staticmethod
    def prepare_environment():
        existing_flags = os.environ.get("QTWEBENGINE_CHROMIUM_FLAGS", "")
        os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = f"{existing_flags} {WebPage.CHROMIUM_FLAGS}".strip()
        for k, v in WebPage.PIPEWIRE_ENV.items():
            os.environ[k] = str(v)
        if sys.platform.startswith("linux"):
            os.environ["PULSE_PROP"] = "media.role=phone"
            os.environ["PULSE_SOURCE"] = "echoCancel_source"
            os.environ["PULSE_LATENCY_MSEC"] = "15"

    def __init__(self, profile: QWebEngineProfile = None, browser=None, parent=None):
        if profile is None:
            profile = QWebEngineProfile.defaultProfile()
        super().__init__(profile, parent)
        self._browser = browser
        self._profile = profile
        self._is_closing = False

        # Signal connections
        self.featurePermissionRequested.connect(self.handlePermissionRequest)
        self.loadFinished.connect(self.inject_webrtc_constraints)
        self.windowCloseRequested.connect(self._prepare_for_close)

        # Use destroyed signal instead of aboutToClose
        if parent:
            parent.destroyed.connect(self._force_media_cleanup)

    def _prepare_for_close(self):
        """Called when the tab is about to close"""
        self._is_closing = True
        self.drop_microphone()
        self.cleanup_audio_system()

    def _force_media_cleanup(self):
        """Final cleanup when page is being destroyed"""
        if hasattr(self, 'url') and self.url().host().endswith('discord.com'):
            self._aggressive_discord_cleanup()

    def _aggressive_discord_cleanup(self):
        """Special handling for Discord's WebRTC implementation"""
        discord_js = r"""
        (function() {
            try {
                // Discord-specific cleanup
                if (window.DiscordNative && window.DiscordNative.webrtc) {
                    window.DiscordNative.webrtc.closeAllConnections();
                }
                
                // Nuclear option for any remaining media
                const tracks = [];
                if (window.localStreams) {
                    window.localStreams.forEach(stream => {
                        stream.getTracks().forEach(track => tracks.push(track));
                    });
                }
                
                if (window.peerConnections) {
                    window.peerConnections.forEach(pc => {
                        pc.getSenders().forEach(sender => {
                            if (sender.track) tracks.push(sender.track);
                        });
                        pc.close();
                    });
                }
                
                tracks.forEach(track => {
                    try {
                        track.stop();
                        track.enabled = false;
                        if (track._switch) track._switch.disconnect();
                    } catch(e) {}
                });
                
                // Release audio contexts
                if (window.activeAudioContexts) {
                    window.activeAudioContexts.forEach(ctx => {
                        try { 
                            ctx.close();
                            ctx.suspend();
                        } catch(e) {}
                    });
                }
                
                console.log('[discord-cleanup] Aggressive media cleanup complete');
            } catch(e) {
                console.error('[discord-cleanup] Error:', e);
            }
        })();
        """
        self.runJavaScript(discord_js)

    def handlePermissionRequest(self, origin, feature):
        trusted_hosts = ('discord.com', 'www.discord.com', 'zoom.us', 'www.zoom.us')
        origin_host = origin.host()
        
        if self._is_closing and origin_host.endswith(('discord.com', 'zoom.us')):
            self.setFeaturePermission(origin, feature, QWebEnginePage.PermissionDeniedByUser)
            return
            
        if feature in [
            QWebEnginePage.MediaAudioCapture,
            QWebEnginePage.MediaVideoCapture,
            QWebEnginePage.MediaAudioVideoCapture,
            QWebEnginePage.DesktopVideoCapture,
        ]:
            if origin_host.endswith(trusted_hosts) or origin_host in ('localhost', '127.0.0.1') or origin.scheme() == 'https':
                self.setFeaturePermission(origin, feature, QWebEnginePage.PermissionGrantedByUser)
            else:
                self.setFeaturePermission(origin, feature, QWebEnginePage.PermissionDeniedByUser)

    def inject_webrtc_constraints(self, ok=True):
        js = r"""
        (async function() {
            try {
                // Initialize tracking containers if they don't exist
                window.localStreams = window.localStreams || new Set();
                window.peerConnections = window.peerConnections || new Set();
                window.activeAudioContexts = window.activeAudioContexts || new Set();

                const log = (...args) => { try { console.debug('[webrtc_inject]', ...args); } catch(e){} };

                // Monitor RTCPeerConnection creation
                const origRTCPeerConnection = window.RTCPeerConnection;
                window.RTCPeerConnection = function(...args) {
                    const pc = new origRTCPeerConnection(...args);
                    window.peerConnections.add(pc);
                    
                    pc.addEventListener('iceconnectionstatechange', () => {
                        if (pc.iceConnectionState === 'closed') {
                            window.peerConnections.delete(pc);
                        }
                    });
                    
                    return pc;
                };

                // Monitor getUserMedia calls
                const origGetUserMedia = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
                navigator.mediaDevices.getUserMedia = async function(constraints) {
                    const stream = await origGetUserMedia(constraints);
                    window.localStreams.add(stream);
                    
                    // Monitor stream's oninactive event
                    stream.oninactive = () => {
                        window.localStreams.delete(stream);
                    };
                    
                    return stream;
                };

                // Monitor AudioContext creation
                const origAudioContext = window.AudioContext || window.webkitAudioContext;
                if (origAudioContext) {
                    window.AudioContext = function(...args) {
                        const ctx = new origAudioContext(...args);
                        window.activeAudioContexts.add(ctx);
                        return ctx;
                    };
                    window.webkitAudioContext = window.AudioContext;
                }

                log('WebRTC monitoring initialized');
            } catch(err) {
                console.warn('WebRTC injection error:', err);
            }
        })();
        """
        try:
            self.runJavaScript(js)
        except Exception as e:
            print("[webrtc_webpage] Injection error:", e)

    def drop_microphone(self):
        """Comprehensive media cleanup"""
        stop_js = r"""
        (function() {
            try {
                // Stop all media streams
                if (window.localStreams) {
                    window.localStreams.forEach(stream => {
                        stream.getTracks().forEach(track => {
                            track.stop();
                            try { track.enabled = false; } catch(e) {}
                        });
                    });
                    window.localStreams.clear();
                }
                
                // Close all peer connections
                if (window.peerConnections) {
                    window.peerConnections.forEach(pc => {
                        try {
                            pc.getSenders().forEach(sender => {
                                if (sender.track) sender.track.stop();
                            });
                            pc.close();
                        } catch(e) {}
                    });
                    window.peerConnections.clear();
                }
                
                // Close all audio contexts
                if (window.activeAudioContexts) {
                    window.activeAudioContexts.forEach(ctx => {
                        try { 
                            ctx.close();
                            ctx.suspend();
                        } catch(e) {}
                    });
                    window.activeAudioContexts.clear();
                }
                
                // Revoke permissions
                if (navigator.permissions && navigator.permissions.revoke) {
                    navigator.permissions.revoke({name: 'microphone'});
                    navigator.permissions.revoke({name: 'camera'});
                }
                
                console.log('[webrtc_cleanup] All media resources released');
            } catch(e) {
                console.error('Media cleanup error:', e);
            }
        })();
        """
        try:
            self.runJavaScript(stop_js)
            QTimer.singleShot(100, self.cleanup_audio_system)  # System cleanup after JS executes
        except Exception as e:
            print("Media cleanup error:", e)

    def cleanup_audio_system(self):
        """System-level audio cleanup (Linux-specific)"""
        if sys.platform.startswith('linux'):
            try:
                # Reset PulseAudio modules
                subprocess.run([
                    'pactl', 'unload-module', 'module-echo-cancel'
                ], stderr=subprocess.DEVNULL)
                
                # Kill any Chromium audio processes
                subprocess.run([
                    'pkill', '-f', 'chromium.*audio'
                ], stderr=subprocess.DEVNULL)
                
                # Reset audio sinks
                subprocess.run([
                    'pactl', 'suspend-sink', '@DEFAULT_SINK@', '0'
                ], stderr=subprocess.DEVNULL)
                
            except Exception as e:
                print("System audio cleanup error:", e)










#--------------------------------------------------------------------------------
class UrlLauncherDialog(QDialog):
    def __init__(self, parent=None, current_url=""):
        super().__init__(parent)
        self.parent_browser = parent
        self.setWindowTitle("Quick URL Launcher")
        self.setMinimumWidth(600)
        
        self._apply_theme()
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        
        self.url_input = QLineEdit()
        self.url_input.setObjectName("urlInput")
        self.url_input.setPlaceholderText("Enter URL or search terms...")
        self.url_input.setText(current_url)
        self.url_input.selectAll()
        layout.addWidget(self.url_input)
        
        btn_layout = QHBoxLayout()
        self.ok_button = QPushButton("Go")
        self.ok_button.setDefault(True)
        self.cancel_button = QPushButton("Cancel")
        btn_layout.addWidget(self.ok_button)
        btn_layout.addStretch()
        btn_layout.addWidget(self.cancel_button)
        layout.addLayout(btn_layout)
        
        self.ok_button.clicked.connect(self._handle_input)
        self.cancel_button.clicked.connect(self.reject)
        self.url_input.returnPressed.connect(self._handle_input)
        self.url_input.installEventFilter(self)
        self.url_input.setFocus()
    
    # Add back the get_url method for compatibility
    def get_url(self):
        """Compatibility method for older code"""
        return self.url_input.text().strip()
    
    def eventFilter(self, obj, event):
        if obj == self.url_input and event.type() == QEvent.KeyPress:
            if event.key() in (Qt.Key_Return, Qt.Key_Enter) and event.modifiers() & Qt.ControlModifier:
                self._autocomplete_url()
                return True
            elif event.key() == Qt.Key_Escape:
                self.reject()
                return True
        return super().eventFilter(obj, event)
    
    def _apply_theme(self):
        if not self.parent_browser:
            return
            
        accent_color = self.parent_browser.current_accent_color
        dark_mode = self.parent_browser.settings_manager.get("dark_mode", False)
        
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {'#252525' if dark_mode else '#ffffff'};
            }}
            QLineEdit#urlInput {{
                border: 2px solid {accent_color};
                border-radius: 15px;
                padding: 8px;
                background: {'#353535' if dark_mode else '#ffffff'};
                color: {'#f0f0f0' if dark_mode else '#000000'};
                selection-background-color: {accent_color};
                font-size: 14px;
                margin-bottom: 10px;
            }}
            QLineEdit#urlInput:focus {{
                border: 2px solid {self._lighten_color(accent_color, 20)};
            }}
            QPushButton {{
                min-width: 80px;
                padding: 5px;
                border-radius: 4px;
                border: 1px solid {'#555' if dark_mode else '#ccc'};
                background: {'#3a3a3a' if dark_mode else '#f0f0f0'};
                color: {'#f0f0f0' if dark_mode else '#000000'};
            }}
            QPushButton:hover {{
                background: {'#4a4a4a' if dark_mode else '#e0e0e0'};
            }}
        """)
    
    def _lighten_color(self, hex_color, percent):
        hex_color = hex_color.lstrip('#')
        r, g, b = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        r = min(255, r + int(255 * (percent/100)))
        g = min(255, g + int(255 * (percent/100)))
        b = min(255, b + int(255 * (percent/100)))
        return f"#{r:02x}{g:02x}{b:02x}"
    
    def _handle_input(self):
        text = self.url_input.text().strip()
        if not text:
            self.reject()
            return
        
        if self.parent_browser:
            self.parent_browser.navigate_to_url(text)
        
        self.accept()
    
    def _autocomplete_url(self):
        text = self.url_input.text().strip()
        
        if (text.startswith(('http://', 'https://', 'ftp://')) or 
            any(tld in text.lower() for tld in ['.com', '.org', '.net', '.io'])):
            self._handle_input()
            return
        
        if any(c in text for c in ' ?&=%+'):
            search_url = self.parent_browser.settings_manager.get(
                "search_engine", 
                "https://www.google.com/search?q={}"
            ).format(urllib.parse.quote(text))
            self.url_input.setText(search_url)
            self._handle_input()
            return
        
        if not text.startswith(('http://', 'https://')):
            if '.' in text:
                text = f'https://{text}'
            else:
                text = f'https://{text}.com'
        
        self.url_input.setText(text)
        self._handle_input()



       
#-------------------------------------------------------

class WebView(QWebEngineView):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setPage(WebPage(self))

class ThemeManager:
    def __init__(self, settings_manager):
        self.settings_manager = settings_manager
        self.current_accent_color = self.settings_manager.get("theme", {}).get("accent_color", "#3daee9")

        # Connect to accent color changes
        if hasattr(self.settings_manager, 'accent_color_changed'):
            self.settings_manager.accent_color_changed.connect(self.update_accent_color)

    def lighten_color(self, hex_color, percent):
        """Lighten a color by specified percentage"""
        hex_color = hex_color.lstrip('#')
        r, g, b = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        r = min(255, r + int(255 * (percent/100)))
        g = min(255, g + int(255 * (percent/100)))
        b = min(255, b + int(255 * (percent/100)))
        return f"#{r:02x}{g:02x}{b:02x}"

    def update_accent_color(self, color_hex):
        """Update the current accent color and refresh UI"""
        print(f"ThemeManager: Updating accent color to {color_hex}")  # Debug print
        self.current_accent_color = color_hex
        self.apply_theme(QApplication.instance())

    def get_base_colors(self):
        """Return color palette based on current theme mode"""
        dark_mode = self.settings_manager.get("dark_mode", True)

        return {
            'bg_color': '#2d2d2d' if dark_mode else '#ffffff',
            'text_color': '#f0f0f0' if dark_mode else '#000000',
            'button_color': '#3a3a3a' if dark_mode else '#e0e0e0',
            'window_color': '#252525' if dark_mode else '#f0f0f0',
            'highlight_color': self.current_accent_color,
            'disabled_color': '#404040' if dark_mode else '#c0c0c0'
        }

    def generate_stylesheet(self):
        """Generate complete stylesheet for the application"""
        colors = self.get_base_colors()
        accent_light = self.lighten_color(self.current_accent_color, 20)
        accent_lighter = self.lighten_color(self.current_accent_color, 40)

        return f"""
            /* Main Window */
            QMainWindow {{
                background-color: {colors['bg_color']};
                color: {colors['text_color']};
            }}

            /* Menu and Tool Bars */
            QMenuBar {{
                background-color: {colors['window_color']};
                color: {colors['text_color']};
                border-bottom: 2px solid {colors['highlight_color']};
            }}

            QToolBar {{
                background-color: {colors['window_color']};
                border-bottom: 1px solid {colors['highlight_color']};
                spacing: 5px;
                padding: 3px;
            }}

            /* Text Inputs */
            QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QComboBox {{
                background-color: {colors['window_color']};
                color: {colors['text_color']};
                border: 1px solid {colors['highlight_color']};
                border-radius: 4px;
                padding: 5px;
                selection-background-color: {colors['highlight_color']};
            }}

            QLineEdit#url_bar {{
                border: 2px solid {colors['highlight_color']};
                border-radius: 15px;
                padding: 5px 10px;
            }}

            /* Buttons */
            QPushButton, QToolButton {{
                background-color: {colors['button_color']};
                color: {colors['text_color']};
                border: 1px solid {colors['highlight_color']};
                border-radius: 4px;
                padding: 5px 10px;
            }}

            QPushButton:hover, QToolButton:hover {{
                background-color: {accent_light};
            }}

            QPushButton:pressed, QToolButton:pressed {{
                background-color: {colors['highlight_color']};
            }}

            /* Tabs */
            QTabWidget::pane {{
                border: none;
                background: {colors['bg_color']};
            }}

            QTabBar::tab {{
                background: {colors['button_color']};
                color: {colors['text_color']};
                border: 1px solid {colors['highlight_color']};
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                padding: 5px 10px;
                margin-right: 2px;
            }}

            QTabBar::tab:selected {{
                background: {colors['bg_color']};
                border-bottom: 2px solid {colors['highlight_color']};
            }}

            QTabBar::tab:hover {{
                background: {accent_light};
            }}

            /* Scrollbars */
            QScrollBar:vertical, QScrollBar:horizontal {{
                background: {colors['window_color']};
                border: none;
                width: 12px;
                height: 12px;
            }}

            QScrollBar::handle:vertical, QScrollBar::handle:horizontal {{
                background: {colors['highlight_color']};
                min-height: 20px;
                min-width: 20px;
                border-radius: 6px;
            }}

            QScrollBar::add-line, QScrollBar::sub-line {{
                background: none;
                border: none;
            }}

            /* Dialogs */
            QDialog {{
                background: {colors['bg_color']};
                border: 2px solid {colors['highlight_color']};
            }}

            QDialogButtonBox QPushButton {{
                min-width: 80px;
            }}

            /* Menus */
            QMenu {{
                background: {colors['window_color']};
                border: 1px solid {colors['highlight_color']};
            }}

            QMenu::item:selected {{
                background: {accent_light};
            }}

            /* Tooltips */
            QToolTip {{
                background: {colors['window_color']};
                color: {colors['text_color']};
                border: 1px solid {colors['highlight_color']};
            }}

            /* Disabled elements */
            QWidget:disabled {{
                color: {colors['disabled_color']};
            }}
        """

    def apply_theme(self, widget=None):
        """Apply the theme to a specific widget or the entire application"""
        stylesheet = self.generate_stylesheet()
        if widget:
            widget.setStyleSheet(stylesheet)
            widget.update()
        else:
            app = QApplication.instance()
            app.setStyleSheet(stylesheet)
            for window in app.topLevelWidgets():
                window.update()

    def get_icon_color(self):
        """Get appropriate icon color based on theme"""
        return QColor('#ffffff') if self.settings_manager.get("dark_mode", True) else QColor('#000000')

    def get_highlight_color(self):
        """Get the current highlight (accent) color"""
        return QColor(self.current_accent_color)



class ThemeSettingsTab(QWidget):
    accent_color_changed = pyqtSignal(str)  # Signal emitted when accent color changes
    theme_mode_changed = pyqtSignal(str)    # Signal emitted when theme mode changes
    
    def __init__(self, settings_manager, parent=None):
        super().__init__(parent)
        self.settings_manager = settings_manager
        self.setup_ui()
        self.load_settings()

    def setup_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Theme mode selection
        theme_group = QGroupBox("Theme Mode")
        theme_layout = QVBoxLayout()
        
        self.system_radio = QRadioButton("System Theme")
        self.light_radio = QRadioButton("Light Theme")
        self.dark_radio = QRadioButton("Dark Theme")
        
        theme_layout.addWidget(self.system_radio)
        theme_layout.addWidget(self.light_radio)
        theme_layout.addWidget(self.dark_radio)
        theme_group.setLayout(theme_layout)
        
        # Accent color selection
        color_group = QGroupBox("Accent Color")
        self.color_layout = QVBoxLayout()  # Made this an instance variable
        
        # Create color buttons
        self.color_buttons = []
        self.setup_color_buttons()
        
        # Add custom color picker
        self.custom_color_btn = QPushButton("Custom Color...")
        self.custom_color_btn.clicked.connect(self.pick_custom_color)
        self.color_layout.addWidget(self.custom_color_btn)
        
        color_group.setLayout(self.color_layout)
        
        # Theme presets
        preset_group = QGroupBox("Theme Presets")
        preset_layout = QHBoxLayout()
        
        self.preset_combo = QComboBox()
        self.preset_combo.addItems(self.settings_manager.get_theme_presets())
        self.preset_combo.currentTextChanged.connect(self.apply_preset)
        
        preset_layout.addWidget(QLabel("Preset:"))
        preset_layout.addWidget(self.preset_combo)
        preset_group.setLayout(preset_layout)
        
        # Add to main layout
        layout.addWidget(theme_group)
        layout.addWidget(color_group)
        layout.addWidget(preset_group)
        layout.addStretch()
        
        self.setLayout(layout)
        
        # Connect signals
        self.system_radio.toggled.connect(self.toggle_theme_mode)
        self.light_radio.toggled.connect(self.toggle_theme_mode)
        self.dark_radio.toggled.connect(self.toggle_theme_mode)

    def setup_color_buttons(self):
        """Initialize all color buttons in one place"""
        colors = self.settings_manager.get_available_accent_colors()
        current_color = self.settings_manager.get("theme", {}).get("accent_color", "#3daee9")
        
        for color_info in colors:
            btn = self.create_color_button(color_info, current_color)
            self.color_buttons.append(btn)
            self.color_layout.addWidget(btn)

    def create_color_button(self, color_info, current_color):
        """Create a single color selection button"""
        btn = QPushButton(color_info["name"])
        btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {color_info["color"]};
                color: white;
                border: none;
                padding: 8px;
                text-align: left;
                border-radius: 4px;
                margin: 2px;
                min-width: 100px;
            }}
            QPushButton:hover {{
                border: 2px solid white;
            }}
            QPushButton:checked {{
                border: 3px solid white;
                font-weight: bold;
            }}
        """)
        btn.setCheckable(True)
        btn.setChecked(color_info["color"] == current_color)
        btn.clicked.connect(lambda checked, c=color_info["color"]: self.select_color(c))
        return btn

    def pick_custom_color(self):
        """Open color dialog to pick a custom accent color"""
        color = QColorDialog.getColor()
        if color.isValid():
            hex_color = color.name()
            self.add_custom_color(hex_color)
            self.select_color(hex_color)

    def add_custom_color(self, hex_color):
        """Add custom color to available colors if not present"""
        colors = self.settings_manager.get("theme", {}).get("available_colors", [])
        if not any(c["color"] == hex_color for c in colors):
            colors.append({"name": "Custom", "color": hex_color})
            self.settings_manager.set("theme", {"available_colors": colors})
            
            # Add new button for the custom color
            btn = self.create_color_button({"name": "Custom", "color": hex_color}, hex_color)
            self.color_buttons.append(btn)
            # Insert before the custom color button
            self.color_layout.insertWidget(self.color_layout.count()-1, btn)
    
    def load_settings(self):
        """Load current theme settings"""
        theme_mode = self.settings_manager.get("theme_mode", "system")
        
        if theme_mode == "system":
            self.system_radio.setChecked(True)
        elif theme_mode == "light":
            self.light_radio.setChecked(True)
        else:
            self.dark_radio.setChecked(True)

    def toggle_theme_mode(self, checked):
        """Toggle between theme modes"""
        if not checked:
            return
            
        if self.sender() == self.system_radio:
            mode = "system"
        elif self.sender() == self.light_radio:
            mode = "light"
        else:
            mode = "dark"
        
        # Store the mode and emit signal
        self.settings_manager.set("theme_mode", mode)
        self.theme_mode_changed.emit(mode)
        self.settings_manager.apply_theme(QApplication.instance())

    def select_color(self, color_hex):
        """Select an accent color - now with forced refresh"""
        # Update button states
        for btn in self.color_buttons:
            btn.setChecked(btn.styleSheet().contains(color_hex))
        
        # Update settings
        self.settings_manager.apply_accent_color(color_hex)
        
        # Emit signal (connected to main window)
        self.accent_color_changed.emit(color_hex)
        
        # Force immediate theme refresh
        app = QApplication.instance()
        self.settings_manager.apply_theme(app)
        
        # Optional: Update just this widget
        self.update()
        self.updateGeometry()
        
    def apply_preset(self, preset_name):
        """Apply a theme preset"""
        if preset_name:
            success = self.settings_manager.apply_theme_preset(preset_name)
            if success:
                # Update selected color button
                new_color = self.settings_manager.get("theme", {}).get("accent_color", "#3daee9")
                self.select_color(new_color)
                # Force UI update
                self.settings_manager.apply_theme(QApplication.instance())

    def update_all_widgets(self):
        """Force update all widgets to apply new theme"""
        QApplication.instance().setStyleSheet(QApplication.instance().styleSheet())

class ScreenRecorder(QObject):
    """
    A robust screen recorder with audio capture, real-time stats, and cross-platform support.
    Features:
    - Screen region recording
    - System audio + microphone capture
    - Real-time file size and duration tracking
    - Automatic duration limits
    - Comprehensive error handling
    """
    
    # Signals
    recording_started = pyqtSignal(str, int)  # filename, duration_seconds
    recording_finished = pyqtSignal(str, bool, str)  # filename, success, duration_str
    recording_progress = pyqtSignal(str, int, int, str, str, str, str)  # filename, elapsed_secs, total_secs, elapsed_str, remaining_str, size_str, bitrate_str
    recording_error = pyqtSignal(str)
    recording_timeout = pyqtSignal()
    recording_status = pyqtSignal(str)
    recording_stats = pyqtSignal(str)  # File size/duration updates

    def __init__(self, parent=None):
        super().__init__(parent)
        self.recording_process = None
        self.recording_file = ""
        self.is_recording = False
        self.region = None
        self.max_duration = 0
        self.start_time = None
        self.last_size = 0
        
        # Initialize timers
        self._init_timers()

    def _init_timers(self):
        """Initialize all QTimer instances"""
        self.progress_timer = QTimer(self)
        self.progress_timer.setInterval(1000)
        self.progress_timer.timeout.connect(self._update_progress)
        
        self.duration_timer = QTimer(self)
        self.duration_timer.setSingleShot(True)
        self.duration_timer.timeout.connect(self._on_duration_timeout)
        
        self.stats_timer = QTimer(self)
        self.stats_timer.setInterval(1000)
        self.stats_timer.timeout.connect(self.update_recording_stats)

    def start_recording(self, region=None, max_duration_minutes=0, include_mic=True, include_speaker=True, quality=1):
        """Start screen recording with countdown timer initialization"""
        if self.is_recording:
            self.recording_error.emit("Recording already in progress")
            return False

        try:
            # If no region specified, use full screen minus taskbar
            if not region:
                region = self.get_full_screen_rect_without_taskbar()
                if not region:
                    self.recording_error.emit("Could not determine screen dimensions")
                    return False

            self.region = region
            self.max_duration = max_duration_minutes * 60  # Convert to seconds
            self.recording_file = self._generate_filename()
            
            # Store timestamps as floats for accurate time calculations
            self.start_time = time.time()
            self.last_update_time = self.start_time
            self.last_size = 0

            # Build and execute FFmpeg command
            cmd = self._build_ffmpeg_command(include_mic, include_speaker, quality)
            self._start_ffmpeg_process(cmd)

            # Update recording state
            self.is_recording = True
            self.progress_timer.start(1000)  # Update progress every second
            self.stats_timer.start(1000)     # Update stats every second
            
            # Start duration timer if limited recording
            if self.max_duration > 0:
                self.duration_timer.start(self.max_duration * 1000)

            # Emit initial progress with all 7 arguments
            self.recording_progress.emit(
                self.recording_file, 
                int(0),  # elapsed_secs
                self.max_duration,  # total_secs
                "00:00",  # elapsed_str
                self._format_time(self.max_duration) if self.max_duration > 0 else "Unlimited",  # remaining_str
                "0 B",  # size_str
                "0 kbps"  # bitrate_str
            )
            
            self.recording_started.emit(self.recording_file, self.max_duration)
            return True

        except Exception as e:
            error_msg = f"Recording failed: {str(e)}"
            self.recording_error.emit(error_msg)
            print(error_msg)
            traceback.print_exc()
            self._cleanup_failed_recording()
            return False


    
    def _update_progress(self):
        """Update recording progress with all stats"""
        if not self.is_recording:
            return

        current_time = time.time()
        elapsed = current_time - self.start_time
        remaining = max(0, self.max_duration - elapsed) if self.max_duration > 0 else 0
        
        # Calculate file size
        size_str = "0 B"
        if os.path.exists(self.recording_file):
            size = os.path.getsize(self.recording_file)
            size_str = format_size(size)
        
        # Calculate bitrate
        bitrate_str = ""
        if elapsed > 0 and os.path.exists(self.recording_file):
            bitrate = (os.path.getsize(self.recording_file) * 8) / (elapsed * 1000)  # kbps
            bitrate_str = f"{bitrate:.1f} kbps"
        
        # Emit with all 7 parameters
        self.recording_progress.emit(
            self.recording_file,
            int(elapsed),
            self.max_duration,
            self._format_time(elapsed),
            self._format_time(remaining) if self.max_duration > 0 else "Unlimited",
            size_str,
            bitrate_str
        )


    def _start_ffmpeg_process(self, cmd):
        """Start the FFmpeg subprocess with proper platform settings"""
        kwargs = {
            'stdin': subprocess.PIPE,
            'stdout': subprocess.PIPE,
            'stderr': subprocess.PIPE,
            'universal_newlines': True
        }
        
        if sys.platform == "win32":
            kwargs.update({
                'shell': True,
                'creationflags': subprocess.CREATE_NO_WINDOW
            })
        
        self.recording_process = subprocess.Popen(cmd, **kwargs)
        time.sleep(0.5)  # Allow time for process to initialize

    def _build_ffmpeg_command(self, include_mic=True, include_speaker=True, quality=1):
        """Construct FFmpeg command based on parameters"""
        cmd = ["ffmpeg", "-y"]
        
        # Video capture (unchanged)
        if not self.region:
            cmd.extend(["-f", "x11grab", "-video_size", "1920x1080", "-framerate", "30", "-i", ":0.0+0,0"])
        else:
            cmd.extend([
                "-f", "x11grab",
                "-video_size", f"{self.region.width()}x{self.region.height()}",
                "-framerate", "30",
                "-i", f":0.0+{self.region.x()},{self.region.y()}"
            ])
        
        # Audio capture (now using monitor device for system audio)
        if include_speaker:
            cmd.extend(["-f", "pulse", "-i", "alsa_output.pci-0000_00_1b.0.analog-stereo.monitor"])
        if include_mic:
            cmd.extend(["-f", "pulse", "-i", "alsa_input.pci-0000_00_1b.0.analog-stereo"])
        
        # Audio mixing with echo cancellation
        if include_mic and include_speaker:
            cmd.extend([
                "-filter_complex",
                "[1:a]aecho=0.8:0.9:1000:0.3[mic_echo];"  # Echo cancellation on mic
                "[mic_echo][2:a]aecho=0.8:0.7:1000:0.3,"
                "amerge=inputs=2[a]",  # Merge with echo-cancelled system audio
                "-map", "0:v",
                "-map", "[a]"
            ])
        elif include_mic or include_speaker:
            cmd.extend(["-map", "0:v", "-map", "1:a"])
        
        # Video encoding (unchanged)
        cmd.extend([
            "-c:v", "libx264",
            "-preset", "fast",
            "-crf", str(23 - quality * 5) if quality else "18",
            "-pix_fmt", "yuv420p",
            "-movflags", "+faststart"
        ])
        
        # Audio encoding with additional processing
        if include_mic or include_speaker:
            cmd.extend([
                "-c:a", "aac",
                "-b:a", "192k",
                "-ar", "44100",
                "-af", "highpass=f=100,lowpass=f=3000"  # Basic noise filtering
            ])
        
        cmd.append(self.recording_file)
        return cmd


    
    def update_recording_stats(self):
        """Update real-time recording statistics"""
        if not self.is_recording or not self.recording_file:
            return

        try:
            current_size = os.path.getsize(self.recording_file)
            size_mb = current_size / (1024 * 1024)
            self.last_size = current_size
            
            elapsed = time.time() - self.start_time

            hours, remainder = divmod(elapsed, 3600)
            minutes, seconds = divmod(remainder, 60)
            
            bitrate = ""
            if elapsed > 0:
                rate_kbps = (current_size * 8) / (elapsed * 1000)
                bitrate = f" | {rate_kbps:.1f} kbps"
            
            status = (f"Recording: {int(hours):02d}:{int(minutes):02d}:{int(seconds):02d} | "
                     f"Size: {size_mb:.2f} MB{bitrate}")
            
            self.recording_stats.emit(status)
        except FileNotFoundError:
            self.recording_stats.emit("Initializing recording...")
        except Exception as e:
            print(f"Stats update error: {e}")

    def stop_recording(self):
        """Stop recording with multiple fallback methods"""
        if not self.is_recording:
            return False

        success = False
        try:
            # Try graceful shutdown first
            if self.recording_process and self.recording_process.stdin:
                try:
                    self.recording_process.stdin.write("q\n")
                    self.recording_process.stdin.flush()
                    self.recording_process.wait(3)
                    success = True
                except (BrokenPipeError, AttributeError):
                    pass

            # Force terminate if needed
            if not success and self.recording_process and self.recording_process.poll() is None:
                self.recording_process.terminate()
                try:
                    self.recording_process.wait(2)
                    success = True
                except subprocess.TimeoutExpired:
                    self.recording_process.kill()
                    self.recording_process.wait()
                    success = False

            # Verify output file
            if success:
                success = self._verify_output_file()

            return success
        except Exception as e:
            print(f"Stop recording error: {e}")
            return False
        finally:
            self._cleanup_recording(success)

    def _verify_output_file(self):
        """Verify the recorded file is valid"""
        try:
            if not os.path.exists(self.recording_file):
                return False
                
            if os.path.getsize(self.recording_file) < 10240:
                return False
                
            return self._is_valid_video(self.recording_file)
        except Exception:
            return False

    def _is_valid_video(self, filepath):
        """Check if file is valid video using ffprobe"""
        try:
            result = subprocess.run(
                ["ffprobe", "-v", "error", filepath],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=2
            )
            return result.returncode == 0
        except:
            return False

    def _cleanup_recording(self, success):
        """Clean up after recording stops"""
        self.is_recording = False
        self.progress_timer.stop()
        self.duration_timer.stop()
        self.stats_timer.stop()
        
        if self.recording_process:
            self.recording_process.stdin = None
            self.recording_process.stdout = None
            self.recording_process.stderr = None
            self.recording_process = None

        duration_str = self._format_duration(self.max_duration)
        self.recording_finished.emit(self.recording_file, success, duration_str)

    def _cleanup_failed_recording(self):
        """Clean up after failed start"""
        if hasattr(self, 'recording_process') and self.recording_process:
            try:
                self.recording_process.kill()
            except:
                pass
        self._cleanup_recording(False)

    def _read_process_error(self):
        """Read FFmpeg process error output"""
        try:
            if self.recording_process:
                return self.recording_process.stderr.read()
        except:
            return "Unknown error"

    def _generate_filename(self):
        """Generate timestamped filename in Videos folder"""
        timestamp = QDateTime.currentDateTime().toString("yyyyMMdd_HHmmss")
        videos_dir = os.path.join(os.path.expanduser("~"), "Videos", "ScreenRecordings")
        os.makedirs(videos_dir, exist_ok=True)
        return os.path.join(videos_dir, f"recording_{timestamp}.mp4")





    def _on_duration_timeout(self):
        """Handle recording duration timeout."""
        if self.is_recording:
            success = self.stop_recording()
            duration_str = self._format_duration(self.max_duration)
            self.recording_timeout.emit()
            self.recording_finished.emit(self.recording_file, success, duration_str)
            # Ensure we emit the signal to update the UI
            self.recording_status.emit("Recording finished (timeout)")

    def _format_duration(self, seconds):
        """Format seconds as HH:MM:SS"""
        m, s = divmod(seconds, 60)
        h, m = divmod(m, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"

    # Public getters
    def get_current_recording_file(self):
        return self.recording_file if self.is_recording else ""

    def is_recording_active(self):
        return self.is_recording




    def get_full_screen_rect_without_taskbar(self, taskbar_height=40):
        """Get screen rectangle excluding taskbar"""
        screen = QApplication.primaryScreen()
        if not screen:
            return None
            
        screen_geom = screen.geometry()
        return QRect(
            screen_geom.x(),
            screen_geom.y(),
            screen_geom.width(),
            screen_geom.height() - taskbar_height
        )



    def get_remaining_time(self):
        """Returns remaining recording time in seconds"""
        if not self.is_recording or not self.max_duration:
            return 0
        elapsed = time.time() - self.start_time

        return max(0, self.max_duration - elapsed)

    def get_formatted_remaining_time(self):
        """Returns formatted MM:SS remaining time string"""
        remaining = self.get_remaining_time()
        return f"{int(remaining//60):02d}:{int(remaining%60):02d}"





    def _format_time(self, seconds):
        """Format seconds into HH:MM:SS or MM:SS"""
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        seconds = int(seconds % 60)
        
        if hours > 0:
            return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        return f"{minutes:02d}:{seconds:02d}"


    def setup_recording_ui(self):
        """Setup recording status display in status bar"""
        # Recording status widget
        self.recording_status_widget = QWidget()
        self.recording_layout = QHBoxLayout()
        self.recording_layout.setContentsMargins(0, 0, 0, 0)
        self.recording_layout.setSpacing(10)
        
        # Elapsed time label
        self.elapsed_label = QLabel("00:00")
        self.elapsed_label.setStyleSheet("color: #ff4545; font-weight: bold;")
        self.recording_layout.addWidget(self.elapsed_label)
        
        # Countdown label
        self.countdown_label = QLabel("02:00")
        self.countdown_label.setStyleSheet("color: #45a1ff; font-weight: bold;")
        self.recording_layout.addWidget(self.countdown_label)
        
        # Separator
        self.recording_layout.addWidget(QLabel("|"))
        
        # File size label
        self.size_label = QLabel("0 MB")
        self.recording_layout.addWidget(self.size_label)
        
        # Bitrate label
        self.bitrate_label = QLabel("0 kbps")
        self.recording_layout.addWidget(self.bitrate_label)
        
        # Add to status bar
        self.recording_status_widget.setLayout(self.recording_layout)
        self.status_bar.addPermanentWidget(self.recording_status_widget)
        self.recording_status_widget.hide()

#-----------------------------------------------------#
import os
import re
import time
from PyQt5.QtCore import QObject, pyqtSignal, QTimer
from PyQt5.QtNetwork import QNetworkAccessManager, QNetworkReply
from PyQt5.QtWebEngineCore import QWebEngineUrlRequestInterceptor

# Directory to store ad block filter lists
ADBLOCK_FILTERS_DIR = os.path.join(os.path.expanduser("~"), ".config", "storm_browser", "adblock_filters")

class AdBlockManager(QObject):
    filter_updated = pyqtSignal(bool)  # Signal for filter update completion

    def __init__(self, parent=None):
        super().__init__(parent)
        self.network_manager = QNetworkAccessManager(self)
        self.filters = {
            'easylist': set(),
            'easyprivacy': set(),
            'ublock': set(),
            'custom': set()
        }
        self.cosmetic_filters = {
            'hide_selectors': set(),
            'style_selectors': set(),
            'scriptlets': set()
        }
        self.whitelisted_domains = set()
        self.last_update = 0
        self.filter_update_interval = 4 * 60 * 60  # 4 hours
        self.filter_lists = {
            'easylist': "https://easylist.to/easylist/easylist.txt",
            'easyprivacy': "https://easylist.to/easylist/easyprivacy.txt",
            'ublock': "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt"
        }

        # Initialize
        self._setup_directories()
        self.load_filters()
        self._schedule_updates()

    def _setup_directories(self):
        """Ensure all needed directories exist."""
        os.makedirs(ADBLOCK_FILTERS_DIR, exist_ok=True)
        if not os.path.exists(os.path.join(ADBLOCK_FILTERS_DIR, "custom.txt")):
            with open(os.path.join(ADBLOCK_FILTERS_DIR, "custom.txt"), 'w') as f:
                f.write("! Custom filter rules\n")

    def _schedule_updates(self):
        """Schedule periodic filter updates."""
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.update_filters)
        self.update_timer.start(self.filter_update_interval * 1000)

    def load_filters(self):
        """Load all filters with validation and error recovery."""
        loaded_lists = 0
        for list_name in list(self.filter_lists.keys()) + ['custom']:
            try:
                filter_path = os.path.join(ADBLOCK_FILTERS_DIR, f"{list_name}.txt")
                if os.path.exists(filter_path):
                    with open(filter_path, 'r', encoding='utf-8', errors='replace') as f:
                        count = self._parse_filter_file(f, list_name)
                        if count > 0:
                            loaded_lists += 1
                            print(f"Loaded {count} rules from {list_name}")
            except Exception as e:
                print(f"Error loading {list_name}: {e}")

        # Load whitelist
        try:
            whitelist_path = os.path.join(ADBLOCK_FILTERS_DIR, "whitelist.txt")
            if os.path.exists(whitelist_path):
                with open(whitelist_path, 'r', encoding='utf-8') as f:
                    self.whitelisted_domains = {line.strip() for line in f if line.strip()}
        except Exception as e:
            print(f"Error loading whitelist: {e}")

        return loaded_lists > 0  # Return True if any lists loaded

    def _parse_filter_file(self, file_obj, list_name):
        """Parse filter file with optimized rule processing."""
        rule_count = 0
        for line in file_obj:
            line = line.strip()
            if not line or line.startswith('!'):
                continue

            if line.startswith('##'):
                self._parse_cosmetic_filter(line)
                rule_count += 1
            elif line.startswith('@@'):
                self._process_exception_rule(line)
                rule_count += 1
            else:
                self.filters[list_name].add(line)
                rule_count += 1

        return rule_count

    def _parse_cosmetic_filter(self, line):
        """Parse cosmetic filter rules."""
        if line.startswith('##^'):
            self.cosmetic_filters['hide_selectors'].add(line[3:])
        elif line.startswith('##'):
            self.cosmetic_filters['style_selectors'].add(line[2:])
        elif line.startswith('#@#'):
            self.cosmetic_filters['scriptlets'].add(line[3:])

    def _process_exception_rule(self, rule):
        """Process exception rules with domain handling."""
        parts = rule[2:].split('$')
        domains = []

        if len(parts) > 1:
            options = parts[1].lower().split(',')
            domains = [opt[7:] for opt in options if opt.startswith('domain=')]

        if domains:
            self.whitelisted_domains.update(domains)
        else:
            self.whitelisted_domains.add(parts[0])

    def update_filters(self, force=False):
        """Update all filter lists with parallel downloads."""
        if not force and time.time() - self.last_update < self.filter_update_interval:
            return

        self.last_update = time.time()
        success_count = 0

        for list_name, url in self.filter_lists.items():
            reply = self.network_manager.get(QNetworkRequest(QUrl(url)))
            reply.finished.connect(
                lambda reply=reply, list_name=list_name: self._handle_filter_download(reply, list_name)
            )

            # Set timeout
            QTimer.singleShot(15000, reply.abort)

        self.filter_updated.emit(success_count > 0)

    def _handle_filter_download(self, reply, list_name):
        """Handle completed filter download."""
        try:
            if reply.error() == QNetworkReply.NoError:
                data = reply.readAll().data()
                if data and b'[Adblock' in data:
                    path = os.path.join(ADBLOCK_FILTERS_DIR, f"{list_name}.txt")
                    with open(path, 'wb') as f:
                        f.write(data)
                    # Reload the filter
                    with open(path, 'r', encoding='utf-8') as f:
                        self._parse_filter_file(f, list_name)
                    return True
        except Exception as e:
            print(f"Error processing {list_name}: {e}")
        finally:
            reply.deleteLater()
        return False

    def should_block_request(self, request_info):
        """Determine if request should be blocked with enhanced logic."""
        url = request_info.requestUrl()
        first_party = request_info.firstPartyUrl()
        resource_type = request_info.resourceType()

        # Skip main frames and important resources
        if resource_type in (QWebEngineUrlRequestInterceptor.ResourceTypeMainFrame,
                             QWebEngineUrlRequestInterceptor.ResourceTypeStylesheet,
                             QWebEngineUrlRequestInterceptor.ResourceTypeScript):
            return False

        # Check whitelist
        domain = url.host()
        if domain in self.whitelisted_domains:
            return False

        # Check against filter lists
        url_str = url.toString()
        for filter_set in self.filters.values():
            for pattern in filter_set:
                if self._match_pattern(url_str, pattern):
                    return True

        return False

    def _match_pattern(self, url, pattern):
        """Optimized pattern matching with caching."""
        # Simple string match
        if not any(c in pattern for c in '^|*'):
            return pattern in url

        # Convert to regex
        regex = []
        in_anchor = False

        for c in pattern:
            if c == '^':
                regex.append(r'([^\w\d_\-%.]|$)')
            elif c == '*':
                regex.append('.*')
            elif c == '|':
                if not regex:
                    regex.append('^')
                elif regex[-1] == '$':
                    continue
                else:
                    regex.append('$')
            else:
                regex.append(re.escape(c))

        try:
            return re.compile(''.join(regex), re.I).search(url) is not None
        except:
            return False

    def get_cosmetic_filters(self):
        """Get all cosmetic filters."""
        return self.cosmetic_filters

class AdBlockRequestInterceptor(QWebEngineUrlRequestInterceptor):
    def __init__(self, adblock_manager, parent=None):
        super().__init__(parent)
        self.manager = adblock_manager

    def interceptRequest(self, info):
        if self.manager.should_block_request(info):
            info.block(True)






class AudioLevelVisualizer(QProgressBar):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.current_level = 0
        self.smoothing_factor = 0.7
        self.animation_timer = QTimer(self)
        self.setup_connections()
        
    def setup_ui(self):
        self.setRange(0, 100)
        self.setTextVisible(False)
        self.setFixedHeight(6)
        self.setMinimumWidth(80)
        self.setMaximumWidth(150)
        self.setStyleSheet("""
            QProgressBar {
                border: 1px solid #444;
                background: #1a1a1a;
                border-radius: 3px;
            }
            QProgressBar::chunk {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #3daee9, stop:0.5 #45a1ff, stop:1 #5882ff
                );
                border-radius: 2px;
            }
        """)
        
    def setup_connections(self):
        self.animation_timer.timeout.connect(self.smooth_level_update)
        self.animation_timer.start(30)  # ~30fps animation
        
    def update_level(self, new_level):
        if not self.isVisible():
            return
        self.current_level = max(0, min(100, new_level))
        
    def smooth_level_update(self):
        if not self.isVisible():
            return
            
        current_value = self.value()
        target_value = self.current_level
        
        if abs(current_value - target_value) < 1:
            self.setValue(target_value)
            return
            
        smoothed_value = int(
            (target_value * (1 - self.smoothing_factor)) + 
            (current_value * self.smoothing_factor)
        )
        self.setValue(smoothed_value)
        
        if target_value == 0 and current_value > 0:
            self.current_level = max(0, current_value - 2)
            
    def set_active(self, active):
        self.setVisible(active)
        if not active:
            self.setValue(0)
            self.current_level = 0
            
    def reset(self):
        self.setValue(0)
        self.current_level = 0













class GoogleLoginHelper:
    """Handles Google/Gmail login compatibility for QtWebEngine."""
    
    def __init__(self, browser_window):
        self.browser = browser_window
        self.settings = browser_window.settings_manager
        
        # Configure default Google-compatible settings
        self.required_settings = {
            "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.6778.85 Safari/537.36",
            "javascript_enabled": True,
            "drm_enabled": True,
            "auto_load_images": True,
            "ad_blocker": False  # Disable for Google domains
        }
        
        self.chromium_flags = (
            "--enable-features=Widevine,PlatformEncryptedDolbyVision "
            "--disable-features=UseChromeOSDirectVideoDecoder "
            "--no-sandbox "
            "--disable-web-security "  # For cross-origin requests
            "--allow-running-insecure-content"
        )

    def enable_google_compatibility(self):
        """Apply all Google-specific compatibility settings."""
        # 1. Update settings
        for key, value in self.required_settings.items():
            self.settings.set(key, value)
        
        # 2. Set environment flags
        os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = self.chromium_flags
        
        # 3. Configure profile
        profile = QWebEngineProfile.defaultProfile()
        profile.setHttpUserAgent(self.required_settings["user_agent"])
        profile.setPersistentCookiesPolicy(QWebEngineProfile.AllowPersistentCookies)
        
        # 4. Only inject JS if we have a current browser
        if self._has_active_browser():
            self._inject_google_workarounds()

    def _has_active_browser(self):
        """Check if we have an active browser instance."""
        try:
            return (hasattr(self.browser, 'current_browser') and 
                    self.browser.current_browser() is not None)
        except:
            return False



    def _inject_google_workarounds(self):
        """JavaScript injections to bypass Google restrictions with proper syntax"""
        if not self._has_active_browser():
            return
            
        js = """
        // First ensure the page is loaded
        if (typeof navigator !== 'undefined') {
            // Bypass browser check
            if (navigator.webdriver === undefined) {
                Object.defineProperty(navigator, 'webdriver', {
                    get: function() { return false; }
                });
            }
            
            // Spoof Chrome properties
            Object.defineProperty(navigator, 'userAgent', {
                value: '%s',
                configurable: false,
                writable: false
            });
            
            // Hide "unsupported browser" warnings
            var hideWarning = function() {
                var warning = document.querySelector('[aria-label="Unsupported browser"]') || 
                              document.getElementById('unsupported-browser');
                if (warning) {
                    warning.style.display = 'none';
                }
            };
            
            // Try immediately and also set up mutation observer
            hideWarning();
            
            if (typeof MutationObserver !== 'undefined') {
                var observer = new MutationObserver(hideWarning);
                observer.observe(document.body, { 
                    childList: true, 
                    subtree: true,
                    attributes: false,
                    characterData: false
                });
            }
        }
        """ % self.required_settings["user_agent"]
        
        try:
            self.browser.current_browser().page().runJavaScript(js)
        except Exception as e:
            print(f"JavaScript injection error: {str(e)}")

    def prepare_for_login(self, url):
        """Safer version with error handling"""
        if any(domain in url.lower() for domain in ["google.com", "accounts.google.com"]):
            try:
                self.enable_google_compatibility()
                if self._has_active_browser():
                    page = self.browser.current_browser().page()
                    profile = page.profile()
                    profile.clearHttpCache()
                    if hasattr(profile, 'cookieStore'):
                        profile.cookieStore().deleteAllCookies()
            except Exception as e:
                print(f"Google login preparation error: {str(e)}")



class CookieManager(QObject):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.settings_manager = parent.settings_manager if hasattr(parent, 'settings_manager') else None
        self.profile = QWebEngineProfile.defaultProfile()
        
    def get_cookie_settings(self):
        return self.settings_manager.get("cookies", {}) if self.settings_manager else {}
    
    def set_cookie_setting(self, key, value):
        if self.settings_manager:
            cookies = self.settings_manager.get("cookies", {})
            cookies[key] = value
            self.settings_manager.set("cookies", cookies)
            self.apply_cookie_settings()
    
    def apply_cookie_settings(self):
        settings = self.get_cookie_settings()
        
        # Set cookie policy
        if settings.get("accept_cookies", True):
            if settings.get("accept_third_party", False):
                policy = QWebEngineProfile.AllowAllCookies
            else:
                policy = QWebEngineProfile.AllowFirstPartyCookies
        else:
            policy = QWebEngineProfile.NoCookies
            
        self.profile.setPersistentCookiesPolicy(policy)
        
        # Set cookie lifetime
        if settings.get("keep_cookies_until") == "forever":
            self.profile.setPersistentStoragePath(os.path.join(CONFIG_DIR, "cookies"))
        else:
            self.profile.setPersistentStoragePath("")  # Session-only cookies







class PasswordManager(QObject):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.settings = QSettings("StormBrowser", "PasswordManager")
        self._init_encryption()
        
    def _init_encryption(self):
        """Initialize encryption using system-specific key with fallback"""
        key = self.settings.value("encryption_key")
        if not key:
            # Fallback method for older Qt versions
            try:
                # Try the modern way first (Qt 5.11+)
                machine_id = QSysInfo.machineUniqueId().toHex().data().decode('utf-8')
            except AttributeError:
                # Fallback for older Qt versions
                import uuid
                machine_id = str(uuid.getnode())
            
            system_data = (
                QGuiApplication.applicationName() + 
                QGuiApplication.organizationName() +
                str(QGuiApplication.applicationPid()) +
                machine_id
            ).encode('utf-8')
            
            key = base64.urlsafe_b64encode(hashlib.sha256(system_data).digest()[:32])
            self.settings.setValue("encryption_key", key.decode('utf-8'))
        
        # Ensure encryption_key is always bytes
        if isinstance(key, str):
            self.encryption_key = key.encode('utf-8')
        else:
            self.encryption_key = key
        
    def _xor_encrypt(self, text):
        """Simple XOR encryption using our key"""
        if isinstance(text, str):
            text = text.encode('utf-8')
        return base64.urlsafe_b64encode(
            bytes([text[i] ^ self.encryption_key[i % len(self.encryption_key)] 
                  for i in range(len(text))])
        ).decode('utf-8')
        
    def _xor_decrypt(self, encrypted_text):
        """XOR decryption using our key"""
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_text.encode('utf-8'))
        decrypted = bytes([encrypted_bytes[i] ^ self.encryption_key[i % len(self.encryption_key)] 
                         for i in range(len(encrypted_bytes))])
        return decrypted.decode('utf-8')
        
    def save_password(self, url, username, password):
        """Store encrypted credentials"""
        passwords = self._get_passwords()
        domain = QUrl(url).host()
        passwords[domain] = {
            'url': url,
            'username': self._xor_encrypt(username),
            'password': self._xor_encrypt(password),
            'timestamp': datetime.now().isoformat()
        }
        self.settings.setValue("passwords", passwords)
        
    def get_password(self, url):
        """Retrieve decrypted credentials"""
        passwords = self._get_passwords()
        domain = QUrl(url).host()
        if domain in passwords:
            return {
                'username': self._xor_decrypt(passwords[domain]['username']),
                'password': self._xor_decrypt(passwords[domain]['password'])
            }
        return None
        
    def _get_passwords(self):
        """Get all stored passwords"""
        return self.settings.value("passwords", {})




class PDFViewer:
    """Handles PDF viewing functionality for the browser."""
    
    def __init__(self, parent=None):
        self.parent = parent
        self.configure_pdf_settings()
    
    def configure_pdf_settings(self):
        """Configure WebEngine settings for PDF support."""
        settings = QWebEngineSettings.globalSettings()
        settings.setAttribute(QWebEngineSettings.PluginsEnabled, True)
        settings.setAttribute(QWebEngineSettings.PdfViewerEnabled, True)
        settings.setAttribute(QWebEngineSettings.LocalContentCanAccessRemoteUrls, True)
    
    def is_pdf_url(self, url):
        """Check if a URL points to a PDF file."""
        if isinstance(url, str):
            url = QUrl(url)
        elif not isinstance(url, QUrl):
            return False
            
        if not url.isValid():
            return False
            
        url_str = url.toString().lower()
        return (url_str.endswith('.pdf') or 
                'application/pdf' in url_str or 
                'content-type: application/pdf' in url_str)
    
    def handle_pdf_request(self, url):
        """Handle PDF viewing for the given URL."""
        if isinstance(url, str):
            url = QUrl(url)
        elif not isinstance(url, QUrl):
            return False
            
        if not self.is_pdf_url(url):
            return False
            
        # Create a dedicated PDF viewer
        pdf_viewer = QWebEngineView()
        pdf_viewer.setUrl(url)
        
        # Add to parent's tab system
        if hasattr(self.parent, 'add_new_tab'):
            self.parent.add_new_tab(
                url=url,
                title=f"PDF: {url.fileName()}",
                background=False,
                widget=pdf_viewer
            )
            return True
        return False

    def print_current_page(self):
        if browser := self.current_browser():
            printer = QPrinter(QPrinter.HighResolution)
            print_dialog = QPrintDialog(printer, self)
            if print_dialog.exec_() == QPrintDialog.Accepted:
                browser.page().print(printer, lambda success: ...)

    def print_to_pdf(self):
        if browser := self.current_browser():
            filename, _ = QFileDialog.getSaveFileName(
                self, "Save as PDF", 
                os.path.join(DOWNLOAD_DIR, f"page_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"),
                "PDF Files (*.pdf)")
            if filename:
                browser.page().printToPdf(filename)


    def handle_pdf_request(self, url):
        """Handle PDF viewing for the given URL."""
        pdf_viewer = QWebEngineView()
        pdf_viewer.setUrl(url)
        self.parent.add_new_tab(url=url, title=f"PDF: {url.fileName()}", widget=pdf_viewer)




class MultiSiteSearchWidget(QDockWidget):
    def __init__(self, parent=None):
        super().__init__("Multi-Site Search", parent)
        self.parent = parent
        self.setFeatures(QDockWidget.DockWidgetMovable | QDockWidget.DockWidgetFloatable)
        self.setAllowedAreas(Qt.RightDockWidgetArea)
        # Set preferred size
        self.setMinimumSize(300, 400)
        self.resize(350, 550)  # Increased height for new categories

        # Create a title bar widget to customize
        title_bar = QWidget()
        title_layout = QHBoxLayout(title_bar)
        title_layout.setContentsMargins(5, 2, 2, 2)
        title_layout.setSpacing(5)

        # Title label
        title_label = QLabel("Multi-Site Search")
        title_layout.addWidget(title_label)

        # Add spacer to push close button to right
        title_layout.addStretch()

        # Close button
        self.close_btn = QToolButton()
        self.close_btn.setIcon(QIcon.fromTheme("window-close"))
        self.close_btn.setStyleSheet("""
            QToolButton {
                border: none;
                background: transparent;
                padding: 2px;
            }
            QToolButton:hover {
                background: #ff4444;
                border-radius: 3px;
            }
        """)
        self.close_btn.setFixedSize(20, 20)
        self.close_btn.clicked.connect(self.close)
        title_layout.addWidget(self.close_btn)

        # Set custom title bar
        self.setTitleBarWidget(title_bar)

        # Main widget and layout
        self.search_widget = QWidget()
        self.layout = QVBoxLayout(self.search_widget)
        self.layout.setContentsMargins(10, 10, 10, 10)
        self.layout.setSpacing(8)

        # Search input field
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Enter search query...")
        self.search_input.returnPressed.connect(self.perform_search)
        self.search_input.clear()
        self.search_input.setFixedWidth(300)
        self.layout.addWidget(self.search_input)

        # Button layout
        button_layout = QHBoxLayout()
        self.layout.addLayout(button_layout)

        # Select All Categories button
        select_all_categories_btn = QPushButton("Select All")
        select_all_categories_btn.clicked.connect(self.select_all_categories)
        button_layout.addWidget(select_all_categories_btn)

        # Deselect All button
        deselect_all_btn = QPushButton("Deselect All")
        deselect_all_btn.clicked.connect(self.deselect_all_categories)
        button_layout.addWidget(deselect_all_btn)

        # Scroll area for site checkboxes
        self.scroll_area = QScrollArea()
        self.scroll_content = QWidget()
        self.scroll_layout = QVBoxLayout(self.scroll_content)
        self.scroll_layout.setAlignment(Qt.AlignTop)
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setWidget(self.scroll_content)
        self.layout.addWidget(self.scroll_area)

        # Site selection checkboxes with all categories
        self.search_categories = {
            "General": [
                "Google",
                "Bing",
                "Yahoo",
                "Brave"
            ],
            "Privacy-Focused": [
                "DuckDuckGo",
                "Startpage",
                "Qwant",
            ],
            "Academic & Knowledge": [
                "Wikipedia",
                "Google Scholar",
                "Semantic Scholar"
            ],
            "Code & Development": [
                "Stack Overflow",
                "GitHub"
            ],
            "Media & Entertainment": [
                "YouTube",
                "IMDb"
            ],
            "Shopping & E-commerce": [
                "Amazon",
                "AliExpress"
            ],
            "Videos": [
                "YouTube Videos",
                "Vimeo",
                "Dailymotion"
            ],
            "Images": [
                "Google Images",
                "Bing Images",
                "Flickr",
                "Imgur"
            ],
            "Documents": [
                "Google PDF Search",
                "SlideShare",
                "Academia.edu",
                "ResearchGate"
            ]
        }

        # Initialize site_checkboxes dictionary and category_checkboxes list
        self.site_checkboxes = {}
        self.category_checkboxes = {}

        # Create checkboxes for each site in categories
        for category, sites in self.search_categories.items():
            # Add category group box
            category_group = QGroupBox(category)
            category_group.setCheckable(True)
            category_group.setChecked(False)
            category_group.setStyleSheet("""
                QGroupBox {
                    font-weight: bold;
                    font-size: 12pt;
                    margin-top: 10px;
                    border: 1px solid gray;
                    border-radius: 5px;
                    padding-top: 15px;
                }
                QGroupBox::title {
                    subcontrol-origin: margin;
                    left: 10px;
                    padding: 0 3px;
                }
            """)

            # Connect the group checkbox to toggle all sites in category
            category_group.toggled.connect(
                lambda checked, category=category: self.on_category_group_toggled(category, checked)
            )

            # Store the category checkbox for later reference
            self.category_checkboxes[category] = category_group

            # Layout for sites in this category
            category_layout = QVBoxLayout()
            category_layout.setSpacing(5)
            category_layout.setContentsMargins(10, 15, 10, 10)

            # Add individual site checkboxes
            for site in sites:
                checkbox = QCheckBox(site)
                self.site_checkboxes[site] = checkbox

                # Connect individual checkbox to update category state
                checkbox.stateChanged.connect(
                    lambda _, cat=category: self.update_category_checkbox(cat)
                )

                category_layout.addWidget(checkbox)

            category_group.setLayout(category_layout)
            self.scroll_layout.addWidget(category_group)

        # Apply styling to all checkboxes
        for name, checkbox in self.site_checkboxes.items():
            checkbox.setChecked(False)
            checkbox.setStyleSheet("""
                QCheckBox {
                    spacing: 5px;
                    padding: 5px;
                    border: 2px solid #FFD700;
                    border-radius: 4px;
                    background-color: white;
                    margin: 2px;
                    color: black;
                }
                QCheckBox:hover {
                    background-color: #f5f5f5;
                }
                QCheckBox::indicator {
                    width: 16px;
                    height: 16px;
                }
            """)

        # Search button
        self.search_button = QPushButton("Search Selected Sites")
        self.search_button.clicked.connect(self.perform_search)
        self.layout.addWidget(self.search_button)

        self.setWidget(self.search_widget)
        self.apply_theme()

    def close(self):
        """Override close to hide instead of destroy"""
        self.hide()

    def apply_theme(self):
        """Apply current theme to the widget"""
        if hasattr(self.parent, 'settings_manager'):
            dark_mode = self.parent.settings_manager.get("dark_mode", True)
            if dark_mode:
                theme = self.parent.settings_manager.get("dark_theme", {})
                self.title_bar.setStyleSheet(f"""
                    QWidget {{
                        background-color: {theme.get("button_color", "#3a3a3a")};
                        border: none;
                    }}
                    QLabel {{
                        color: {theme.get("text_color", "#f0f0f0")};
                    }}
                """)
            else:
                self.title_bar.setStyleSheet("""
                    QWidget {
                        background-color: #f0f0f0;
                        border: none;
                    }
                    QLabel {
                        color: black;
                    }
                """)

    # ... rest of your existing methods remain unchanged ...

    def toggle_category_sites(self, sites, checked):
        """Toggle all checkboxes in a category."""
        for site in sites:
            if site in self.site_checkboxes:
                self.site_checkboxes[site].setChecked(checked)

    def update_category_checkbox(self, category):
        """Update the category checkbox state based on individual checkboxes."""
        if category not in self.category_checkboxes:
            return
            
        sites = self.search_categories.get(category, [])
        if not sites:
            return
            
        checked_count = sum(1 for site in sites 
                          if site in self.site_checkboxes 
                          and self.site_checkboxes[site].isChecked())
        
        # Block signals to prevent infinite recursion
        self.category_checkboxes[category].blockSignals(True)
        
        if checked_count == 0:
            self.category_checkboxes[category].setChecked(False)
            self.category_checkboxes[category].setProperty("partial", False)
        elif checked_count == len(sites):
            self.category_checkboxes[category].setChecked(True)
            self.category_checkboxes[category].setProperty("partial", False)
        else:
            # Show partially checked state
            self.category_checkboxes[category].setChecked(True)
            self.category_checkboxes[category].setProperty("partial", True)
        
        self.category_checkboxes[category].style().unpolish(self.category_checkboxes[category])
        self.category_checkboxes[category].style().polish(self.category_checkboxes[category])
        self.category_checkboxes[category].blockSignals(False)

    def select_all_categories(self):
        """Select all site checkboxes across all categories."""
        for checkbox in self.site_checkboxes.values():
            checkbox.setChecked(True)

    def deselect_all_categories(self):
        """Deselect all site checkboxes across all categories."""
        for checkbox in self.site_checkboxes.values():
            checkbox.setChecked(False)


    def perform_search(self):
        query = self.search_input.text().strip()
        if not query:
            self.parent.status_bar.showMessage("Please enter a search query.", 3000)
            return

        encoded_query = quote_plus(query)
        search_urls = {
            # General search
            "Google": f"https://www.google.com/search?q={encoded_query}",
            "Bing": f"https://www.bing.com/search?q={encoded_query}",
            "Yahoo": f"https://search.yahoo.com/search?p={encoded_query}",
            "Brave": f"https://search.brave.com/search?q={encoded_query}",
            
            # Privacy-focused
            "DuckDuckGo": f"https://duckduckgo.com/?q={encoded_query}",
            "Startpage": f"https://www.startpage.com/do/search?query={encoded_query}",
            "Qwant": f"https://www.qwant.com/?q={encoded_query}",
            
            # Academic & Knowledge
            "Wikipedia": f"https://en.wikipedia.org/wiki/Special:Search?search={encoded_query}",
            "Google Scholar": f"https://scholar.google.com/scholar?q={encoded_query}",
            "Semantic Scholar": f"https://www.semanticscholar.org/search?q={encoded_query}",
            
            # Code & Development
            "Stack Overflow": f"https://stackoverflow.com/search?q={encoded_query}",
            "GitHub": f"https://github.com/search?q={encoded_query}",
            
            # Media & Entertainment
            "YouTube": f"https://www.youtube.com/results?search_query={encoded_query}",
            "IMDb": f"https://www.imdb.com/find?q={encoded_query}",
            
            # Shopping
            "Amazon": f"https://www.amazon.com/s?k={encoded_query}",
            "AliExpress": f"https://www.aliexpress.com/wholesale?SearchText={encoded_query}",
            
            # Videos
            "YouTube Videos": f"https://www.youtube.com/results?search_query={encoded_query}",
            "Vimeo": f"https://vimeo.com/search?q={encoded_query}",
            "Dailymotion": f"https://www.dailymotion.com/search/{encoded_query}",
            
            # Images
            "Google Images": f"https://www.google.com/search?tbm=isch&q={encoded_query}",
            "Bing Images": f"https://www.bing.com/images/search?q={encoded_query}",
            "Flickr": f"https://www.flickr.com/search/?text={encoded_query}",
            "Imgur": f"https://imgur.com/search?q={encoded_query}",
            
            # Documents
            "Google PDF Search": f"https://www.google.com/search?q=filetype:pdf+{encoded_query}",
            "SlideShare": f"https://www.slideshare.net/search/slideshow?searchfrom=header&q={encoded_query}",
            "Academia.edu": f"https://www.academia.edu/search?q={encoded_query}",
            "ResearchGate": f"https://www.researchgate.net/search?q={encoded_query}"
        }

        sites_searched = 0
        for site, url in search_urls.items():
            if self.site_checkboxes.get(site, None) and self.site_checkboxes[site].isChecked():
                self.parent.add_new_tab(url, title=f"{site} Search", background=True)
                sites_searched += 1

        if sites_searched > 0:
            self.parent.status_bar.showMessage(f"Searching on {sites_searched} sites...", 3000)
            self.search_input.clear()
        else:
            self.parent.status_bar.showMessage("Please select at least one site to search.", 3000)

    def apply_theme(self):
        if self.parent.settings_manager.get("dark_mode", True):
            base_color = self.parent.settings_manager.get("dark_theme", {}).get("base_color", "#2d2d2d")
            text_color = self.parent.settings_manager.get("dark_theme", {}).get("text_color", "#f0f0f0")
            button_color = self.parent.settings_manager.get("dark_theme", {}).get("button_color", "#3a3a3a")
            highlight_color = self.parent.settings_manager.get("dark_theme", {}).get("highlight_color", "#3daee9")

            self.setStyleSheet(f"""
                QDockWidget {{
                    background-color: {base_color};
                    color: {text_color};
                    border: 1px solid {button_color};
                }}
                QWidget {{
                    background-color: {base_color};
                    color: {text_color};
                }}
                QLineEdit {{
                    background-color: {button_color};
                    color: {text_color};
                    border: 1px solid {highlight_color};
                    padding: 5px;
                    border-radius: 3px;
                }}
                QPushButton {{
                    background-color: {button_color};
                    color: {text_color};
                    border: 1px solid {highlight_color};
                    padding: 5px;
                    border-radius: 3px;
                }}
                QPushButton:hover {{
                    background-color: {highlight_color};
                    color: black;
                }}
                QScrollArea {{
                    border: 1px solid {button_color};
                    background-color: {base_color};
                }}
                QGroupBox {{
                    color: {text_color};
                    border: 1px solid {highlight_color};
                }}
            """)
        else:
            self.setStyleSheet(f"""
                QDockWidget {{
                    background-color: #f0f0f0;
                    border: 1px solid #c0c0c0;
                }}
                QWidget {{
                    background-color: #f0f0f0;
                }}
                QLineEdit {{
                    background-color: white;
                    border: 1px solid #c0c0c0;
                    padding: 5px;
                    border-radius: 3px;
                }}
                QPushButton {{
                    background-color: #e0e0e0;
                    border: 1px solid #c0c0c0;
                    padding: 5px;
                    border-radius: 3px;
                }}
                QPushButton:hover {{
                    background-color: #3daee9;
                }}
                QScrollArea {{
                    border: 1px solid #c0c0c0;
                    background-color: #f0f0f0;
                }}
                QGroupBox {{
                    color: black;
                    border: 1px solid gray;
                }}
            """)

    def on_category_group_toggled(self, category, checked):
        """Toggle all site checkboxes in a category only if the group box was toggled directly."""
        # Prevent recursive toggling when individual checkboxes update the group box state
        if category not in self.search_categories:
            return

        # Do not force re-checking if already partially selected
        if self.category_checkboxes[category].property("partial") is True:
            return  # Ignore toggle triggered by internal state update

        for site in self.search_categories[category]:
            checkbox = self.site_checkboxes.get(site)
            if checkbox:
                checkbox.setChecked(checked)



# ====================== BOOKMARK IMPORT ======================
class BookmarkImporter:
    @staticmethod
    def get_browser_bookmarks(browser):
        paths = {
            "chrome": {
                "linux": "~/.config/google-chrome/Default/Bookmarks",
                "windows": os.path.expanduser("~/AppData/Local/Google/Chrome/User Data/Default/Bookmarks"),
                "darwin": "~/Library/Application Support/Google/Chrome/Default/Bookmarks"
            },
            "firefox": {
                "linux": "~/.mozilla/firefox/*.default-release/places.sqlite",
                "windows": os.path.expanduser("~/AppData/Roaming/Mozilla/Firefox/Profiles/*.default-release/places.sqlite"),
                "darwin": "~/Library/Application Support/Firefox/Profiles/*.default-release/places.sqlite"
            }
        }
        
        system = platform.system().lower()
        if browser == "chrome":
            path = os.path.expanduser(paths["chrome"].get(system, ""))
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return BookmarkImporter._parse_chrome_bookmarks(data)
        
        elif browser == "firefox":
            import glob
            path_pattern = os.path.expanduser(paths["firefox"].get(system, ""))
            matches = glob.glob(path_pattern)
            if matches:
                return BookmarkImporter._parse_firefox_bookmarks(matches[0])
        
        return []

    @staticmethod
    def _parse_chrome_bookmarks(data, folder="Imported Chrome"):
        bookmarks = []
        if "roots" in data:
            for root in data["roots"].values():
                if "children" in root:
                    for child in root["children"]:
                        if child["type"] == "url":
                            bookmarks.append({
                                "url": child["url"],
                                "title": child["name"],
                                "folder": folder,
                                "date": datetime.now().isoformat()
                            })
        return bookmarks

    @staticmethod
    def _parse_firefox_bookmarks(db_path):
        bookmarks = []
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT moz_bookmarks.title, moz_places.url 
                FROM moz_bookmarks 
                JOIN moz_places ON moz_bookmarks.fk = moz_places.id 
                WHERE moz_bookmarks.type = 1
            """)
            for title, url in cursor.fetchall():
                bookmarks.append({
                    "url": url,
                    "title": title or url,
                    "folder": "Imported Firefox",
                    "date": datetime.now().isoformat()
                })
            conn.close()
        except sqlite3.Error:
            pass
        return bookmarks



import os
import json

class ConfigManager:
    """
    A centralized manager for handling JSON configuration files.
    Ensures files exist, initializes them with default content if missing,
    and provides safe loading and saving mechanisms.
    """
    def __init__(self, config_dir="~/.config/storm_browser"):
        self.config_dir = os.path.expanduser(config_dir)
        self.ensure_config_dir()

        # Define default content for required files
        self.default_files = {
            "bookmarks.json": {"folders": {"Main": []}},
            "history.json": {"entries": []},
            "settings.json": {
                "home_page": "https://www.google.com",
                "dark_mode": False,
                "shortcuts": {
                    "new_tab": "Ctrl+T",
                    "close_tab": "Ctrl+W",
                    "bookmark_search": "Ctrl+K",
                    "calendar": "Ctrl+Shift+C"
                }
            },
            "events.json": {},
            "notes.json": {}
        }

    def ensure_config_dir(self):
        """Ensure the configuration directory exists."""
        if not os.path.exists(self.config_dir):
            try:
                os.makedirs(self.config_dir)
            except Exception as e:
                print(f"Error creating config directory: {e}")

    def ensure_files_exist(self):
        """Ensure all required files exist and are initialized."""
        for file_name, default_content in self.default_files.items():
            file_path = os.path.join(self.config_dir, file_name)
            if not os.path.exists(file_path):
                print(f"Creating missing file: {file_path}")
                self.save_file(file_path, default_content)

    def load_file(self, file_name, default=None):
        """
        Load a JSON file safely.
        :param file_name: Name of the file (e.g., 'settings.json').
        :param default: Default value to return if the file doesn't exist or is invalid.
        :return: Loaded JSON data or default value.
        """
        file_path = os.path.join(self.config_dir, file_name)
        if default is None:
            default = {}
        try:
            if os.path.exists(file_path):
                with open(file_path, "r", encoding="utf-8") as f:
                    return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Error loading file {file_path}: {e}")
        return default

    def save_file(self, file_name, data):
        """
        Save data to a JSON file.
        :param file_name: Name of the file (e.g., 'settings.json').
        :param data: Data to save.
        """
        file_path = os.path.join(self.config_dir, file_name)
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
        except Exception as e:
            print(f"Error saving file {file_path}: {e}")

    def validate_and_repair(self, file_name, default_content):
        """
        Validate and repair a JSON file by ensuring all required keys exist.
        :param file_name: Name of the file (e.g., 'settings.json').
        :param default_content: Default structure to validate against.
        """
        file_path = os.path.join(self.config_dir, file_name)
        data = self.load_file(file_name, default_content)
        needs_save = False

        # Recursive validation
        def validate(current, default):
            nonlocal needs_save
            for key, default_value in default.items():
                if key not in current:
                    current[key] = default_value
                    needs_save = True
                elif isinstance(default_value, dict) and isinstance(current[key], dict):
                    validate(current[key], default_value)

        validate(data, default_content)
        if needs_save:
            print(f"Repairing file: {file_path}")
            self.save_file(file_name, data)

    def initialize(self):
        """Initialize all required files and validate their content."""
        self.ensure_files_exist()
        for file_name, default_content in self.default_files.items():
            self.validate_and_repair(file_name, default_content)






# ====================== DOWNLOAD MANAGER ======================
# Define global paths
import os
import json
import time
from PyQt5.QtCore import pyqtSignal, QObject
from PyQt5.QtWebEngineWidgets import QWebEngineDownloadItem

DOWNLOAD_DIR = os.path.expanduser("~/Downloads")
COMPLETED_DOWNLOADS_FILE = os.path.join(DOWNLOAD_DIR, "completed_downloads.json")


def ensure_config_dir():
    """Ensure the download directory exists."""
    if not os.path.exists(DOWNLOAD_DIR):
        os.makedirs(DOWNLOAD_DIR)


def format_size(bytes_received):
    """Format bytes into human-readable size (e.g., 1.2 MB)."""
    for unit in ["B", "KB", "MB", "GB"]:
        if bytes_received < 1024:
            return f"{bytes_received:.1f} {unit}"
        bytes_received /= 1024
    return f"{bytes_received:.1f} TB"


class DownloadManager(QObject):
    # Signals to notify UI about changes
    download_progress = pyqtSignal(str, int, int, str, str)  # filename, received, total, speed, eta
    download_finished = pyqtSignal(str, bool, str)          # path, success, filename
    download_started = pyqtSignal(int, str)                 # download_id, filename
    download_list_updated = pyqtSignal()                    # no arguments
    download_paused = pyqtSignal(int)                       # download_id
    download_resumed = pyqtSignal(int)                      # download_id

    def __init__(self, parent=None):
        super().__init__(parent)
        self.active_downloads = {}
        self.paused_downloads = {}
        self.completed_downloads = []

        # Load existing downloads
        self.load_completed_downloads()
        # DO NOT reassign signals here — they are already defined at the class level

    def handle_download(self, download_item):
        """Handle a new download request from QWebEngineView."""
        filename = download_item.suggestedFileName() or f"download_{int(time.time())}"
        path = self._get_unique_path(filename)
        
        # Check if this path matches a paused download to resume it
        for download_id, paused_download in self.paused_downloads.items():
            if paused_download['path'] == path:
                self._resume_download(download_id, download_item)
                return
                
        # Otherwise proceed with new download
        download_item.setPath(path)
        download_id = int(time.time() * 1000)
        
        # Prevent duplicate IDs
        while download_id in self.active_downloads:
            download_id += 1

        self.active_downloads[download_id] = {
            "item": download_item,
            "filename": filename,
            "path": path,
            "start_time": time.time(),
            "last_update": time.time(),
            "last_bytes": 0,
            "speed": 0,
            "received": 0,
            "total": 0,
            "paused": False
        }

        self.download_started.emit(filename, "0 B")
        download_item.accept()

        # Connect signals only once per download item
        download_item.downloadProgress.connect(
            lambda r, t, id=download_id: self._on_download_progress(id, r, t)
        )
        download_item.finished.connect(
            lambda id=download_id: self._on_download_finished(id)
        )

    def _resume_download(self, download_id, download_item):
        """Resume a paused download."""
        paused_download = self.paused_downloads.pop(download_id)
        
        # Set up the download item with the paused download's path
        download_item.setPath(paused_download['path'])
        
        # Restore the download state
        self.active_downloads[download_id] = {
            "item": download_item,
            "filename": paused_download['filename'],
            "path": paused_download['path'],
            "start_time": paused_download['start_time'],
            "last_update": time.time(),
            "last_bytes": paused_download['received'],
            "speed": 0,
            "received": paused_download['received'],
            "total": paused_download['total'],
            "paused": False
        }
        
        # Accept the download to resume it
        download_item.accept()
        
        # Reconnect signals
        download_item.downloadProgress.connect(
            lambda r, t, id=download_id: self._on_download_progress(id, r, t)
        )
        download_item.finished.connect(
            lambda id=download_id: self._on_download_finished(id)
        )
        
        self.download_resumed.emit(paused_download['filename'])
        self.download_list_updated.emit()



    def resume_download(self, download_id):
        if download_id in self.paused_downloads:
            download = self.paused_downloads.pop(download_id)
            self.active_downloads[download_id] = download
            self.download_resumed.emit(download_id)
            self.download_list_updated.emit()
            return True
        return False

    def is_paused(self, download_id):
        """Check if a download is paused."""
        return download_id in self.paused_downloads

    def get_paused_downloads(self):
        """Return all paused download items."""
        return self.paused_downloads.values()

    def clear_paused_downloads(self):
        """Clear all paused downloads."""
        self.paused_downloads.clear()
        self.download_list_updated.emit()

    def _get_unique_path(self, filename):
        """Generate a unique path to avoid overwriting existing files."""
        base, ext = os.path.splitext(filename)
        counter = 1
        while os.path.exists(os.path.join(DOWNLOAD_DIR, filename)):
            filename = f"{base}({counter}){ext}"
            counter += 1
        return os.path.join(DOWNLOAD_DIR, filename)

    def _on_download_progress(self, download_id, received, total):
        """Handle download progress updates."""
        if download_id not in self.active_downloads:
            return

        download = self.active_downloads[download_id]
        now = time.time()
        time_elapsed = now - download["last_update"]

        if time_elapsed > 0:
            bytes_diff = received - download["last_bytes"]
            download["speed"] = bytes_diff / time_elapsed  # bytes per second

        download["last_update"] = now
        download["last_bytes"] = received
        download["received"] = received
        download["total"] = total

        percent = (received / total * 100) if total > 0 else 0
        speed_str = f"{format_size(download['speed'])}/s"
        eta_seconds = max(0, int((total - received) / download["speed"])) if download["speed"] > 0 else 0
        eta_str = format_time(eta_seconds) if eta_seconds > 0 else "Calculating..."

        self.download_progress.emit(
            download["filename"], received, total, speed_str, eta_str
        )

    def _on_download_finished(self, download_id):
        if download_id not in self.active_downloads:
            return

        download = self.active_downloads.pop(download_id)
        
        # Determine if the download was successful
        if hasattr(download["item"], "state"):
            success = download["item"].state() == QWebEngineDownloadItem.DownloadCompleted
        else:
            success = True  # Assume success if state is not available

        # Add to completed downloads list only if not paused
        if not download.get('paused', False):
            self.completed_downloads.append({
                "filename": download["filename"],
                "path": download["path"],
                "timestamp": download["start_time"],
                "received": download.get("received", 0),
                "total": download.get("total", 0),
                "success": success
            })

            # Emit signal for UI update
            self.download_finished.emit(download["path"], success, download["filename"])

            # Save completed downloads to disk
            self.save_completed_downloads()

        # Notify UI that the list has changed
        self.download_list_updated.emit()

    def save_completed_downloads(self):
        """Save completed downloads to a JSON file."""
        try:
            with open(COMPLETED_DOWNLOADS_FILE, "w", encoding="utf-8") as f:
                json.dump(self.completed_downloads, f, indent=4)
        except Exception as e:
            print(f"Error saving completed downloads: {str(e)}")

    def load_completed_downloads(self):
        """Load completed downloads from disk."""
        if os.path.exists(COMPLETED_DOWNLOADS_FILE):
            try:
                with open(COMPLETED_DOWNLOADS_FILE, "r", encoding="utf-8") as f:
                    self.completed_downloads = json.load(f)
            except Exception as e:
                print(f"Error loading completed downloads: {str(e)}")
                self.completed_downloads = []
        else:
            self.completed_downloads = []

    def get_active_downloads(self):
        """Return active download items for UI display."""
        return self.active_downloads.values()

    def get_completed_downloads(self):
        """Return completed download items for UI display."""
        return self.completed_downloads

    def clear_all_downloads(self):
        """Clear all active, paused and completed downloads from memory."""
        self.active_downloads.clear()
        self.paused_downloads.clear()
        self.completed_downloads.clear()
        self.save_completed_downloads()
        self.download_list_updated.emit()

    def clear_completed_downloads(self):
        """Clear completed downloads list and delete the file from disk."""
        # Clear in-memory list
        self.completed_downloads = []
        
        # Delete the file if it exists
        if os.path.exists(COMPLETED_DOWNLOADS_FILE):
            try:
                os.remove(COMPLETED_DOWNLOADS_FILE)
                print(f"[DEBUG] Deleted {COMPLETED_DOWNLOADS_FILE}")
            except Exception as e:
                print(f"[ERROR] Could not delete download history file: {e}")
        
        # Notify UI that the list has changed
        self.download_list_updated.emit()

    def cancel_download(self, download_id):
        """Cancel a specific active download by ID."""
        if download_id in self.active_downloads:
            download = self.active_downloads[download_id]
            if 'item' in download:
                download['item'].cancel()
            del self.active_downloads[download_id]
            self.download_list_updated.emit()

    def remove_completed_download(self, index):
        """Remove a specific completed download by index."""
        if 0 <= index < len(self.completed_downloads):
            del self.completed_downloads[index]
            self.save_completed_downloads()
            self.download_list_updated.emit()


    # In your DownloadManager class, add these methods:
    def pause_download(self, download_id: int):
        if download_id in self.active_downloads:
            download = self.active_downloads.pop(download_id)
            self.paused_downloads[download_id] = download
            self.download_paused.emit(download_id)  # Now emits an int
            self.download_list_updated.emit()
            return True
        return False

    def resume_download(self, download_id: int):
        if download_id in self.paused_downloads:
            download = self.paused_downloads.pop(download_id)
            self.active_downloads[download_id] = download
            self.download_resumed.emit(download_id)
            self.download_list_updated.emit()
            return True
        return False

            
# ====================== BOOKMARK MANAGER ======================
class BookmarkManager(QObject):
    def __init__(self, parent=None):
        super().__init__(parent)
        ensure_config_dir()
        self.bookmarks = load_json_file(BOOKMARKS_FILE, {"folders": {"Main": []}})

    def add_bookmark(self, url, title, folder="Main", description=""):
        """
        Add a new bookmark to the specified folder.
        
        Args:
            url (str): URL of the bookmark.
            title (str): Title or name of the bookmark.
            folder (str): Folder name to categorize the bookmark (default: "Main").
            description (str): Optional description for the bookmark.
        """
        # Create the folder if it doesn't exist
        if folder not in self.bookmarks["folders"]:
            self.bookmarks["folders"][folder] = []

        # Append the new bookmark with a timestamp and optional description
        self.bookmarks["folders"][folder].append({
            "url": url,
            "title": title,
            "description": description,
            "date": datetime.now().isoformat()
        })

        # Save bookmarks to file
        save_json_file(BOOKMARKS_FILE, self.bookmarks)

    def remove_bookmark(self, url, folder="Main"):
        if folder in self.bookmarks["folders"]:
            self.bookmarks["folders"][folder] = [
                b for b in self.bookmarks["folders"][folder] 
                if b["url"] != url
            ]
            save_json_file(BOOKMARKS_FILE, self.bookmarks)

    def get_bookmarks(self, folder="Main"):
        return self.bookmarks["folders"].get(folder, [])

    def get_all_bookmarks(self):
        """Get all bookmarks across all folders."""
        all_bookmarks = []
        for folder, bookmarks in self.bookmarks["folders"].items():
            for bookmark in bookmarks:
                bookmark_copy = bookmark.copy()
                bookmark_copy["folder"] = folder
                all_bookmarks.append(bookmark_copy)
        return all_bookmarks

    def import_browser_bookmarks(self, browser):
        imported = BookmarkImporter.get_browser_bookmarks(browser)
        for bookmark in imported:
            self.add_bookmark(bookmark["url"], bookmark["title"], bookmark.get("folder", "Imported"))
        return len(imported)

# ====================== HISTORY MANAGER ======================
class HistoryManager(QObject):
    history_updated = pyqtSignal(list)  # Signal emits filtered history

    def __init__(self, parent=None):
        super().__init__(parent)
        ensure_config_dir()
        self.history = load_json_file(HISTORY_FILE, {"entries": []})
        self.current_filter = ""
        self._filtered_history = []

    def add_history_entry(self, url, title, browser=None):
        """Add a new history entry with optional browser context for incognito checks"""
        should_add = True
        if browser and hasattr(browser, 'parentWidget'):
            try:
                tab_index = browser.parentWidget().parent().indexOf(browser.parentWidget())
                tab_data = browser.parentWidget().parent().tabData(tab_index)
                should_add = not tab_data.get("is_incognito", False)
            except Exception:
                should_add = True  # Fallback if context resolution fails

        if should_add:
            self.history["entries"].append({
                "url": url,
                "title": title,
                "date": datetime.now().isoformat(),
                "visit_count": 1
            })
            save_json_file(HISTORY_FILE, self.history)
            self.update_filtered_history()

    def clear_history(self):
        self.history["entries"] = []
        save_json_file(HISTORY_FILE, self.history)
        self.update_filtered_history()

    def set_search_filter(self, search_text):
        """Update the search filter and emit matching results"""
        self.current_filter = search_text.lower()
        self.update_filtered_history()

    def update_filtered_history(self):
        """Apply the filter to the full history and emit the result"""
        if not self.current_filter:
            self._filtered_history = sorted(
                self.history["entries"],
                key=lambda x: x["date"],
                reverse=True
            )
        else:
            self._filtered_history = [
                entry for entry in self.history["entries"]
                if self.current_filter in entry["title"].lower() or
                   self.current_filter in entry["url"].lower()
            ]
            self._filtered_history.sort(key=lambda x: x["date"], reverse=True)

        self.history_updated.emit(self._filtered_history[:100])

    def get_history(self, limit=100, search_query=None):
        """Original get_history method for backward compatibility"""
        if search_query:
            self.set_search_filter(search_query)
            return self._filtered_history[:limit]
        return sorted(self.history["entries"], key=lambda x: x["date"], reverse=True)[:limit]

    def get_filtered_history(self, limit=100):
        """Get the currently filtered history"""
        return self._filtered_history[:limit]



# ====================== SETTINGS MANAGER ======================
class SettingsManager(QObject):
    accent_color_changed = pyqtSignal(str)  # Signal emitted when accent color changes
    theme_mode_changed = pyqtSignal(str)    # Signal emitted when theme mode changes
    
    def __init__(self, parent=None):
        super().__init__(parent)
        ensure_config_dir()
        
        # Default settings with dark mode enabled
        self.default_settings = {
            "home_page": DEFAULT_HOME_PAGE,
            "search_engine": "https://www.google.com/search?q={}",
            "download_dir": DOWNLOAD_DIR,
            "dark_mode": True,
            "theme": {
                "accent_color": "#3daee9",
                "available_colors": [
                    {"name": "Blue", "color": "#3daee9"},
                    {"name": "Red", "color": "#e74c3c"},
                    {"name": "Green", "color": "#2ecc71"},
                    {"name": "Purple", "color": "#9b59b6"},
                    {"name": "Orange", "color": "#e67e22"},
                    {"name": "Pink", "color": "#e91e63"},
                    {"name": "Teal", "color": "#1abc9c"},
                    {"name": "Yellow", "color": "#f1c40f"}
                ],
                "presets": {
                    "default_dark": {
                        "base_color": "#2d2d2d",
                        "highlight_color": "#3daee9",
                        "text_color": "#f0f0f0",
                        "button_color": "#3a3a3a",
                        "window_color": "#252525",
                        "disabled_color": "#404040",
                        "tooltip_color": "#353535"
                    },
                    "firefox_dark": {
                        "base_color": "#2b1a1a",
                        "highlight_color": "#ff4545",
                        "text_color": "#fbfbfe",
                        "button_color": "#4d2a2a",
                        "window_color": "#1a0a0a",
                        "disabled_color": "#3a2525",
                        "tooltip_color": "#3a2525",
                        "tab_selected": "#1a0a0a",
                        "tab_unselected": "#2b1a1a"
                    },
                    "deep_ocean": {
                        "base_color": "#0f1a26",
                        "highlight_color": "#4fc1e9",
                        "text_color": "#f5f7fa",
                        "button_color": "#1a2635",
                        "window_color": "#0a121f",
                        "disabled_color": "#1a2a3a",
                        "tooltip_color": "#1a2a3a"
                    }
                }
            },
            "dark_theme": {
                "base_color": "#2d2d2d",
                "highlight_color": "#3daee9",
                "text_color": "#f0f0f0",
                "button_color": "#3a3a3a",
                "disabled_color": "#404040",
                "window_color": "#252525",
                "tooltip_color": "#353535"
            },
            "ad_blocker": True,
            "javascript_enabled": True,
            "auto_load_images": True,
            "drm_enabled": DRM_ENABLED,
            "hls_enabled": HLS_ENABLED,
            "user_agent": USER_AGENT,
            "cookies": {
                "accept_cookies": True,
                "accept_third_party": False,
                "keep_cookies_until": "session_end",
                "blocked_sites": [],
                "whitelisted_sites": []
            },
            "shortcuts": {
                "new_tab": "Ctrl+T",
                "close_tab": "Ctrl+W",
                "next_tab": "Ctrl+Tab",
                "prev_tab": "Ctrl+Shift+Tab",
                "reload": "F5",
                "bookmarks": "Ctrl+B",
                "history": "Ctrl+H",
                "downloads": "Ctrl+J",
                "dev_tools": "F12",
                "multi_site_search": "Ctrl+K",
                "bookmark_search": "Ctrl+Shift+K",
                "calendar": "Ctrl+Shift+C",
                "cookie_manager": "Ctrl+Shift+M",
                "incognito_tab": "Ctrl+Shift+N",
                "theme_selector": "Ctrl+Shift+T"
            }
        }
        
        # Load settings
        self.settings = load_json_file(SETTINGS_FILE, self.default_settings)
        self.validate_settings()

    def validate_settings(self):
        """Ensure all settings exist and are valid."""
        needs_save = False
        
        # Check top-level settings
        for key, default_value in self.default_settings.items():
            if key not in self.settings:
                self.settings[key] = default_value
                needs_save = True
                
        # Check dark theme colors
        if "dark_theme" not in self.settings:
            self.settings["dark_theme"] = self.default_settings["dark_theme"]
            needs_save = True
        else:
            for color_key, default_value in self.default_settings["dark_theme"].items():
                if color_key not in self.settings["dark_theme"]:
                    self.settings["dark_theme"][color_key] = default_value
                    needs_save = True
        
        # Check cookie settings
        if "cookies" not in self.settings:
            self.settings["cookies"] = self.default_settings["cookies"]
            needs_save = True
        else:
            for cookie_key, default_value in self.default_settings["cookies"].items():
                if cookie_key not in self.settings["cookies"]:
                    self.settings["cookies"][cookie_key] = default_value
                    needs_save = True
        
        # Check shortcuts
        if "shortcuts" not in self.settings:
            self.settings["shortcuts"] = self.default_settings["shortcuts"]
            needs_save = True
        else:
            for shortcut, default_value in self.default_settings["shortcuts"].items():
                if shortcut not in self.settings["shortcuts"]:
                    self.settings["shortcuts"][shortcut] = default_value
                    needs_save = True
        
        if needs_save:
            self.save_settings()

    def save_settings(self):
        """Save current settings to file."""
        save_json_file(SETTINGS_FILE, self.settings)

    def get(self, key, default=None):
        """Get a setting value."""
        return self.settings.get(key, default)

    def set(self, key, value):
        """Set a setting value and save to disk."""
        self.settings[key] = value
        self.save_settings()

    def get_shortcut(self, action):
        """Get keyboard shortcut for an action."""
        try:
            return self.settings["shortcuts"].get(action, self.default_settings["shortcuts"].get(action, ""))
        except KeyError:
            return self.default_settings["shortcuts"].get(action, "")

    def apply_theme_preset(self, preset_name):
        """Apply a predefined theme preset."""
        presets = self.settings.get("theme", {}).get("presets", {})
        if preset_name in presets:
            preset = presets[preset_name]
            
            # Update dark theme settings
            dark_theme = self.settings.setdefault("dark_theme", {})
            for key, value in preset.items():
                dark_theme[key] = value
            
            # Update accent color if specified in preset
            if "highlight_color" in preset:
                self.settings["theme"]["accent_color"] = preset["highlight_color"]
                self.accent_color_changed.emit(preset["highlight_color"])
            
            self.save_settings()
            self.apply_theme(QApplication.instance())
            return True
        return False

    def get_theme_presets(self):
        """Return list of available theme presets."""
        return list(self.settings.get("theme", {}).get("presets", {}).keys())

    def apply_dark_mode(self, app):
        """Apply dark theme to the application."""
        if not self.settings.get("dark_mode", True):
            app.setPalette(QStyleFactory.create("Fusion").standardPalette())
            app.setStyleSheet("")
            return

        # Use Fusion style as base
        app.setStyle("Fusion")
        
        # Get theme colors
        theme = self.settings.get("dark_theme", self.default_settings["dark_theme"])
        accent_color = self.settings.get("theme", {}).get("accent_color", "#3daee9")
        
        # Create and set dark palette
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(theme["window_color"]))
        palette.setColor(QPalette.WindowText, QColor(theme["text_color"]))
        palette.setColor(QPalette.Base, QColor(theme["base_color"]))
        palette.setColor(QPalette.AlternateBase, QColor(theme["base_color"]))
        palette.setColor(QPalette.ToolTipBase, QColor(theme["tooltip_color"]))
        palette.setColor(QPalette.ToolTipText, QColor(theme["text_color"]))
        palette.setColor(QPalette.Text, QColor(theme["text_color"]))
        palette.setColor(QPalette.Button, QColor(theme["button_color"]))
        palette.setColor(QPalette.ButtonText, QColor(theme["text_color"]))
        palette.setColor(QPalette.BrightText, Qt.red)
        palette.setColor(QPalette.Link, QColor(accent_color))
        palette.setColor(QPalette.Highlight, QColor(accent_color))
        palette.setColor(QPalette.HighlightedText, Qt.black)
        palette.setColor(QPalette.Disabled, QPalette.Text, QColor(theme["disabled_color"]))
        palette.setColor(QPalette.Disabled, QPalette.ButtonText, QColor(theme["disabled_color"]))
        
        app.setPalette(palette)
        
        # Apply stylesheet
        app.setStyleSheet(f"""
            QWidget {{
                background-color: {theme["base_color"]};
                color: {theme["text_color"]};
            }}
            QPushButton, QToolButton {{
                background-color: {theme["button_color"]};
                border: 1px solid #444;
                padding: 5px;
                border-radius: 3px;
            }}
            QPushButton:hover, QToolButton:hover {{
                background-color: #{self._adjust_lightness(theme["button_color"], 10)};
            }}
            QTabBar::tab {{
                background: {theme["button_color"]};
                color: {theme["text_color"]};
                padding: 8px;
                border: 1px solid #444;
            }}
            QLineEdit, QTextEdit {{
                background-color: {theme["window_color"]};
                border: 1px solid #444;
            }}
            QMenu {{
                background-color: {theme["window_color"]};
            }}
        """)

    def apply_theme(self, app):
        """Apply current theme settings"""
        accent = self.get("theme", {}).get("accent_color", "#3daee9")
        dark_mode = self.get("dark_mode", True)
        
        # Generate stylesheet using current accent color
        stylesheet = self.generate_stylesheet(accent, dark_mode)
        app.setStyleSheet(stylesheet)

    def apply_light_mode(self, app):
        """Apply light theme palette."""
        palette = QPalette()
        accent_color = self.get("theme", {}).get("accent_color", "#3daee9")
        
        # Basic colors
        palette.setColor(QPalette.Window, QColor(240, 240, 240))
        palette.setColor(QPalette.WindowText, Qt.black)
        palette.setColor(QPalette.Base, QColor(255, 255, 255))
        palette.setColor(QPalette.AlternateBase, QColor(240, 240, 240))
        
        # Text colors
        palette.setColor(QPalette.Text, Qt.black)
        palette.setColor(QPalette.ButtonText, Qt.black)
        
        # Button colors
        palette.setColor(QPalette.Button, QColor(240, 240, 240))
        
        # Highlight colors
        palette.setColor(QPalette.Highlight, QColor(accent_color))
        palette.setColor(QPalette.HighlightedText, Qt.white)
        
        app.setPalette(palette)

    def apply_accent_color(self, color_hex):
        """Apply the selected accent color to the theme."""
        if "theme" not in self.settings:
            self.settings["theme"] = {}
        
        self.settings["theme"]["accent_color"] = color_hex
        
        # Update the dark theme highlight color
        if "dark_theme" in self.settings:
            self.settings["dark_theme"]["highlight_color"] = color_hex
        
        self.save_settings()
        
        # Emit signal to update all UI components
        self.accent_color_changed.emit(color_hex)

    def get_available_accent_colors(self):
        """Return list of available accent colors."""
        return self.settings.get("theme", {}).get("available_colors", 
            self.default_settings["theme"]["available_colors"])

    def _adjust_lightness(self, hex_color, percent):
        """Adjust color lightness (helper for styles)."""
        try:
            hex_color = hex_color.lstrip('#')
            r, g, b = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
            
            # Convert to HSL
            r /= 255.0
            g /= 255.0
            b /= 255.0
            max_val = max(r, g, b)
            min_val = min(r, g, b)
            l = (max_val + min_val) / 2.0
            
            # Adjust lightness
            l = min(1.0, max(0.0, l + (percent / 100.0)))
            
            # Convert back to RGB
            if l <= 0:
                return "000000"
            if l >= 1:
                return "ffffff"
                
            if max_val == min_val:
                r = g = b = l
            else:
                def hue2rgb(p, q, t):
                    if t < 0: t += 1
                    if t > 1: t -= 1
                    if t < 1/6: return p + (q - p) * 6 * t
                    if t < 1/2: return q
                    if t < 2/3: return p + (q - p) * (2/3 - t) * 6
                    return p
                
                if l < 0.5:
                    q = l * (1 + percent/100)
                else:
                    q = l + percent/100 - (l * percent/100)
                    
                p = 2 * l - q
                r = hue2rgb(p, q, r + 1/3)
                g = hue2rgb(p, q, g)
                b = hue2rgb(p, q, b - 1/3)
            
            # Convert to hex
            r = int(max(0, min(255, round(r * 255))))
            g = int(max(0, min(255, round(g * 255))))
            b = int(max(0, min(255, round(b * 255))))
            return f"{r:02x}{g:02x}{b:02x}"
        except:
            return hex_color.lstrip('#')

        
    def apply_theme_preset(self, preset_name):
        """Apply a predefined theme preset."""
        presets = self.settings.get("theme", {}).get("presets", {})
        if preset_name in presets:
            preset = presets[preset_name]
            
            # Update dark theme settings
            dark_theme = self.settings.setdefault("dark_theme", {})
            for key, value in preset.items():
                dark_theme[key] = value
            
            # Update accent color if specified in preset
            if "highlight_color" in preset:
                self.settings["theme"]["accent_color"] = preset["highlight_color"]
            
            self.save_settings()
            self.apply_theme(QApplication.instance())
            return True
        return False

    def get_theme_presets(self):
        """Return list of available theme presets."""
        return list(self.settings.get("theme", {}).get("presets", {}).keys())


        


    def validate_settings(self):
        """Ensure all settings exist and are valid."""
        needs_save = False
        
        # Check top-level settings
        for key, default_value in self.default_settings.items():
            if key not in self.settings:
                self.settings[key] = default_value
                needs_save = True
                
        # Check dark theme colors
        if "dark_theme" not in self.settings:
            self.settings["dark_theme"] = self.default_settings["dark_theme"]
            needs_save = True
        else:
            for color_key, default_value in self.default_settings["dark_theme"].items():
                if color_key not in self.settings["dark_theme"]:
                    self.settings["dark_theme"][color_key] = default_value
                    needs_save = True
        
        # Check cookie settings
        if "cookies" not in self.settings:
            self.settings["cookies"] = self.default_settings["cookies"]
            needs_save = True
        else:
            for cookie_key, default_value in self.default_settings["cookies"].items():
                if cookie_key not in self.settings["cookies"]:
                    self.settings["cookies"][cookie_key] = default_value
                    needs_save = True
        
        # Check shortcuts
        if "shortcuts" not in self.settings:
            self.settings["shortcuts"] = self.default_settings["shortcuts"]
            needs_save = True
        else:
            for shortcut, default_value in self.default_settings["shortcuts"].items():
                if shortcut not in self.settings["shortcuts"]:
                    self.settings["shortcuts"][shortcut] = default_value
                    needs_save = True
        
        if needs_save:
            self.save_settings()

    def save_settings(self):
        """Save current settings to file."""
        save_json_file(SETTINGS_FILE, self.settings)

    def get(self, key, default=None):
        """Get a setting value."""
        return self.settings.get(key, default)

    def set(self, key, value):
        """Set a setting value and save to disk."""
        self.settings[key] = value
        self.save_settings()

    def get_shortcut(self, action):
        """Get keyboard shortcut for an action."""
        try:
            return self.settings["shortcuts"].get(action, self.default_settings["shortcuts"].get(action, ""))
        except KeyError:
            return self.default_settings["shortcuts"].get(action, "")




    def closeEvent(self, event):
        # Save completed downloads
        self.download_manager.save_completed_downloads()
        
        # Clean up tabs and other resources
        for index in range(self.tab_widget.count()):
            widget = self.tab_widget.widget(index)
            if widget:
                webview = widget.findChild(QWebEngineView)
                if webview:
                    webview.page().setAudioMuted(True)
                    webview.stop()
        
        event.accept()





    def apply_dark_mode(self, app):
        """Apply dark theme to the application."""
        if not self.settings.get("dark_mode", True):
            app.setPalette(QStyleFactory.create("Fusion").standardPalette())
            app.setStyleSheet("")
            return

        # Use Fusion style as base
        app.setStyle("Fusion")
        
        # Get theme colors
        theme = self.settings.get("dark_theme", self.default_settings["dark_theme"])
        
        # Create and set dark palette
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(theme["window_color"]))
        palette.setColor(QPalette.WindowText, QColor(theme["text_color"]))
        palette.setColor(QPalette.Base, QColor(theme["base_color"]))
        palette.setColor(QPalette.AlternateBase, QColor(theme["base_color"]))
        palette.setColor(QPalette.ToolTipBase, QColor(theme["tooltip_color"]))
        palette.setColor(QPalette.ToolTipText, QColor(theme["text_color"]))
        palette.setColor(QPalette.Text, QColor(theme["text_color"]))
        palette.setColor(QPalette.Button, QColor(theme["button_color"]))
        palette.setColor(QPalette.ButtonText, QColor(theme["text_color"]))
        palette.setColor(QPalette.BrightText, Qt.red)
        palette.setColor(QPalette.Link, QColor(theme["highlight_color"]))
        palette.setColor(QPalette.Highlight, QColor(theme["highlight_color"]))
        palette.setColor(QPalette.HighlightedText, Qt.black)
        palette.setColor(QPalette.Disabled, QPalette.Text, QColor(theme["disabled_color"]))
        palette.setColor(QPalette.Disabled, QPalette.ButtonText, QColor(theme["disabled_color"]))
        
        app.setPalette(palette)
        
        # Apply stylesheet
        app.setStyleSheet(f"""
            QWidget {{
                background-color: {theme["base_color"]};
                color: {theme["text_color"]};
            }}
            QPushButton, QToolButton {{
                background-color: {theme["button_color"]};
                border: 1px solid #444;
                padding: 5px;
                border-radius: 3px;
            }}
            QPushButton:hover, QToolButton:hover {{
                background-color: #{self._adjust_lightness(theme["button_color"], 10)};
            }}
            QTabBar::tab {{
                background: {theme["button_color"]};
                color: {theme["text_color"]};
                padding: 8px;
                border: 1px solid #444;
            }}
            QLineEdit, QTextEdit {{
                background-color: {theme["window_color"]};
                border: 1px solid #444;
            }}
            QMenu {{
                background-color: {theme["window_color"]};
            }}
        """)


    def apply_theme(self, app):
        """Apply theme to the entire application"""
        if not app:
            return
            
        # Store current palette before changes
        old_palette = app.palette()
        
        if self.get("dark_mode", True):
            # Apply dark theme
            palette = QPalette()
            # ... (rest of your dark theme palette setup)
            app.setPalette(palette)
        else:
            # Apply light theme
            app.setPalette(QStyleFactory.create("Fusion").standardPalette())
        
        # Force style refresh
        app.setStyleSheet(app.styleSheet())
        for widget in app.allWidgets():
            widget.update()


    def apply_light_mode(self, app):
        """Apply light theme palette"""
        palette = QPalette()
        
        # Basic colors
        palette.setColor(QPalette.Window, QColor(240, 240, 240))
        palette.setColor(QPalette.WindowText, Qt.black)
        palette.setColor(QPalette.Base, QColor(255, 255, 255))
        palette.setColor(QPalette.AlternateBase, QColor(240, 240, 240))
        
        # Text colors
        palette.setColor(QPalette.Text, Qt.black)
        palette.setColor(QPalette.ButtonText, Qt.black)
        
        # Button colors
        palette.setColor(QPalette.Button, QColor(240, 240, 240))
        
        # Highlight colors
        accent_color = self.get("theme", {}).get("accent_color", "#3daee9")
        palette.setColor(QPalette.Highlight, QColor(accent_color))
        palette.setColor(QPalette.HighlightedText, Qt.white)
        
        app.setPalette(palette)

    def apply_accent_color(self, color_hex):
        """Apply the selected accent color to the theme"""
        if "theme" not in self.settings:
            self.settings["theme"] = {}
        
        self.settings["theme"]["accent_color"] = color_hex
        self.save_settings()
        
        # Update the dark theme highlight color
        if "dark_theme" in self.settings:
            self.settings["dark_theme"]["highlight_color"] = color_hex
            self.save_settings()
        
        # Re-apply the theme
        self.apply_theme(QApplication.instance())












    def _adjust_lightness(self, hex_color, percent):
        """Adjust color lightness (helper for styles)."""
        try:
            hex_color = hex_color.lstrip('#')
            r, g, b = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
            
            # Convert to HSL
            r /= 255.0
            g /= 255.0
            b /= 255.0
            max_val = max(r, g, b)
            min_val = min(r, g, b)
            l = (max_val + min_val) / 2.0
            
            # Adjust lightness
            l = min(1.0, max(0.0, l + (percent / 100.0)))
            
            # Convert back to RGB
            if l <= 0:
                return "000000"
            if l >= 1:
                return "ffffff"
                
            if max_val == min_val:
                r = g = b = l
            else:
                def hue2rgb(p, q, t):
                    if t < 0: t += 1
                    if t > 1: t -= 1
                    if t < 1/6: return p + (q - p) * 6 * t
                    if t < 1/2: return q
                    if t < 2/3: return p + (q - p) * (2/3 - t) * 6
                    return p
                
                if l < 0.5:
                    q = l * (1 + percent/100)
                else:
                    q = l + percent/100 - (l * percent/100)
                    
                p = 2 * l - q
                r = hue2rgb(p, q, r + 1/3)
                g = hue2rgb(p, q, g)
                b = hue2rgb(p, q, b - 1/3)
            
            # Convert to hex
            r = int(max(0, min(255, round(r * 255))))
            g = int(max(0, min(255, round(g * 255))))
            b = int(max(0, min(255, round(b * 255))))
            return f"{r:02x}{g:02x}{b:02x}"
        except:
            return hex_color.lstrip('#')

    def apply_accent_color(self, color_hex):
        """Apply the selected accent color to the theme"""
        if "theme" not in self.settings:
            self.settings["theme"] = {}
        
        self.settings["theme"]["accent_color"] = color_hex
        self.save_settings()
        
        # Update the dark theme highlight color
        if "dark_theme" in self.settings:
            self.settings["dark_theme"]["highlight_color"] = color_hex
            self.save_settings()
        
        # Re-apply the theme
        if hasattr(self.parent(), 'apply_dark_mode'):
            self.parent().apply_dark_mode(QApplication.instance())

# ====================== NOTIFICATION MANAGER ======================
class NotificationManager(QObject):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.notification_window = None

    def show_notification(self, title, message, duration=3000):
        if self.notification_window:
            self.notification_window.close()
            
        self.notification_window = QLabel(message)
        self.notification_window.setWindowTitle(title)
        self.notification_window.setWindowFlags(
            Qt.WindowStaysOnTopHint | 
            Qt.FramelessWindowHint | 
            Qt.ToolTip
        )
        self.notification_window.setStyleSheet("""
            QLabel {
                background-color: #333;
                color: white;
                padding: 10px;
                border-radius: 5px;
                border: 1px solid #555;
            }
        """)
        self.notification_window.adjustSize()
        
        screen = QApplication.primaryScreen().geometry()
        x = screen.width() - self.notification_window.width() - 20
        y = screen.height() - self.notification_window.height() - 50
        self.notification_window.move(x, y)
        
        self.notification_window.show()
        QTimer.singleShot(duration, self.notification_window.close)

# ====================== BOOKMARK SEARCHER AND LAUNCHER ======================
class BookmarkSearcher(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.setWindowTitle("Bookmark Search - (Shift/Ctrl for Multi-Select)")
        self.setMinimumSize(900, 650)
        
        # State tracking
        self.modifiers = Qt.NoModifier
        self.last_clicked_index = None
        
        self.setup_ui()
        
        # Apply theme if needed
        if self.parent.settings_manager.get("dark_mode"):
            self.apply_dark_mode()

    def setup_ui(self):
        """Initialize UI components with enhanced selection handling."""
        layout = QVBoxLayout()
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)
        
        # Search bar with improved UX
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Search bookmarks by title, URL, or description...")
        self.search_bar.setClearButtonEnabled(True)
        self.search_bar.textChanged.connect(self.search_bookmarks)
        
        # Add search icon
        search_icon = QLabel()
        search_icon.setPixmap(QIcon.fromTheme("edit-find").pixmap(16, 16))
        search_layout = QHBoxLayout()
        search_layout.addWidget(search_icon)
        search_layout.addWidget(self.search_bar)
        layout.addLayout(search_layout)

        # Results list with better visual feedback
        self.results_list = QListWidget()
        self.results_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.results_list.setSortingEnabled(True)
        self.results_list.setAlternatingRowColors(True)
        self.results_list.itemActivated.connect(self.on_item_activated)
        self.results_list.itemClicked.connect(self.on_item_clicked)
        layout.addWidget(self.results_list)

        # Status bar for item count
        self.status_label = QLabel()
        layout.addWidget(self.status_label)

        # Button panel with improved layout
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(8)
        
        self.open_btn = QPushButton(QIcon.fromTheme("document-open"), "Open Selected (Enter)")
        self.open_btn.clicked.connect(self.open_selected_bookmarks)
        
        self.open_all_btn = QPushButton(QIcon.fromTheme("document-open-all"), "Open All (Ctrl+Enter)")
        self.open_all_btn.clicked.connect(self.open_all_visible)
        
        close_btn = QPushButton(QIcon.fromTheme("window-close"), "Close (Esc)")
        close_btn.clicked.connect(self.reject)
        
        btn_layout.addWidget(self.open_btn)
        btn_layout.addWidget(self.open_all_btn)
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)

        self.setLayout(layout)
        self.search_bookmarks()
        self.search_bar.setFocus()

    def search_bookmarks(self):
        """Enhanced search with better performance and feedback."""
        query = self.search_bar.text().strip().lower()
        self.results_list.clear()
        
        if not query:
            bookmarks = self.parent.bookmark_manager.get_all_bookmarks()
        else:
            bookmarks = [
                b for b in self.parent.bookmark_manager.get_all_bookmarks()
                if (query in b["title"].lower() or 
                    query in b["url"].lower() or
                    query in b.get("description", "").lower())
            ]
        
        for bookmark in bookmarks:
            item = QListWidgetItem(f"{bookmark['title']} - {bookmark['url']}")
            item.setData(Qt.UserRole, bookmark["url"])
            
            # Enhanced tooltip with formatting
            tooltip = f"""
            <b>{bookmark['title']}</b><br>
            <small>URL: {bookmark['url']}</small><br>
            <small>Folder: {bookmark.get('folder', 'Main')}</small><br>
            <small>Added: {bookmark.get('date', 'Unknown')}</small>
            """
            if bookmark.get("description"):
                tooltip += f"<br><small>Notes: {bookmark['description']}</small>"
            
            item.setToolTip(tooltip.strip())
            self.results_list.addItem(item)
        
        self.results_list.sortItems()
        self.update_status(f"Found {len(bookmarks)} bookmarks")

    def update_status(self, message):
        """Update status label with search results count."""
        self.status_label.setText(message)

    def on_item_activated(self, item):
        """Handle item activation with better tab management."""
        if url := item.data(Qt.UserRole):
            # Remove background condition to open in foreground
            self.parent.add_new_tab(QUrl(url))
            self.accept()  # Close the dialog

    def on_item_clicked(self, item):
        """Track last clicked item for selection management."""
        self.last_clicked_index = self.results_list.row(item)

    def keyPressEvent(self, event):
        self.modifiers = event.modifiers()
        
        # Handle ESC key for exiting fullscreen mode
        if event.key() == Qt.Key_Escape and self.isFullScreen():
            self.exit_fullscreen()
            event.accept()
            return
        
        # Existing functionality for Enter/Return keys
        if event.key() in (Qt.Key_Return, Qt.Key_Enter):
            if event.modifiers() & Qt.ControlModifier:
                self.autocomplete_url()  # New autocomplete behavior
            else:
                selected = self.results_list.selectedItems()
                if selected:
                    self.on_item_activated(selected[0])
                elif self.results_list.count() > 0:
                    self.on_item_activated(self.results_list.item(0))
            event.accept()
        else:
            super().keyPressEvent(event)

    def mousePressEvent(self, event):
        """Improved multi-selection behavior."""
        if event.button() == Qt.LeftButton:
            item = self.results_list.itemAt(event.pos())
            if item:
                if self.modifiers & (Qt.ControlModifier | Qt.ShiftModifier):
                    item.setSelected(not item.isSelected())
                    self.last_clicked_index = self.results_list.row(item)
                else:
                    super().mousePressEvent(event)
        else:
            super().mousePressEvent(event)

    def open_selected_bookmarks(self):
        """Open all selected bookmarks in new tabs (works in both modes).
        If Ctrl is held, opens in incognito tabs. Truncates tab titles."""
        modifiers = QApplication.keyboardModifiers()
        incognito = modifiers & Qt.ControlModifier  # Check if Ctrl is pressed

        # Helper function to truncate title
        def truncate_title(title, max_length=15):
            if len(title) > max_length:
                return title[:max_length - 3] + "..." # Subtract 3 for "..."
            return title

        if hasattr(self, 'bookmarks_tree'):
            # Full manager mode
            selected = self.bookmarks_tree.selectedItems()
            
            # Show status message
            if incognito:
                self.status_bar.showMessage(f"Opening {len(selected)} bookmark(s) in incognito mode...", 3000)
            else:
                self.status_bar.showMessage(f"Opening {len(selected)} bookmark(s)...", 3000)

            for item in selected:
                if not item.childCount():  # Only open leaf nodes (not folders)
                    bookmark = item.data(0, Qt.UserRole)
                    if bookmark:
                        original_title = bookmark["title"]
                        if incognito:
                            # Open in new incognito tab with shortened title
                            display_title = truncate_title(original_title)
                            self.parent.add_incognito_tab(QUrl(bookmark["url"]), f"IC: {display_title}")
                        else:
                            # Open in new regular tab with shortened title (remove background=True)
                            display_title = truncate_title(original_title)
                            self.parent.add_new_tab(QUrl(bookmark["url"]), title=display_title)
                                
        elif hasattr(self, 'results_list'):  # Quick access mode (BookmarkSearcher)
            selected = self.results_list.selectedItems()
            
            if hasattr(self, 'parent') and hasattr(self.parent, 'status_bar'):
                if incognito:
                    self.parent.status_bar.showMessage(f"Opening {len(selected)} bookmark(s) in incognito mode...", 3000)
                else:
                    self.parent.status_bar.showMessage(f"Opening {len(selected)} bookmark(s)...", 3000)

            for item in selected:
                url = item.data(Qt.UserRole)
                if url:
                    original_title = item.text()
                    if incognito:
                        # Open in new incognito tab with shortened title
                        display_title = truncate_title(original_title)
                        self.parent.add_incognito_tab(QUrl(url), f"IC: {display_title}")
                    else:
                        # Open in new regular tab with shortened title (remove background=True)
                        display_title = truncate_title(original_title)
                        self.parent.add_new_tab(QUrl(url), title=display_title)


    def open_all_visible(self):
        """Open all visible bookmarks in background tabs."""
        for i in range(self.results_list.count()):
            if url := self.results_list.item(i).data(Qt.UserRole):
                self.parent.add_new_tab(QUrl(url), background=True)
        self.accept()

    def apply_dark_mode(self, app):
        """Apply dark theme palette without interfering with custom themes"""
        palette = QPalette()
        
        # Basic colors
        palette.setColor(QPalette.Window, QColor(53, 53, 53))
        palette.setColor(QPalette.WindowText, Qt.white)
        palette.setColor(QPalette.Base, QColor(35, 35, 35))
        palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
        
        # Text colors
        palette.setColor(QPalette.Text, Qt.white)
        palette.setColor(QPalette.ButtonText, Qt.white)
        
        # Button colors
        palette.setColor(QPalette.Button, QColor(53, 53, 53))
        
        # Highlight colors (using accent color)
        accent_color = self.get("theme", {}).get("accent_color", "#3daee9")
        palette.setColor(QPalette.Highlight, QColor(accent_color))
        palette.setColor(QPalette.HighlightedText, Qt.black)
        
        app.setPalette(palette)
        
        # Apply minimal necessary stylesheet
        app.setStyleSheet(f"""
            QToolTip {{
                color: #ffffff;
                background-color: #2a82da;
                border: 1px solid white;
            }}
        """)



class BlobUrlInterceptor(QWebEngineUrlRequestInterceptor):
    def interceptRequest(self, info):
        if info.requestUrl().scheme() == 'blob':
            info.setAllowed(True)


# =================================================================
class BrowserCalendar(QWidget):
    DATE_FORMAT = "yyyy-MM-dd"
    DISPLAY_DATE_FORMAT = "MMMM d, yyyy"
    TIME_FORMAT = "HH:mm"

    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.setObjectName("BrowserCalendarWidget")
        self.notes = {}
        self.events = {}
        self.setup_ui()
        self.setup_timers()
        self.load_events()
        self.load_notes_from_file()
        self.show_events_for_date(QDate.currentDate())
        self.show_notes_for_date(QDate.currentDate())

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(10)

        self.calendar = QCalendarWidget()
        self.calendar.setGridVisible(True)
        self.calendar.setVerticalHeaderFormat(QCalendarWidget.NoVerticalHeader)
        layout.addWidget(self.calendar)

        # Connect calendar click to show events and notes for the selected date
        self.calendar.clicked.connect(self.show_events_for_date)
        self.calendar.clicked.connect(self.show_notes_for_date)

        self.event_list = QListWidget()
        self.event_list.setAlternatingRowColors(True)
        self.event_list.itemDoubleClicked.connect(self.on_event_clicked)
        layout.addWidget(self.event_list)

        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)

        notes_tab = QWidget()
        notes_layout = QVBoxLayout(notes_tab)
        notes_layout.setSpacing(6)
        notes_layout.setContentsMargins(8, 8, 8, 8)

        self.notes_text = QTextBrowser()
        self.notes_text.setReadOnly(False)
        self.notes_text.setOpenLinks(False)
        self.notes_text.setMouseTracking(True)
        self.notes_text.viewport().setCursor(Qt.IBeamCursor)
        self.notes_text.setAcceptRichText(True)

        font = QFont()
        font.setPointSize(14)
        self.notes_text.setFont(font)

        self.notes_text.setStyleSheet("""
            QTextBrowser {
                background-color: #2b2b2b;
                color: #ffffff;
                padding: 5px;
                border: 1px solid #444;
                font-size: 14pt;
            }
        """)

        self.notes_text.anchorClicked.connect(self.open_note_link)
        self.notes_text.setContextMenuPolicy(Qt.CustomContextMenu)
        self.notes_text.customContextMenuRequested.connect(self.show_notes_context_menu)
        self.notes_text.viewport().installEventFilter(self)

        notes_layout.addWidget(self.notes_text)

        format_layout = QHBoxLayout()
        bold_btn = QPushButton("Bold")
        italic_btn = QPushButton("Italic")
        underline_btn = QPushButton("Underline")
        color_btn = QPushButton("Color")
        highlight_btn = QPushButton("Highlight")
        clear_format_btn = QPushButton("Clear")

        format_layout.addWidget(bold_btn)
        format_layout.addWidget(italic_btn)
        format_layout.addWidget(underline_btn)
        format_layout.addWidget(color_btn)
        format_layout.addWidget(highlight_btn)
        format_layout.addWidget(clear_format_btn)
        notes_layout.addLayout(format_layout)

        btn_layout = QHBoxLayout()
        save_btn = QPushButton("Save Notes")
        delete_btn = QPushButton("Delete Notes")
        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(delete_btn)
        notes_layout.addLayout(btn_layout)

        save_btn.clicked.connect(self.save_notes)
        delete_btn.clicked.connect(self.delete_notes)
        bold_btn.clicked.connect(self.apply_bold)
        italic_btn.clicked.connect(self.apply_italic)
        underline_btn.clicked.connect(self.apply_underline)
        color_btn.clicked.connect(self.apply_text_color)
        highlight_btn.clicked.connect(self.apply_background_color)
        clear_format_btn.clicked.connect(self.clear_formatting)

        self.tab_widget.addTab(notes_tab, "Notes")

        btn_layout = QHBoxLayout()
        self.add_btn = QPushButton("Add Event")
        self.edit_btn = QPushButton("Edit Event")
        self.delete_btn = QPushButton("Delete Event")
        self.show_all_btn = QPushButton("Show All")

        self.add_btn.clicked.connect(self.show_add_event_dialog)
        self.edit_btn.clicked.connect(self.show_edit_event_dialog)
        self.delete_btn.clicked.connect(self.delete_selected_event)
        self.show_all_btn.clicked.connect(self.show_all_events)

        btn_layout.addWidget(self.add_btn)
        btn_layout.addWidget(self.edit_btn)
        btn_layout.addWidget(self.delete_btn)
        btn_layout.addWidget(self.show_all_btn)
        layout.addLayout(btn_layout)

        self.status_label = QLabel()
        self.update_date_time_label()
        layout.addWidget(self.status_label)

    def show_notes_for_date(self, date):
        """Display notes for the selected date."""
        date_str = date.toString(self.DATE_FORMAT)
        note_data = self.notes.get(date_str)

        if isinstance(note_data, dict):
            raw_text = note_data.get('raw', '')
        else:
            raw_text = ''

        if raw_text:
            html_notes = self._convert_urls_to_links(raw_text)
            safe_html = f'''
            <div style="color: black !important; font-family: sans-serif; font-size: 14pt; padding: 5px;">
                {html_notes}
            </div>
            '''
            full_html = f'''
            <html>
            <head>
                <style>
                    body {{ margin: 0; padding: 10px; background-color: #ffff99; -webkit-text-fill-color: black !important; }}
                    * {{ color: black !important; font-family: sans-serif !important; font-size: 14pt !important; -webkit-text-fill-color: black !important; }}
                    a {{ color: #45a1ff !important; text-decoration: underline !important; }}
                </style>
            </head>
            <body>
                {safe_html}
            </body>
            </html>
            '''
            self.notes_text.setHtml(full_html)
        else:
            self.notes_text.setHtml('''
                <html>
                    <body style="background-color: #ffff99; color: black; margin: 10px;">
                        <span style="color: black;">&nbsp;</span>
                    </body>
                </html>
            ''')

    def show_events_for_date(self, date):
        """Display events for the selected date."""
        date_str = date.toString(self.DATE_FORMAT)
        self.event_list.clear()

        if date_str in self.events:
            header = QListWidgetItem(f"Events for {date.toString(self.DISPLAY_DATE_FORMAT)}:")
            header.setFlags(header.flags() & ~Qt.ItemIsSelectable)
            self.event_list.addItem(header)

            for event in sorted(self.events[date_str], key=lambda x: x['time']):
                item = QListWidgetItem(f"{event['time']}: {event['name']}")
                item.setData(Qt.UserRole, (date_str, event))
                self.event_list.addItem(item)
        else:
            self.event_list.addItem(f"No events for {date.toString(self.DISPLAY_DATE_FORMAT)}")

    def apply_italic(self):
        cursor = self.notes_text.textCursor()
        if not cursor.hasSelection():
            return
        fmt = cursor.charFormat()
        fmt.setFontItalic(not fmt.fontItalic())
        cursor.mergeCharFormat(fmt)
        self.notes_text.setTextCursor(cursor)

    def apply_underline(self):
        cursor = self.notes_text.textCursor()
        if not cursor.hasSelection():
            return
        fmt = cursor.charFormat()
        current_underline = fmt.underlineStyle()
        new_underline = Qt.NoUnderline if current_underline != Qt.NoUnderline else Qt.SingleUnderline
        fmt.setUnderlineStyle(new_underline)
        cursor.mergeCharFormat(fmt)
        self.notes_text.setTextCursor(cursor)

    def apply_bold(self):
        cursor = self.notes_text.textCursor()
        if not cursor.hasSelection():
            return
        fmt = cursor.charFormat()
        current_weight = fmt.fontWeight()
        new_weight = QFont.Normal if current_weight > QFont.Normal else QFont.Bold
        fmt.setFontWeight(new_weight)
        cursor.mergeCharFormat(fmt)
        self.notes_text.setTextCursor(cursor)

    def apply_text_color(self):
        color = QColorDialog.getColor()
        if color.isValid():
            cursor = self.notes_text.textCursor()
            if cursor.hasSelection():
                fmt = QTextCharFormat()
                fmt.setForeground(color)
                cursor.mergeCharFormat(fmt)
                self.notes_text.setTextCursor(cursor)

    def apply_background_color(self):
        color = QColorDialog.getColor()
        if color.isValid():
            cursor = self.notes_text.textCursor()
            if cursor.hasSelection():
                fmt = QTextCharFormat()
                fmt.setBackground(color)
                cursor.mergeCharFormat(fmt)
                self.notes_text.setTextCursor(cursor)

    def clear_formatting(self):
        cursor = self.notes_text.textCursor()
        if cursor.hasSelection():
            fmt = QTextCharFormat()
            fmt.clearProperty(QTextFormat.FontWeight)
            fmt.clearProperty(QTextFormat.FontItalic)
            fmt.clearProperty(QTextFormat.TextUnderlineStyle)
            fmt.setForeground(QBrush())
            fmt.setBackground(QBrush())
            cursor.mergeCharFormat(fmt)
            self.notes_text.setTextCursor(cursor)

    def open_note_link(self, url):
        if isinstance(url, str):
            url = QUrl(url)
        if not url.isValid():
            return
        browser_window = self.parent()
        while browser_window and not isinstance(browser_window, QMainWindow):
            browser_window = browser_window.parent()
        if browser_window and hasattr(browser_window, 'add_new_tab'):
            browser_window.add_new_tab(url, background=True)
        else:
            QDesktopServices.openUrl(url)

    def eventFilter(self, source, event):
        if source == self.notes_text.viewport():
            if event.type() == QEvent.MouseMove:
                anchor = self.notes_text.anchorAt(event.pos())
                if anchor:
                    self.notes_text.viewport().setCursor(Qt.PointingHandCursor)
                else:
                    self.notes_text.viewport().setCursor(Qt.IBeamCursor)
            elif event.type() == QEvent.MouseButtonRelease and event.button() == Qt.LeftButton:
                anchor = self.notes_text.anchorAt(event.pos())
                if anchor:
                    self.open_note_link(QUrl(anchor))
                    return True
        return super().eventFilter(source, event)

    def show_notes_context_menu(self, pos):
        menu = QMenu(self)
        selected_date = self.calendar.selectedDate()
        date_str = selected_date.toString(self.DATE_FORMAT)
        has_notes = date_str in self.notes and bool(self.notes[date_str].get('raw', '').strip())
        cursor = self.notes_text.cursorForPosition(pos)
        cursor.select(QTextCursor.WordUnderCursor)
        selected_text = cursor.selectedText()

        is_url = False
        url = None
        url_pattern = re.compile(r'^(https?://|www\.)[^\s/$.?#].[^\s]*$', re.IGNORECASE)
        if selected_text:
            url_candidate = selected_text.strip()
            if url_pattern.match(url_candidate):
                is_url = True
                url = url_candidate
                if url.startswith('www.'):
                    url = f'https://{url}'

        if is_url and url:
            display_text = (selected_text[:20] + '...') if len(selected_text) > 20 else selected_text
            url_menu = QMenu("URL Actions", self)

            open_external_action = QAction("Open in Default Browser", self)
            open_external_action.setIcon(QIcon.fromTheme("web-browser"))
            open_external_action.triggered.connect(lambda: QDesktopServices.openUrl(QUrl(url)))
            url_menu.addAction(open_external_action)

            main_window = self.window()

            if hasattr(main_window, 'add_new_tab'):
                open_normal_action = QAction("Open in New Tab", self)
                open_normal_action.setIcon(QIcon.fromTheme("tab-new"))
                open_normal_action.triggered.connect(lambda: main_window.add_new_tab(QUrl(url)))
                url_menu.addAction(open_normal_action)

            if hasattr(main_window, 'add_incognito_tab'):
                open_incognito_action = QAction("Open in Incognito Tab", self)
                incognito_icon = (
                    QIcon.fromTheme("private-browsing") or
                    QIcon.fromTheme("incognito") or
                    QIcon.fromTheme("view-private")
                )
                if not incognito_icon.isNull():
                    open_incognito_action.setIcon(incognito_icon)
                open_incognito_action.triggered.connect(
                    lambda: main_window.add_incognito_tab(QUrl(url), f"Incognito: {display_text}")
                )
                url_menu.addAction(open_incognito_action)

            copy_action = QAction("Copy URL", self)
            copy_action.setIcon(QIcon.fromTheme("edit-copy"))
            copy_action.triggered.connect(lambda: QApplication.clipboard().setText(url))
            url_menu.addAction(copy_action)
            menu.addMenu(url_menu)
            menu.addSeparator()

        edit_actions = [
            ("edit-undo", "Undo", self.notes_text.undo, self.notes_text.document().isUndoAvailable()),
            ("edit-redo", "Redo", self.notes_text.redo, self.notes_text.document().isRedoAvailable()),
            ("edit-cut", "Cut", self.notes_text.cut, self.notes_text.textCursor().hasSelection()),
            ("edit-copy", "Copy", self.notes_text.copy, self.notes_text.textCursor().hasSelection()),
            ("edit-paste", "Paste", self.notes_text.paste, bool(QApplication.clipboard().text()))
        ]

        for icon_name, name, handler, enabled in edit_actions:
            action = QAction(name, self)
            action.setIcon(QIcon.fromTheme(icon_name))
            action.setEnabled(enabled)
            action.triggered.connect(handler)
            menu.addAction(action)
            if name == "Redo":
                menu.addSeparator()

        if has_notes:
            copy_all_action = QAction("Copy All Notes", self)
            copy_all_action.setIcon(QIcon.fromTheme("edit-copy"))
            copy_all_action.triggered.connect(lambda: QApplication.clipboard().setText(self.notes_text.toPlainText()))
            menu.addAction(copy_all_action)
            clear_action = QAction("Clear Notes", self)
            clear_action.setIcon(QIcon.fromTheme("edit-clear"))
            clear_action.triggered.connect(self.delete_notes)
            menu.addAction(clear_action)
            menu.addSeparator()

        format_menu = QMenu("Text Formatting", self)
        format_menu.setIcon(QIcon.fromTheme("preferences-desktop-font"))
        formatting_actions = [
            ("format-text-bold", "Bold", self.apply_bold),
            ("format-text-italic", "Italic", self.apply_italic),
            ("format-text-underline", "Underline", self.apply_underline),
            ("format-text-color", "Text Color", self.apply_text_color),
            ("format-fill-color", "Highlight", self.apply_background_color)
        ]

        for icon_name, name, handler in formatting_actions:
            action = QAction(name, self)
            action.setIcon(QIcon.fromTheme(icon_name))
            action.triggered.connect(handler)
            format_menu.addAction(action)
        menu.addMenu(format_menu)

        menu.exec_(self.notes_text.viewport().mapToGlobal(pos))

    def setup_timers(self):
        self.reminder_timer = QTimer(self)
        self.reminder_timer.timeout.connect(self.check_reminders)
        self.reminder_timer.start(60000)

        self.clock_timer = QTimer(self)
        self.clock_timer.timeout.connect(self.update_date_time_label)
        self.clock_timer.start(1000)

    def _convert_urls_to_links(self, text):
        text = (text.replace('&', '&amp;')
                    .replace('<', '&lt;')
                    .replace('>', '&gt;')
                    .replace('"', '&quot;'))

        url_pattern = re.compile(
            r'('
            r'(https?|ftp)://[^\s/$.?#].[^\s]*'  # Standard URLs
            r'|'
            r'www\.[^\s/$.?#].[^\s]*'  # www domains
            r'|'
            r'[a-z0-9.-]+\.[a-z]{2,}(?=/|$)[^\s]*'  # Plain domains
            r')',
            re.IGNORECASE)

        def make_link(match):
            url = match.group(1)
            if not url.startswith(('http://', 'https://', 'ftp://')):
                url = 'http://' + url
            return f'<a href="{url}">{match.group(1)}</a>'

        text = url_pattern.sub(make_link, text)
        return text.replace('\n', '<br>')

    def save_notes(self):
        date_str = self.calendar.selectedDate().toString(self.DATE_FORMAT)
        raw_text = self.notes_text.toPlainText()
        if raw_text.strip():
            self.notes[date_str] = {'raw': raw_text}
            converted = self._convert_urls_to_links(raw_text)
            html_notes = f'''
            <html>
            <head>
            <style>
                a {{ color: #45a1ff; text-decoration: underline; }}
                body {{
                    font-family: sans-serif;
                    font-size: 12pt;
                    color: #f0f0f0;
                    background-color: transparent;
                }}
            </style>
            </head>
            <body>{converted}</body>
            </html>
            '''
            self.notes[date_str]['html'] = html_notes
        else:
            self.notes.pop(date_str, None)
        self.save_notes_to_file()
        if hasattr(self, 'main_window') and hasattr(self.main_window, 'status_bar'):
            self.main_window.status_bar.showMessage(f"Notes saved for {date_str}", 2000)

    def delete_selected_event(self):
        selected_items = self.event_list.selectedItems()
        if not selected_items:
            QMessageBox.information(self, "No Selection", "Please select an event to delete.")
            return
        selected_item = selected_items[0]
        item_data = selected_item.data(Qt.UserRole)
        if not item_data or not isinstance(item_data, tuple) or len(item_data) != 2:
            QMessageBox.warning(self, "Error", "Invalid event data format.")
            return
        date_str, event = item_data
        if date_str not in self.events:
            QMessageBox.warning(self, "Error", "No events exist for this date.")
            return
        if event not in self.events[date_str]:
            QMessageBox.warning(self, "Error", "Event not found in current data.")
            return
        reply = QMessageBox.question(
            self,
            "Confirm Deletion",
            f"Delete event '{event['name']}' at {event['time']} on {QDate.fromString(date_str, self.DATE_FORMAT).toString(self.DISPLAY_DATE_FORMAT)}?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            try:
                self.events[date_str].remove(event)
                if not self.events[date_str]:
                    del self.events[date_str]
                self.save_events()
                current_date = self.calendar.selectedDate()
                self.show_events_for_date(current_date)
                QMessageBox.information(
                    self,
                    "Success",
                    "Event deleted successfully.",
                    QMessageBox.Ok
                )
            except Exception as e:
                QMessageBox.critical(
                    self,
                    "Error",
                    f"Failed to delete event: {str(e)}",
                    QMessageBox.Ok
                )

    def delete_notes(self):
        date_str = self.calendar.selectedDate().toString(self.DATE_FORMAT)
        reply = QMessageBox.question(self, "Confirm Delete",
                                     f"Delete notes for {date_str}?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.notes.pop(date_str, None)
            self.notes_text.clear()
            self.save_notes_to_file()
            main_window = self.get_main_window()
            if main_window and hasattr(main_window, 'status_bar'):
                main_window.status_bar.showMessage(f"Notes deleted for {date_str}", 2000)

    def get_main_window(self):
        parent = self.parent()
        while parent and not isinstance(parent, QMainWindow):
            parent = parent.parent()
        return parent

    def save_notes_to_file(self):
        notes_file = os.path.join(self._get_config_dir(), "calendar_notes.json")
        try:
            with open(notes_file, "w", encoding='utf-8') as f:
                json.dump(self.notes, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Error saving notes: {e}")
            QMessageBox.critical(self, "Save Error", f"Could not save notes:\n{str(e)}")

    def load_notes_from_file(self):
        notes_file = os.path.join(self._get_config_dir(), "calendar_notes.json")
        try:
            if os.path.exists(notes_file):
                with open(notes_file, "r", encoding='utf-8') as f:
                    self.notes = json.load(f)
            else:
                self.notes = {}
        except Exception as e:
            print(f"Error loading notes: {e}")
            self.notes = {}

    def _validate_event(self, event):
        errors = []

        if not isinstance(event, dict):
            errors.append("Event data must be a dictionary.")
            return False, errors

        if 'name' not in event or not event['name'].strip():
            errors.append("Event name cannot be empty.")

        if 'time' not in event or not QTime.fromString(event['time'], self.TIME_FORMAT).isValid():
            errors.append("Invalid time format (use HH:mm).")

        return len(errors) == 0, errors

    def add_event(self, dialog):
        name = self.event_name_edit.text().strip()
        date = self.date_edit.selectedDate()
        if not date.isValid():
            date = QDate.currentDate()
        date_str = date.toString(self.DATE_FORMAT)
        time = self.time_edit.time().toString(self.TIME_FORMAT)

        event = {
            "name": name,
            "time": time,
            "reminder": self.reminder_check.isChecked()
        }

        is_valid, errors = self._validate_event(event)
        if not is_valid:
            QMessageBox.warning(dialog, "Validation Error", "\n".join(errors))
            return

        if date_str not in self.events:
            self.events[date_str] = []

        existing_events = [e for e in self.events[date_str]
                          if e["time"] == time and e["name"] == name]
        if existing_events:
            QMessageBox.information(dialog, "Duplicate Event", "This event already exists.")
            return

        self.events[date_str].append(event)
        self.save_events()
        self.show_events_for_date(date)
        dialog.accept()

    def load_events(self):
        events_file = self.get_events_file_path()
        self.events = {}

        try:
            if os.path.exists(events_file):
                with open(events_file, 'r', encoding='utf-8') as f:
                    raw_data = json.load(f)

                if isinstance(raw_data, dict):
                    for date_str, events in raw_data.items():
                        try:
                            if not QDate.fromString(date_str, self.DATE_FORMAT).isValid():
                                print(f"Skipping invalid date entry: {date_str}")
                                continue

                            if isinstance(events, list):
                                valid_events = []
                                for event in events:
                                    is_valid, errors = self._validate_event(event)
                                    if is_valid:
                                        valid_events.append(event)
                                    else:
                                        print(f"Skipping invalid event: {errors}")

                                if valid_events:
                                    self.events[date_str] = valid_events
                        except Exception as e:
                            print(f"Error processing date {date_str}: {e}")
                            continue

        except Exception as e:
            print(f"Error loading events: {e}")
            self.events = {}

    def update_date_time_label(self):
        current = QDateTime.currentDateTime()
        self.status_label.setText(current.toString("dddd, MMMM d, yyyy - hh:mm:ss AP"))

    def show_all_events(self):
        self.event_list.clear()
        self.event_list.addItem("All Events:")

        for date in sorted(self.events.keys()):
            for event in sorted(self.events[date], key=lambda x: x['time']):
                reminder = " 🔔" if event.get("reminder") else ""
                self.event_list.addItem(
                    f"{QDate.fromString(date, self.DATE_FORMAT).toString('MMM d')}: "
                    f"{event['time']} - {event['name']}{reminder}"
                )

    def on_event_clicked(self, item):
        text = item.text()
        if ":" in text and "-" in text:
            date_part = text.split(":")[0].strip()
            date = QDate.fromString(date_part, "MMM d")
            self.calendar.setSelectedDate(date)

    def show_add_event_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Add Event")
        layout = QVBoxLayout(dialog)

        name_layout = QHBoxLayout()
        name_layout.addWidget(QLabel("Name:"))
        self.event_name_edit = QLineEdit()
        name_layout.addWidget(self.event_name_edit)
        layout.addLayout(name_layout)

        date_time_layout = QHBoxLayout()

        date_group = QGroupBox("Date")
        date_layout = QVBoxLayout()
        self.date_edit = QCalendarWidget()
        self.date_edit.setSelectedDate(self.calendar.selectedDate())
        date_layout.addWidget(self.date_edit)
        date_group.setLayout(date_layout)

        time_group = QGroupBox("Time")
        time_layout = QVBoxLayout()
        self.time_edit = QTimeEdit()
        self.time_edit.setTime(QTime.currentTime())
        time_layout.addWidget(self.time_edit)
        time_group.setLayout(time_layout)

        date_time_layout.addWidget(date_group)
        date_time_layout.addWidget(time_group)
        layout.addLayout(date_time_layout)

        self.reminder_check = QCheckBox("Set Reminder")
        layout.addWidget(self.reminder_check)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(lambda: self.add_event(dialog))
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        dialog.exec_()

    def show_edit_event_dialog(self):
        selected_items = self.event_list.selectedItems()
        if not selected_items:
            QMessageBox.information(self, "No Selection", "Please select an event to edit.")
            return

        selected_item = selected_items[0]
        date_str, event = selected_item.data(Qt.UserRole)
        dialog = QDialog(self)
        dialog.setWindowTitle("Edit Event")
        layout = QVBoxLayout(dialog)

        name_layout = QHBoxLayout()
        name_layout.addWidget(QLabel("Name:"))
        self.edit_name_edit = QLineEdit()
        self.edit_name_edit.setText(event["name"])
        name_layout.addWidget(self.edit_name_edit)
        layout.addLayout(name_layout)

        date_time_layout = QHBoxLayout()
        self.edit_date_edit = QCalendarWidget()
        self.edit_date_edit.setSelectedDate(QDate.fromString(date_str, self.DATE_FORMAT))
        self.edit_time_edit = QTimeEdit()
        self.edit_time_edit.setTime(QTime.fromString(event["time"], self.TIME_FORMAT))
        date_time_layout.addWidget(self.edit_date_edit)
        date_time_layout.addWidget(self.edit_time_edit)
        layout.addLayout(date_time_layout)

        self.edit_reminder_check = QCheckBox("Set Reminder")
        self.edit_reminder_check.setChecked(event.get("reminder", False))
        layout.addWidget(self.edit_reminder_check)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(lambda: self.save_edited_event(date_str, event, dialog))
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        dialog.exec_()

    def save_edited_event(self, old_date_str, old_event, dialog):
        new_name = self.edit_name_edit.text().strip()
        new_date = self.edit_date_edit.selectedDate()
        new_time = self.edit_time_edit.time().toString(self.TIME_FORMAT)
        new_date_str = new_date.toString(self.DATE_FORMAT)
        has_reminder = self.edit_reminder_check.isChecked()

        if not new_name:
            QMessageBox.warning(dialog, "Invalid Name", "Event name cannot be empty.")
            return

        if new_date_str in self.events:
            for existing_event in self.events[new_date_str]:
                if (old_date_str == new_date_str and
                    existing_event["name"] == old_event["name"] and
                    existing_event["time"] == old_event["time"]):
                    continue

                if (existing_event["time"] == new_time and
                    existing_event["name"].lower() == new_name.lower()):
                    QMessageBox.warning(dialog, "Duplicate Event",
                                      f"An event already exists at {new_time} on {new_date.toString(self.DISPLAY_DATE_FORMAT)}.")
                    return

        updated_event = {
            "name": new_name,
            "time": new_time,
            "reminder": has_reminder
        }

        if old_date_str != new_date_str:
            self.events[old_date_str].remove(old_event)
            if not self.events[old_date_str]:
                del self.events[old_date_str]

        if new_date_str not in self.events:
            self.events[new_date_str] = []

        self.events[new_date_str].append(updated_event)
        self.events[new_date_str].sort(key=lambda x: x["time"])

        self.save_events()
        self.show_events_for_date(new_date)

        QMessageBox.information(dialog, "Success", "Event updated successfully.")
        dialog.accept()

    def check_reminders(self):
        current_date = QDate.currentDate().toString(self.DATE_FORMAT)
        current_time = QTime.currentTime().toString(self.TIME_FORMAT)

        if current_date in self.events:
            for event in self.events[current_date]:
                if event.get("reminder") and event["time"] == current_time:
                    self.show_reminder_notification(event)
                    event["reminder"] = False
                    self.save_events()

    def show_reminder_notification(self, event):
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Information)
        msg.setWindowTitle("Event Reminder")
        msg.setText(f"⏰ Reminder: {event['name']} at {event['time']}")
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()

    def _get_config_dir(self):
        config_dir = os.path.expanduser("~/.config/storm_browser")
        os.makedirs(config_dir, exist_ok=True)
        return config_dir

    def get_events_file_path(self):
        config_dir = os.path.expanduser("~/.config/storm_browser")
        os.makedirs(config_dir, exist_ok=True)
        return os.path.join(config_dir, "calendar_events.json")

    def save_events(self):
        events_file = self.get_events_file_path()
        try:
            validated_events = {}
            for date_str, events in self.events.items():
                valid, date = self.validate_date_string(date_str)
                if valid:
                    validated_events[date_str] = events

            with open(events_file, 'w', encoding='utf-8') as f:
                json.dump(validated_events, f, indent=2, ensure_ascii=False)

        except Exception as e:
            print(f"Error saving events: {e}")
            QMessageBox.critical(self, "Save Error", f"Could not save events:\n{str(e)}")

    def validate_date_string(self, date_str):
        date = QDate.fromString(date_str, self.DATE_FORMAT)
        return date.isValid(), date


#=============================================================================


class FaviconManager(QObject):
    favicon_ready = pyqtSignal(str, QIcon)  # Signal emitted when favicon is loaded
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.network_manager = QNetworkAccessManager(self)
        self.favicon_cache = {}
        self.cache_dir = os.path.join(
            QStandardPaths.writableLocation(QStandardPaths.CacheLocation), 
            "favicons"
        )
        os.makedirs(self.cache_dir, exist_ok=True)
        self._setup_cache_cleanup()
        
        # Connect signals
        self.network_manager.finished.connect(self._on_favicon_downloaded)
        
    def _setup_cache_cleanup(self):
        """Setup periodic cache cleanup"""
        self.cache_cleanup_timer = QTimer(self)
        self.cache_cleanup_timer.timeout.connect(self._cleanup_cache)
        self.cache_cleanup_timer.start(24 * 60 * 60 * 1000)  # Daily cleanup

    def _cleanup_cache(self, max_age_days=30, max_size_mb=50):
        """Clean up old or oversized cache"""
        total_size = 0
        now = time.time()
        
        for filename in os.listdir(self.cache_dir):
            filepath = os.path.join(self.cache_dir, filename)
            try:
                stat = os.stat(filepath)
                file_age = (now - stat.st_mtime) / (24 * 3600)  # in days
                
                # Delete if too old
                if file_age > max_age_days:
                    os.unlink(filepath)
                    continue
                    
                # Count size for active files
                total_size += stat.st_size
                
            except Exception as e:
                print(f"Cache cleanup error for {filepath}: {str(e)}")
        
        # Convert to MB
        total_size_mb = total_size / (1024 * 1024)
        
        # If cache is too big, delete oldest files
        if total_size_mb > max_size_mb:
            files = []
            for filename in os.listdir(self.cache_dir):
                filepath = os.path.join(self.cache_dir, filename)
                try:
                    stat = os.stat(filepath)
                    files.append((stat.st_mtime, filepath))
                except:
                    continue
            
            # Sort by oldest first
            files.sort()
            
            # Delete until we're under the limit
            for mtime, filepath in files:
                if total_size_mb <= max_size_mb * 0.8:  # Stop at 80% of limit
                    break
                try:
                    size = os.path.getsize(filepath)
                    os.unlink(filepath)
                    total_size_mb -= size / (1024 * 1024)
                except:
                    continue

    def get_favicon(self, url):
        """Get favicon for given URL with improved handling"""
        if not url:
            return QIcon()
            
        parsed = QUrl(url)
        if not parsed.isValid():
            return QIcon()
            
        domain = parsed.host()
        if not domain:
            return QIcon()
            
        # Normalize domain (remove www. if present)
        domain = domain.lower()
        if domain.startswith('www.'):
            domain = domain[4:]
            
        # Check memory cache first
        if domain in self.favicon_cache:
            return self.favicon_cache[domain]
            
        # Check disk cache
        favicon_path = os.path.join(self.cache_dir, f"{domain}.ico")
        if os.path.exists(favicon_path):
            try:
                # Validate the cached file
                if os.path.getsize(favicon_path) > 0:
                    icon = QIcon(favicon_path)
                    if not icon.isNull():
                        self.favicon_cache[domain] = icon
                        return icon
                # If invalid, delete it
                os.unlink(favicon_path)
            except Exception as e:
                print(f"Error loading cached favicon: {str(e)}")
                
        # Try multiple favicon locations
        favicon_urls = [
            f"https://{domain}/favicon.ico",
            f"http://{domain}/favicon.ico",
            f"https://www.{domain}/favicon.ico",
            f"http://www.{domain}/favicon.ico",
            parsed.toString() + "/favicon.ico"
        ]
        
        # Try each URL until we find one that works
        for favicon_url in favicon_urls:
            qurl = QUrl(favicon_url)
            if qurl.isValid():
                self._download_favicon(qurl, domain)
                break
                
        return QIcon()  # Return empty icon while loading

    def _download_favicon(self, url, domain):
        """Download favicon with proper timeout and redirect handling"""
        request = QNetworkRequest(url)
        request.setAttribute(QNetworkRequest.FollowRedirectsAttribute, True)
        request.setRawHeader(b"User-Agent", b"Mozilla/5.0")
        
        reply = self.network_manager.get(request)
        
        # Set timeout (10 seconds)
        timer = QTimer(reply)
        timer.setSingleShot(True)
        timer.timeout.connect(reply.abort)
        timer.start(10000)
        
        # Store domain with reply for later identification
        reply.domain = domain

    def _on_favicon_downloaded(self, reply):
        """Handle completed favicon download"""
        domain = getattr(reply, 'domain', '')
        
        if reply.error() == QNetworkReply.NoError:
            data = reply.readAll().data()
            if data:  # Only proceed if we got data
                pixmap = QPixmap()
                if pixmap.loadFromData(data):
                    icon = QIcon(pixmap)
                    if not icon.isNull():
                        self.favicon_cache[domain] = icon
                        
                        # Save to cache
                        favicon_path = os.path.join(self.cache_dir, f"{domain}.ico")
                        try:
                            with open(favicon_path, 'wb') as f:
                                f.write(data)
                        except Exception as e:
                            print(f"Error saving favicon: {str(e)}")
                        
                        # Emit signal that favicon is ready
                        self.favicon_ready.emit(domain, icon)
        else:
            error = reply.errorString()
            if reply.error() != QNetworkReply.OperationCanceledError:
                print(f"Favicon download failed for {domain}: {error}")
                
        reply.deleteLater()

    def clear_cache(self):
        """Clear both memory and disk cache"""
        self.favicon_cache.clear()
        if os.path.exists(self.cache_dir):
            for filename in os.listdir(self.cache_dir):
                file_path = os.path.join(self.cache_dir, filename)
                try:
                    if os.path.isfile(file_path):
                        os.unlink(file_path)
                except Exception as e:
                    print(f"Error deleting {file_path}: {str(e)}")

# ====================== MAIN BROWSER WINDOW ======================
# --- Add Import for the ChromeProfileImporter ---
# Make sure this import path is correct relative to your icarus_browser.py


#!/usr/bin/env python3
import sys, os
from PyQt5.QtWidgets import QMainWindow, QStatusBar, QMessageBox, QAction
from PyQt5.QtCore import Qt, QUrl, QTimer
from PyQt5.QtWebEngineWidgets import QWebEngineProfile, QWebEnginePage, QWebEngineView

# --- Assume all your other imports (managers, utilities, etc.) are here ---
# from your_modules import ConfigManager, SettingsManager, ThemeManager, ...
# from chrome_profile_importer import ChromeProfileImporter

class BrowserMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Storm Browser v12 - Ultimate Edition")
        self.setMinimumSize(800, 600)
        self.showMaximized()
        self.shortcuts = []
        # --- Manager Initialization ---
        self.config_manager = ConfigManager()
        self.config_manager.initialize()
        self.settings_manager = SettingsManager(self)
        self.theme_manager = ThemeManager(self.settings_manager)
        self.password_manager = PasswordManager(self)
        self.download_manager = DownloadManager(self)
        self.bookmark_manager = BookmarkManager(self)
        self.history_manager = HistoryManager(self)
        self.cookie_manager = CookieManager(self)
        self.notification_manager = NotificationManager(self)
        self.screen_recorder = ScreenRecorder(self)
        self.screen_recorder.recording_started.connect(self.on_recording_started)
        self.screen_recorder.recording_finished.connect(self.on_recording_finished)
        self.screen_recorder.recording_progress.connect(self.on_recording_progress)
        self.screen_recorder.recording_error.connect(self.on_recording_error)
        self.screen_recorder.recording_status.connect(self.handle_recording_status)
        self.screen_recorder.recording_timeout.connect(self.on_recording_timeout)
        self.screen_recorder.recording_stats.connect(self.handle_recording_stats)
        self.current_accent_color = self.settings_manager.get("theme", {}).get("accent_color", "#3daee9")
        self.settings_manager.accent_color_changed.connect(self.handle_accent_color_change)
        self.status_bar = QStatusBar()
        self.status_bar.setSizeGripEnabled(False)
        self.setStatusBar(self.status_bar)
        self.recording_size_timer = QTimer(self)
        self.recording_size_timer.timeout.connect(self.update_recording_size)
        self.last_file_size = 0
        self.favicon_manager = FaviconManager(self)
        self.favicon_manager.favicon_ready.connect(self.update_tab_favicon)
        self.pdf_viewer = PDFViewer(self)
        self.url_interceptor = BlobUrlInterceptor()
        QWebEngineProfile.defaultProfile().setUrlRequestInterceptor(self.url_interceptor)
        
        # --- Netflix DRM Handler Initialization ---
        self.netflix_drm_handler = NetflixDRMHandler()
        
        self.setup_ui()
        self.connect_signals()
        try:
            self.tab_widget.tabCloseRequested.disconnect()
        except TypeError:
            pass
        self.tab_widget.tabCloseRequested.connect(lambda idx: self.close_tab(idx))
        self._init_autocomplete_system()
        self.setup_calendar()
        self.setup_connections()
        self.setup_shortcuts()
        self.setup_url_launcher_shortcut()
        self._setup_password_handling()
        if self.settings_manager.get("dark_mode"):
            self.settings_manager.apply_dark_mode(QApplication.instance())
        self.update_url_bar_style(self.current_accent_color)
        self.theme_manager.apply_theme()
        # --- Google Profile Import integration ---
        self.google_imported_profile = None
        self.use_imported_profile_for_new_tabs = False
        self._create_import_menu_action()
        self.configure_webengine()
        self.multi_site_search = MultiSiteSearchWidget(parent=self)
        self.addDockWidget(Qt.RightDockWidgetArea, self.multi_site_search)
        self.multi_site_search.hide()
        
        # Verify Widevine support after initialization
        if self.netflix_drm_handler.widevine_available:
            QTimer.singleShot(2000, self.netflix_drm_handler.verify_widevine_support)
        
        self.add_new_tab(QUrl(self.settings_manager.get("home_page")))
        self.tab_widget.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tab_widget.customContextMenuRequested.connect(self.show_tab_context_menu)
        self.closed_tabs = []
        self.MAX_CLOSED_TABS = 10
        self.setFocusPolicy(Qt.StrongFocus)
    
    def get_netflix_profile(self):
        """Get the Netflix profile with DRM support."""
        if self.netflix_drm_handler:
            return self.netflix_drm_handler.get_netflix_profile()
        return None

    # --- Google Profile Import Methods ---
    def _create_import_menu_action(self):
        menu_bar = self.menuBar()
        if not menu_bar:
            return
        target_menu = None
        for action in menu_bar.actions():
            menu = action.menu()
            if menu and menu.title().lower().replace('&', '') in ["tools", "edit", "view", "profile", "accounts"]:
                target_menu = menu
                break
        if target_menu is None:
            target_menu = menu_bar.addMenu("&Profiles")
        existing_actions = [act.text() for act in target_menu.actions()]
        if "Import Google Login" not in existing_actions:
            import_google_action = QAction("Import Google Login", self)
            import_google_action.setStatusTip("Import a Google login session from Chrome")
            import_google_action.triggered.connect(self.initiate_google_import)
            target_menu.addAction(import_google_action)

    def initiate_google_import(self):
        if 'ChromeProfileImporter' not in globals():
            QMessageBox.critical(self, "Import Error", "ChromeProfileImporter class not found.")
            return
        importer_dialog = ChromeProfileImporter(parent=self)
        importer_dialog.profile_imported.connect(self.on_google_profile_imported)
        importer_dialog.import_failed.connect(self.on_google_import_failed)
        self.status_bar.showMessage("Google Import: Opening Chrome for login...", 3000)
        importer_dialog.exec_()
        self.status_bar.clearMessage()



    def interceptRequest(self, info):
        # Force the User-Agent header for every single HTTP request
        info.setHttpHeader(b"User-Agent", self.user_agent.encode("utf-8"))


    def on_google_profile_imported(self, profile_path_str):
        """
        Handles the signal emitted when a Google profile is successfully imported.
        Sets up the imported profile for use in new tabs and forces a modern UA
        so streaming sites like Netflix work.
        """
        print(f"[INFO] Setting up imported profile from: {profile_path_str}")

        # Create the QWebEngineProfile
        self.google_imported_profile = QWebEngineProfile(profile_path_str, self)

        # Configure persistent storage
        self.google_imported_profile.setPersistentCookiesPolicy(QWebEngineProfile.ForcePersistentCookies)
        self.google_imported_profile.setHttpCacheType(QWebEngineProfile.DiskHttpCache)

        # Latest Chrome UA string (verified working)
        latest_chrome_ua = (
            "Mozilla/5.0 (X11; Linux x86_64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/139.0.0.0 Safari/537.36"
        )

        # Set UA via profile API
        try:
            self.google_imported_profile.setHttpUserAgent(latest_chrome_ua)
            print(f"[SUCCESS] Profile User-Agent set: {latest_chrome_ua}")
        except Exception as e:
            print(f"[ERROR] Failed to set profile User-Agent: {e}")
        finally:
            # Store UA for reapplication in add_new_tab
            self.google_imported_profile._forced_user_agent = latest_chrome_ua

        # Attach a UA interceptor so *all* requests use the latest UA
        try:
            ua_interceptor = ForcedUserAgentInterceptor(latest_chrome_ua)
            self.google_imported_profile.setUrlRequestInterceptor(ua_interceptor)
            self.google_imported_profile._ua_interceptor = ua_interceptor  # Keep a reference
            print("[INFO] UA interceptor attached to imported profile.")
        except Exception as e:
            print(f"[ERROR] Could not attach UA interceptor: {e}")

        # Connect download handler
        if not hasattr(self.google_imported_profile, '_download_handler_connected_for_storm'):
            try:
                self.google_imported_profile.downloadRequested.connect(self.download_manager.handle_download)
                self.google_imported_profile._download_handler_connected_for_storm = True
                print("[INFO] Connected download handler to imported profile.")
            except Exception as e:
                print(f"[WARNING] Could not connect download handler to imported profile: {e}")

        # Ask if this profile should be used for all new tabs
        reply = QMessageBox.question(
            self,
            "Use Imported Profile?",
            "Do you want to use this profile for all new tabs?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes
        )

        self.use_imported_profile_for_new_tabs = (reply == QMessageBox.Yes)
        print(f"[INFO] Use imported profile for new tabs: {self.use_imported_profile_for_new_tabs}")
        print("[INFO] Imported Google profile setup completed.")








    def handle_accent_color_change(self, color_hex):
        """Handle accent color changes from settings"""
        self.current_accent_color = color_hex
        self.apply_accent_color_to_ui()
        self.update_url_bar_style(color_hex)

    def apply_accent_color_to_ui(self):
        """Apply current accent color to all UI components"""
        accent = self.current_accent_color
        
        # Basic stylesheet that will affect most elements
        stylesheet = f"""
            QTabBar::tab:selected {{
                border-bottom: 2px solid {accent};
            }}
            QLineEdit#url_bar {{
                border: 2px solid {accent};
                selection-background-color: {accent};
            }}
            QLineEdit#url_bar:focus {{
                border: 2px solid {self.lighten_color(accent, 20)};
            }}
            QPushButton:hover, QToolButton:hover {{
                background-color: {self.lighten_color(accent, 10)};
            }}
            QMenu::item:selected {{
                background-color: {self.lighten_color(accent, 20)};
            }}
        """
        
        # Apply the stylesheet
        self.setStyleSheet(self.styleSheet() + stylesheet)
        
        # Force refresh
        self.update()

    def lighten_color(self, hex_color, percent):
        """Lighten a color by specified percentage"""
        hex_color = hex_color.lstrip('#')
        r, g, b = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        r = min(255, r + int(255 * (percent/100)))
        g = min(255, g + int(255 * (percent/100)))
        b = min(255, b + int(255 * (percent/100)))
        return f"#{r:02x}{g:02x}{b:02x}"

    def update_url_bar_style(self, accent_color):
        """Update URL bar styling with accent color"""
        url_bar_style = f"""
            QLineEdit {{
                border: 2px solid {accent_color};
                border-radius: 15px;
                padding: 8px;
                background: {'#252525' if self.settings_manager.get("dark_mode") else '#ffffff'};
                color: {'#f0f0f0' if self.settings_manager.get("dark_mode") else '#000000'};
                selection-background-color: {accent_color};
                font-size: 14px;
                margin: 0 5px;
            }}
            QLineEdit:focus {{
                border: 2px solid {self.lighten_color(accent_color, 20)};
                background: {'#353535' if self.settings_manager.get("dark_mode") else '#f8f8f8'};
            }}
        """
        self.url_bar.setStyleSheet(url_bar_style)



    def setup_url_launcher_shortcut(self):
        """Setup Ctrl+L to launch URL dialog"""
        self.url_launcher_shortcut = QShortcut(QKeySequence("Ctrl+L"), self)
        self.url_launcher_shortcut.activated.connect(self.launch_url_prompt)
        self.shortcuts.append(self.url_launcher_shortcut)  # Add to shortcuts list for management





    def _init_autocomplete_system(self):
        """Initialize autocomplete cache"""
        self._autocomplete_cache = set()  # Using set to avoid duplicates
        
        # Add common domains
        common_domains = [
            'google.com', 'youtube.com', 'facebook.com', 
            'twitter.com', 'wikipedia.org', 'github.com'
        ]
        for domain in common_domains:
            self._autocomplete_cache.add(domain)
        
        # Add from bookmarks
        bookmarks = self.bookmark_manager.get_all_bookmarks()
        for bookmark in bookmarks:
            url = bookmark.get('url', '')
            if url:
                parsed = QUrl(url)
                if parsed.isValid():
                    domain = parsed.host()
                    if domain:
                        self._autocomplete_cache.add(domain)
        
        # Add from history
        history = self.history_manager.get_history()
        for entry in history:
            url = entry.get('url', '')
            if url:
                parsed = QUrl(url)
                if parsed.isValid():
                    domain = parsed.host()
                    if domain:
                        self._autocomplete_cache.add(domain)




    def keyPressEvent(self, event):
        """Handle keyboard shortcuts"""
        # Handle Ctrl+Enter for autocomplete
        if (event.key() in (Qt.Key_Return, Qt.Key_Enter) and 
            event.modifiers() & Qt.ControlModifier):
            self.handle_ctrl_enter()
        else:
            super().keyPressEvent(event)

    def setup_ctrl_enter_shortcut(self):
        """Setup Ctrl+Enter for URL autocompletion"""
        self.ctrl_enter_shortcut = QShortcut(QKeySequence("Ctrl+Return"), self)
        self.ctrl_enter_shortcut.activated.connect(self.handle_ctrl_enter)
        
    def handle_ctrl_enter(self):
        """Handle Ctrl+Enter in the address bar"""
        if hasattr(self, 'url_bar') and self.url_bar.hasFocus():
            # Get the current URL from the bar
            url = self.url_bar.text().strip()
            if url:
                # Call auto_complete_and_navigate with the URL
                self.auto_complete_and_navigate(url)
        else:
            # Fallback behavior if URL bar doesn't have focus
            self.url_bar.setFocus()
            self.url_bar.selectAll() 





    def auto_complete_and_navigate(self, url):
        """
        Intelligently auto-complete URL or perform search using configured search engine
        Always uses HTTPS with comprehensive error handling for WGU.edu and other sites
        """
        if not url:
            return

        # Normalize the URL
        original_url = url.strip()
        normalized_url = original_url.lower()
        
        # Special case handling for WGU
        if 'wgu.edu' in normalized_url.replace('www.', ''):
            wgu_url = 'https://www.wgu.edu' if not normalized_url.startswith(('http://', 'https://')) else original_url
            wgu_url = wgu_url.replace('http://', 'https://')  # Force HTTPS
            if browser := self.current_browser():
                browser.setUrl(QUrl(wgu_url))
                self.url_bar.setText(wgu_url)
                
                # Set up load verification
                QTimer.singleShot(5000, lambda: self.verify_load_success(browser, wgu_url))
                return
        
        # Check if URL is complete
        if '://' in normalized_url or any(tld in normalized_url for tld in ['.com', '.org', '.net', '.io', '.gov', '.edu']):
            # Force HTTPS protocol
            if '://' not in normalized_url:
                final_url = f'https://{original_url}'
            else:
                final_url = original_url.replace('http://', 'https://')
            
            if browser := self.current_browser():
                browser.setUrl(QUrl(final_url))
                self.url_bar.setText(final_url)
                QTimer.singleShot(5000, lambda: self.verify_load_success(browser, final_url))
            return
        
        # Search query detection
        def is_search_query(query):
            return (' ' in query or 
                    not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/.*)?$', query))
        
        if is_search_query(original_url):
            search_engine_url = self.settings_manager.get("search_engine", "https://www.google.com/search?q={}")
            search_url = search_engine_url.format(urllib.parse.quote(original_url))
            if browser := self.current_browser():
                browser.setUrl(QUrl(search_url))
                self.url_bar.setText(search_url)
            return
        
        # URL completion (always HTTPS)
        if not original_url.startswith(('http://', 'https://')):
            if '.' in original_url:
                final_url = f'https://{original_url}'
            else:
                final_url = f'https://{original_url}.com'
        
        if browser := self.current_browser():
            browser.setUrl(QUrl(final_url))
            self.url_bar.setText(final_url)
            QTimer.singleShot(5000, lambda: self.verify_load_success(browser, final_url))

    def verify_load_success(self, browser, attempted_url):
        """Verify if page loaded successfully, handle failures"""
        if not browser.url().isValid() or browser.url().isEmpty() or browser.url().toString().startswith('about:blank'):
            print(f"Failed to load {attempted_url}")

            # Special handling for WGU
            if 'wgu.edu' in attempted_url.lower():
                # Try alternative WGU URLs
                alternatives = [
                    'https://my.wgu.edu',
                    'https://portal.wgu.edu',
                    'https://wgu.edu'
                ]

                for alt_url in alternatives:
                    print(f"Trying alternative URL: {alt_url}")
                    browser.setUrl(QUrl(alt_url))
                    if not browser.url().isEmpty():
                        self.url_bar.setText(alt_url)
                        return

            # Final fallback to search
            search_url = f"https://www.google.com/search?q={urllib.parse.quote(attempted_url)}"
            print(f"Falling back to search URL: {search_url}")
            browser.setUrl(QUrl(search_url))
            self.url_bar.setText(search_url)














    def get_current_search_engine(self):
        """
        Return the base URL for the current search engine
        """
        # Dictionary of search engines
        search_engines = {
            'DuckDuckGo': 'https://duckduckgo.com/html/?q=',
            'Google': 'https://www.google.com/search?q=',
            'Bing': 'https://www.bing.com/search?q=',
            # Add more search engines as needed
        }
        
        # Try to get from settings, default to DuckDuckGo
        try:
            # Assuming you have a method or attribute to store current search engine
            current_engine = getattr(self, '_current_search_engine', 'DuckDuckGo')
            return search_engines.get(current_engine, search_engines['DuckDuckGo'])
        except Exception:
            # Fallback to DuckDuckGo if anything goes wrong
            return search_engines['DuckDuckGo']

    def set_search_engine(self, engine_name):
        """
        Set the current search engine
        """
        search_engines = ['DuckDuckGo', 'Google', 'Bing']
        
        if engine_name in search_engines:
            # Store the selected search engine
            self._current_search_


    def on_url_completer_activated(self, text):
        """Handle when a completer suggestion is selected"""
        # Directly navigate to the selected URL without search
        self.navigate_to_url(text)




    def navigate_to_url(self, url=None):
        """
        Navigate to URL with better handling of autocomplete selections
        """
        if url is None:
            url = self.url_bar.text().strip()
        
        if not url:
            return
        
        # If URL is already complete (has scheme or known TLD), navigate directly
        if (url.startswith(('http://', 'https://', 'ftp://')) or
            any(tld in url.lower() for tld in ['.com', '.org', '.net', '.io', '.gov', '.edu'])):
            if browser := self.current_browser():
                browser.setUrl(QUrl(url))
            return
        
        # Otherwise, treat as search
        search_engine_url = self.settings_manager.get("search_engine", "https://www.google.com/search?q={}")
        search_url = search_engine_url.format(urllib.parse.quote(url))
        if browser := self.current_browser():
            browser.setUrl(QUrl(search_url))



    def launch_url_prompt(self):
        """Launch URL dialog when Ctrl+L is pressed"""
        current_browser = self.current_browser()
        current_url = current_browser.url().toString() if current_browser else ""
        
        dialog = UrlLauncherDialog(self, current_url=current_url)
        if dialog.exec_() == QDialog.Accepted:
            # Either access the URL directly from the input field
            url = dialog.url_input.text().strip()
            # Or use the get_url() method (both will work now)
            # url = dialog.get_url()
            
            if url:
                self.navigate_to_url(url)

    def show_error_dialog(self, message):
        """Display an error dialog to the user"""
        from PyQt5.QtWidgets import QMessageBox
        error_dialog = QMessageBox()
        error_




# In your BrowserMainWindow.__init__() or setup_ui() method:
        self.tab_widget.setStyleSheet("""
            QTabWidget::pane {
                border: none;
                top: -1px;
                background-color: #1e1e1e;
            }

            QTabBar {
                background: transparent;
            }

            QTabBar::tab {
                background: #2b2b2b;
                color: #dcdcdc;
                padding: 6px 10px;
                border: 1px solid #444;
                border-bottom: 3px solid blue;
                border-left-radius: 1px;
                border-right-radius: 1px;
                margin-right: 0px;
            }

            QTabBar::tab:selected {
                background: #1e1e1e;
                color: white;
                font-weight: bold;
                border-bottom: 2px solid yellow;
                border-left: 0px solid yellow;
                border-right: 0px solid yellow;
            }

            QTabBar::tab:hover {
                background: #3a3a3a;
            }

            QTabBar::tab[is-incognito="true"] {
                background-color: #3a3a3a;
                color: red;
                font-weight: bold;
            }

            QTabBar::tab[is-incognito="true"]:hover {
                background-color: #555555;
            }
        """)



#_____________________________________________________________

# Add these methods to BrowserMainWindow class

    def setup_find_bar(self):
        """Setup the find bar widget with case options and a label for found items count."""
        self.find_bar = QWidget()
        self.find_bar.setObjectName("findBar")
        find_layout = QHBoxLayout(self.find_bar)
        find_layout.setContentsMargins(5, 2, 5, 2)
        find_layout.setSpacing(5)

        # Find input field
        self.find_line_edit = QLineEdit()
        self.find_line_edit.setPlaceholderText("Find in page...")
        self.find_line_edit.setMinimumWidth(200)
        self.find_line_edit.textChanged.connect(self.perform_find)  # Connect to perform_find on text change

        # Case sensitivity toggle
        self.case_checkbox = QCheckBox("Aa")
        self.case_checkbox.setToolTip("Case sensitive search")

        # Next/Previous buttons
        self.next_btn = QPushButton("▶")
        self.prev_btn = QPushButton("◀")
        for btn in [self.prev_btn, self.next_btn]:
            btn.setFixedSize(28, 28)

        self.next_btn.clicked.connect(lambda: self.perform_find(next=True))
        self.prev_btn.clicked.connect(lambda: self.perform_find(next=False, backward=True))

        # Close button
        self.find_close_btn = QPushButton("×")
        self.find_close_btn.setFixedSize(25, 25)
        self.find_close_btn.clicked.connect(self.hide_find_bar)

        # Label to display the count of found items
        self.find_count_label = QLabel("0/0")
        self.find_count_label.setFixedWidth(50)
        self.find_count_label.setAlignment(Qt.AlignCenter)

        # Add widgets to layout
        find_layout.addWidget(self.find_line_edit)
        find_layout.addWidget(self.case_checkbox)
        find_layout.addWidget(self.prev_btn)
        find_layout.addWidget(self.next_btn)
        find_layout.addWidget(self.find_count_label)
        find_layout.addWidget(self.find_close_btn)

        # Add find bar to main window layout (at the bottom)
        if hasattr(self, 'main_layout'):
            self.main_layout.addWidget(self.find_bar)
        else:
            # Fallback if main_layout isn't available
            central = self.centralWidget()
            if central:
                central.layout().addWidget(self.find_bar)

        self.find_bar.hide()

        # Apply styling
        self.update_find_bar_style()

    def perform_find(self, next=False, backward=False):
        """Perform text search in current page and update the count label."""
        if not hasattr(self, 'find_line_edit'):
            return

        text = self.find_line_edit.text()
        if not text:
            self.find_count_label.setText("0/0")
            return

        flags = QWebEnginePage.FindFlags()
        if self.case_checkbox.isChecked():
            flags |= QWebEnginePage.FindCaseSensitively
        if backward:
            flags |= QWebEnginePage.FindBackward

        if browser := self.current_browser():
            # Use JavaScript to count the occurrences of the text
            script = f"""
            var regex = new RegExp('{text}', 'g');
            var bodyText = document.body.innerText;
            var matches = bodyText.match(regex);
            matches ? matches.length : 0;
            """
            browser.page().runJavaScript(script, lambda result: self.update_find_count_label(result, text, flags))

    def update_find_count_label(self, total_count, text, flags):
        """Update the find count label with the total count of found items."""
        if browser := self.current_browser():
            # Highlight the first occurrence
            browser.page().findText(text, flags)
        self.find_count_label.setText(f"1/{total_count}")





    def get_total_found_count(self, text, flags):
        """Placeholder method to get the total count of found items."""
        # Implement the logic to count the total occurrences of the text
        # This is a simplified example and may not work as expected
        if browser := self.current_browser():
            # This is a mock implementation
            # You need to replace it with actual logic to count occurrences
            return 10  # Mock count
        return 0


    def update_find_bar_style(self):
        """Update find bar styling based on current theme"""
        dark_mode = self.settings_manager.get("dark_mode", True)
        accent_color = self.settings_manager.get("theme", {}).get("accent_color", "#3daee9")
        
        if dark_mode:
            self.find_bar.setStyleSheet(f"""
                QWidget#findBar {{
                    background-color: #3a3a3a;
                    border-top: 1px solid #555;
                }}
                QLineEdit {{
                    background-color: #2c2c2c;
                    color: #ffffff;
                    border: 1px solid #555;
                    padding: 4px;
                    border-radius: 4px;
                }}
                QLineEdit::placeholder {{
                    color: #aaaaaa;
                }}
                QCheckBox {{
                    color: white;
                }}
                QPushButton {{
                    border: none;
                    background-color: #444;
                    color: white;
                    padding: 2px;
                }}
                QPushButton:hover {{
                    background-color: #666;
                }}
                QPushButton#find_close_btn {{
                    font-weight: bold;
                    background-color: transparent;
                    color: #ccc;
                }}
                QPushButton#find_close_btn:hover {{
                    color: red;
                }}
            """)
        else:
            self.find_bar.setStyleSheet(f"""
                QWidget#findBar {{
                    background-color: #f0f0f0;
                    border-top: 1px solid #ccc;
                }}
                QLineEdit {{
                    background-color: white;
                    color: black;
                    border: 1px solid #aaa;
                    padding: 4px;
                    border-radius: 4px;
                }}
                QLineEdit::placeholder {{
                    color: #666;
                }}
                QCheckBox {{
                    color: black;
                }}
                QPushButton {{
                    border: none;
                    background-color: #ddd;
                    color: black;
                    padding: 2px;
                }}
                QPushButton:hover {{
                    background-color: #ccc;
                }}
                QPushButton#find_close_btn {{
                    font-weight: bold;
                    background-color: transparent;
                    color: #666;
                }}
                QPushButton#find_close_btn:hover {{
                    color: red;
                }}
            """)






    def setup_find_shortcut(self):
        """Setup the Ctrl+F shortcut to toggle the find bar."""
        try:
            find_shortcut = self.get_shortcut("find")
            if find_shortcut:
                self._create_shortcut(find_shortcut, self.toggle_find_bar)
            else:
                QShortcut(QKeySequence("Ctrl+F"), self, self.toggle_find_bar)
            print("Ctrl+F shortcut set up")  # Debug print
        except Exception as e:
            print(f"Error setting up find shortcut: {e}")

    def toggle_find_bar(self):
        """Toggle the visibility of the find bar."""
        print("toggle_find_bar called")  # Debug print
        if hasattr(self, 'find_bar'):
            if self.find_bar.isVisible():
                self.hide_find_bar()
            else:
                self.show_find_bar()
        else:
            self.setup_find_bar()
            self.show_find_bar()

    def show_find_bar(self):
        """Display the find bar widget."""
        print("show_find_bar called")  # Debug print
        if not hasattr(self, 'find_bar'):
            self.setup_find_bar()

        self.find_bar.show()
        self.find_line_edit.setFocus()
        self.find_line_edit.selectAll()

    def hide_find_bar(self):
        """Hide the find bar and clear search highlights."""
        print("hide_find_bar called")  # Debug print
        if hasattr(self, 'find_bar') and self.find_bar:
            self.find_bar.hide()
            if browser := self.current_browser():
                browser.page().findText("")  # Clear search highlights














    def handle_accent_color_change(self, color_hex):
        """Handle accent color changes from settings"""
        self.current_accent_color = color_hex
        self.apply_accent_color_to_ui()
        self.update_url_bar_style(color_hex)
        if hasattr(self, 'find_bar'):
            self.update_find_bar_style()





















    def get_current_browser(self):
        """Return the current QWebEngineView from the active tab."""
        if hasattr(self, 'tab_widget'):
            current_tab = self.tab_widget.currentWidget()
            if current_tab:
                browser = current_tab.findChild(QWebEngineView)
                if browser:
                    print("Current browser instance retrieved successfully")
                    return browser
                else:
                    print("No browser instance found in the current tab")
        else:
            print("Tab widget not found")
        return None

    def get_shortcut(self, name):
        """Get shortcut for a given action name."""
        if hasattr(self, 'settings_manager'):
            return self.settings_manager.get_shortcut(name)
        if hasattr(self, 'settings') and 'shortcuts' in self.settings:
            return self.settings['shortcuts'].get(name, '')
        return ''



#_______________________________________________________________




    def update_url_bar_style(self, accent_color):
        """Update URL bar styling with accent color"""
        url_bar_style = f"""
            QLineEdit {{
                border: 2px solid {accent_color};
                border-radius: 15px;
                padding: 8px;
                background: {self.get_url_bar_bg_color()};
                color: {self.get_url_bar_text_color()};
                selection-background-color: {accent_color};
                font-size: 14px;
                margin: 0 5px;
            }}
            QLineEdit:focus {{
                border: 2px solid {self.lighten_color(accent_color, 20)};
                background: {self.get_url_bar_focus_bg_color()};
            }}
        """
        self.url_bar.setStyleSheet(url_bar_style)

    def update_nav_buttons_style(self, accent_color):
        """Update navigation buttons to match accent color"""
        button_style = f"""
            QToolButton {{
                border: 1px solid {accent_color};
                border-radius: 5px;
                padding: 5px;
                background: {self.get_toolbar_bg_color()};
                margin: 0 2px;
            }}
            QToolButton:hover {{
                background: {self.lighten_color(accent_color, 10)};
            }}
            QToolButton:pressed {{
                background: {accent_color};
            }}
        """
        for btn in [self.back_btn, self.forward_btn, self.refresh_btn, self.home_btn]:
            btn.setStyleSheet(button_style)

    def lighten_color(self, hex_color, percent):
        """Lighten a color by specified percentage"""
        hex_color = hex_color.lstrip('#')
        r, g, b = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        r = min(255, r + int(255 * (percent/100)))
        g = min(255, g + int(255 * (percent/100)))
        b = min(255, b + int(255 * (percent/100)))
        return f"#{r:02x}{g:02x}{b:02x}"

    def get_url_bar_bg_color(self):
        """Get URL bar background color based on theme"""
        if self.settings_manager.get("dark_mode"):
            return self.settings_manager.get("dark_theme", {}).get("base_color", "#2d2d2d")
        return "#ffffff"

    def get_url_bar_text_color(self):
        """Get URL bar text color based on theme"""
        if self.settings_manager.get("dark_mode"):
            return self.settings_manager.get("dark_theme", {}).get("text_color", "#f0f0f0")
        return "#000000"

    def get_url_bar_focus_bg_color(self):
        """Get URL bar focus background color based on theme"""
        if self.settings_manager.get("dark_mode"):
            return self.settings_manager.get("dark_theme", {}).get("window_color", "#252525")
        return "#f8f8f8"

    def get_toolbar_bg_color(self):
        """Get toolbar background color based on theme"""
        if self.settings_manager.get("dark_mode"):
            return self.settings_manager.get("dark_theme", {}).get("button_color", "#3a3a3a")
        return "#f0f0f0"

    def apply_tab_style(self):
        """Apply consistent tab styling"""
        accent_color = self.settings_manager.get("theme", {}).get("accent_color", "#3daee9")
        tab_style = f"""
            QTabWidget::pane {{
                border: none;
                top: -1px;
                background: {self.get_url_bar_bg_color()};
            }}
            QTabBar::tab {{
                background: {self.get_toolbar_bg_color()};
                color: {self.get_url_bar_text_color()};
                padding: 8px;
                border: 1px solid {accent_color};
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                margin-right: 2px;
            }}
            QTabBar::tab:selected {{
                background: {self.get_url_bar_bg_color()};
                border-bottom: 2px solid {accent_color};
            }}
            QTabBar::tab:hover {{
                background: {self.lighten_color(accent_color, 10)};
            }}
        """
        self.tab_widget.setStyleSheet(tab_style)





    def keyPressEvent(self, event):
        """Handle key press events, including the Escape key to exit full-screen mode."""
        if event.key() == Qt.Key_Escape:
            # Check if any browser is in full-screen mode
            current_browser = self.current_browser()
            if current_browser:
                # Execute JavaScript to exit full-screen mode
                current_browser.page().runJavaScript(
                    """
                    if (document.fullscreenElement) {
                        document.exitFullscreen();
                    } else if (document.webkitFullscreenElement) {
                        document.webkitExitFullscreen();
                    } else if (document.msFullscreenElement) {
                        document.msExitFullscreen();
                    }
                    """
                )
                return

        # Call the base class method to handle other key events
        super().keyPressEvent(event)



    def handle_fullscreen_request(self, request):
        """Handle full-screen requests from the QWebEngineView."""
        if request.toggleOn():
            # Enter full-screen mode
            self.fullscreen_window = QMainWindow()
            self.fullscreen_window.setWindowFlags(Qt.Window | Qt.FramelessWindowHint)
            self.fullscreen_window.setCentralWidget(self.current_browser())
            self.fullscreen_window.showFullScreen()
            request.accept()
        else:
            # Exit full-screen mode
            if hasattr(self, 'fullscreen_window') and self.fullscreen_window:
                self.fullscreen_window.close()
                self.fullscreen_window.deleteLater()
                self.fullscreen_window = None
            request.accept()

    # Connect the fullScreenRequested signal to the handler
    def setup_browser_signals(self, browser):
        """Connect signals for the browser."""
        browser.page().fullScreenRequested.connect(self.handle_fullscreen_request)



    def set_current_browser_focus(self):
        """Set focus to the current browser."""
        current_widget = self.tab_widget.currentWidget()
        if current_widget and hasattr(current_widget, 'browser'):
            current_widget.browser.setFocus()

    


    def on_recording_timeout(self):
        """Handle recording timeout - reset UI to initial state."""
        self.record_btn.setText("⏺")  # Reset to record icon
        self.record_btn.show()
        self.stop_recording_btn.hide()
        self.status_bar.showMessage("Recording stopped (timeout reached)", 3000)


    def apply_recorder_theme(self):
        """Apply current theme to screen recorder controls"""
        if self.settings_manager.get("dark_mode"):
            theme = self.settings_manager.get("dark_theme")
            base_color = theme["base_color"]
            text_color = theme["text_color"]
            button_color = theme["button_color"]
            highlight_color = theme["highlight_color"]
            
            self.record_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {button_color};
                    color: {text_color};
                    border: 1px solid {highlight_color};
                    border-radius: 4px;
                    padding: 5px;
                    min-width: 30px;
                }}
                QPushButton:hover {{
                    background-color: {highlight_color};
                }}
            """)
            
            self.stop_recording_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: #ff4545;
                    color: white;
                    border: 1px solid #ff0000;
                    border-radius: 4px;
                    padding: 5px;
                    min-width: 30px;
                }}
                QPushButton:hover {{
                    background-color: #ff6b6b;
                }}
            """)
            
            # Apply to recording status widget
            if hasattr(self, 'recording_status_widget'):
                self.recording_status_widget.setStyleSheet(f"""
                    QWidget {{
                        background-color: {base_color};
                        color: {text_color};
                        padding: 2px 5px;
                        border: 1px solid {highlight_color};
                        border-radius: 3px;
                    }}
                    QLabel {{
                        color: {text_color};
                    }}
                """)
                
                # Specific label colors
                self.elapsed_label.setStyleSheet("color: #ff4545; font-weight: bold;")
                self.countdown_label.setStyleSheet("color: #45a1ff; font-weight: bold;")
        else:
            # Light theme
            self.record_btn.setStyleSheet("""
                QPushButton {
                    background-color: #f0f0f0;
                    color: black;
                    border: 1px solid #c0c0c0;
                    border-radius: 4px;
                    padding: 5px;
                    min-width: 30px;
                }
                QPushButton:hover {
                    background-color: #e0e0e0;
                }
            """)
            
            self.stop_recording_btn.setStyleSheet("""
                QPushButton {
                    background-color: #ff4545;
                    color: white;
                    border: 1px solid #ff0000;
                    border-radius: 4px;
                    padding: 5px;
                    min-width: 30px;
                }
                QPushButton:hover {
                    background-color: #ff6b6b;
                }
            """)
            
            if hasattr(self, 'recording_status_widget'):
                self.recording_status_widget.setStyleSheet("""
                    QWidget {
                        background-color: #f0f0f0;
                        color: black;
                        padding: 2px 5px;
                        border: 1px solid #c0c0c0;
                        border-radius: 3px;
                    }
                """)
                
                # Light theme label colors
                self.elapsed_label.setStyleSheet("color: #d00000; font-weight: bold;")
                self.countdown_label.setStyleSheet("color: #0066cc; font-weight: bold;")





    def handle_recording_stats(self, status_message):
        """Handle recording status updates with file size info."""
        # Only update if we're currently recording
        if self.screen_recorder.is_recording_active():
            current_msg = self.status_bar.currentMessage()
            if "Recording" in current_msg:  # If we already have a recording message
                # Keep the existing message but update the size part
                parts = current_msg.rsplit(" - ", 1)
                if len(parts) == 2:
                    self.status_bar.showMessage(f"{parts[0]} - {status_message}", 1000)
            else:
                self.status_bar.showMessage(status_message, 1000)


    def show_recording_control_panel(self):
        """Show a modern, sleek popup dialog with screen recording options."""
        # Initialize dialog with popup properties
        self.control_panel = QDialog(self)
        self.control_panel.setWindowTitle("Screen Recording Settings")
        self.control_panel.setWindowFlags(Qt.Popup | Qt.FramelessWindowHint)
        self.control_panel.setAttribute(Qt.WA_TranslucentBackground)
        self.control_panel.setFixedSize(400, 550)  # Increased size for a more modern look

        self.control_panel.setStyleSheet("""
            QDialog {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #1e1e2d, stop:1 #2d2d3a);
                border: 2px solid #4a4a68;
                border-radius: 15px;
            }
            QGroupBox {
                color: #cacae0;
                border: 1px solid #4a4a68;
                border-radius: 10px;
                margin-top: 0px;
                padding-top: 12px;
                font-weight: bold;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #2a2a3a, stop:1 #3a3a4a);
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 5px;
            }
            QRadioButton, QCheckBox {
                color: #cacae0;
                padding: 2px;
                spacing: 5px;
            }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #5a5a8a, stop:1 #4a4a68);
                color: white;
                border: none;
                border-radius: 10px;
                padding: 10px;
                min-width: 120px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #6a6a9a, stop:1 #5a5a8a);
            }
            QSpinBox, QSlider {
                border: 1px solid #4a4a68;
                background: #2a2a3a;
                color: #cacae0;
                border-radius: 5px;
            }
            QLabel {
                color: #cacae0;
            }
        """)

        # Main layout with reduced spacing and margins
        main_layout = QVBoxLayout(self.control_panel)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(5)

        # Recording Type Section
        type_group = QGroupBox("Recording Type")
        type_layout = QVBoxLayout()
        type_layout.setSpacing(2)

        self.fullscreen_radio = QRadioButton("Full Screen")
        self.window_radio = QRadioButton("Application Window")
        self.region_radio = QRadioButton("Custom Region")
        self.fullscreen_radio.setChecked(True)

        # Region coordinates controls
        region_coords = QWidget()
        coords_layout = QHBoxLayout()
        coords_layout.setSpacing(2)
        for label in ["X:", "Y:", "W:", "H:"]:
            coords_layout.addWidget(QLabel(label))
            spin = QSpinBox()
            spin.setRange(0, 9999)
            spin.setSuffix(" px")
            spin.setEnabled(False)
            setattr(self, f"region_{label.lower().replace(':', '')}", spin)
            coords_layout.addWidget(spin)
        region_coords.setLayout(coords_layout)
        region_coords.hide()

        self.region_radio.toggled.connect(region_coords.setVisible)

        type_layout.addWidget(self.fullscreen_radio)
        type_layout.addWidget(self.window_radio)
        type_layout.addWidget(self.region_radio)
        type_layout.addWidget(region_coords)
        type_group.setLayout(type_layout)
        main_layout.addWidget(type_group)

        # Duration Section
        duration_group = QGroupBox("Duration")
        duration_layout = QVBoxLayout()
        duration_layout.setSpacing(2)

        self.duration_spin = QSpinBox()
        self.duration_spin.setRange(0, 240)
        self.duration_spin.setValue(0)
        self.duration_spin.setSuffix(" min")

        self.time_preview = QLabel("Unlimited Recording")
        self.time_preview.setStyleSheet("font-style: italic;")
        self.duration_spin.valueChanged.connect(lambda: self.time_preview.setText(
            f"Recording for {self.duration_spin.value()} min" if self.duration_spin.value() > 0 else "Unlimited Recording"
        ))

        duration_layout.addWidget(self.duration_spin)
        duration_layout.addWidget(self.time_preview)
        duration_group.setLayout(duration_layout)
        main_layout.addWidget(duration_group)

        # Audio Options
        audio_group = QGroupBox("Audio")
        audio_layout = QVBoxLayout()
        audio_layout.setSpacing(2)

        self.mic_check = QCheckBox("Microphone")
        self.system_check = QCheckBox("System Audio")
        self.mic_check.setChecked(True)
        self.system_check.setChecked(True)

        # Volume sliders
        mic_volume_layout = QHBoxLayout()
        mic_volume_layout.addWidget(QLabel("Mic:"))
        self.mic_volume = QSlider(Qt.Horizontal)
        self.mic_volume.setRange(0, 100)
        self.mic_volume.setValue(80)
        mic_volume_layout.addWidget(self.mic_volume)

        system_volume_layout = QHBoxLayout()
        system_volume_layout.addWidget(QLabel("Sys:"))
        self.system_volume = QSlider(Qt.Horizontal)
        self.system_volume.setRange(0, 100)
        self.system_volume.setValue(80)
        system_volume_layout.addWidget(self.system_volume)

        audio_layout.addWidget(self.mic_check)
        audio_layout.addLayout(mic_volume_layout)
        audio_layout.addWidget(self.system_check)
        audio_layout.addLayout(system_volume_layout)
        audio_group.setLayout(audio_layout)
        main_layout.addWidget(audio_group)

        # Quality Section
        quality_group = QGroupBox("Quality")
        quality_layout = QHBoxLayout()
        quality_layout.setSpacing(5)

        self.quality_low = QRadioButton("Low")
        self.quality_med = QRadioButton("Medium")
        self.quality_high = QRadioButton("High")
        self.quality_med.setChecked(True)

        quality_layout.addWidget(self.quality_low)
        quality_layout.addWidget(self.quality_med)
        quality_layout.addWidget(self.quality_high)
        quality_group.setLayout(quality_layout)
        main_layout.addWidget(quality_group)

        # Start Button
        self.start_recording_btn = QPushButton("Start Recording")
        self.start_recording_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #8a5af0, stop:1 #6a3af0);
                color: white;
                border: none;
                border-radius: 10px;
                padding: 10px;
                min-width: 120px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #9a7af0, stop:1 #7a5af0);
            }
        """)
        self.start_recording_btn.clicked.connect(lambda: (
            self._start_from_panel(),
            self.control_panel.close()
        ))

        main_layout.addWidget(self.start_recording_btn)

        # Position near record button
        pos = self.record_btn.mapToGlobal(QPoint(0, 0))
        self.control_panel.move(
            pos.x() - self.control_panel.width() // 2 + self.record_btn.width() // 2,
            pos.y() + self.record_btn.height() + 5
        )

        self.control_panel.exec_()




    def _start_from_panel(self):
        """Start recording based on panel selections."""
        duration = self.duration_spin.value() * 60  # Convert to seconds
        include_mic = self.mic_check.isChecked()
        include_system = self.system_check.isChecked()

        if self.quality_low.isChecked():
            quality = 0
        elif self.quality_high.isChecked():
            quality = 2
        else:
            quality = 1  # Medium

        if self.fullscreen_radio.isChecked():
            self.start_recording(
                max_duration_minutes=duration // 60,
                include_mic=include_mic,
                include_speaker=include_system,
                quality=quality
            )
        elif self.window_radio.isChecked():
            self._select_window_and_record(duration, include_mic, include_system, quality)
        elif self.region_radio.isChecked():
            self._select_region_and_record(duration, include_mic, include_system, quality)

        self.control_panel.accept()




    def _start_or_stop_recording(self):
        if self.screen_recorder.is_recording():
            self.screen_recorder.stop_recording()
            self.start_stop_btn.setText("Start Recording")
        else:
            # Get selected options
            duration = self.duration_spin.value() * 60  # Convert to seconds
            include_mic = self.mic_check.isChecked()
            include_system = self.system_audio_check.isChecked()

            if self.quality_low.isChecked():
                quality = 0
            elif self.quality_high.isChecked():
                quality = 2
            else:
                quality = 1  # Medium

            if self.fullscreen_radio.isChecked():
                success = self.screen_recorder.start_recording(
                    max_duration_minutes=duration // 60,
                    include_mic=include_mic,
                    include_speaker=include_system,
                    quality=quality
                )
            elif self.window_radio.isChecked():
                self._select_window_and_record(duration, include_mic, include_system, quality)
            elif self.region_radio.isChecked():
                self._select_region_and_record(duration, include_mic, include_system, quality)

            if not success:
                self.status_bar.showMessage("Failed to start recording", 3000)
            else:
                self.start_stop_btn.setText("Stop Recording")





    def on_recording_error(self, error_msg):
        """Handle recording errors"""
        self.status_bar.showMessage(error_msg, 5000)
        self.notification_manager.show_notification("Recording Error", error_msg, 5000)

    def handle_recording_status(self, message):
        """Handle recording status updates"""
        self.status_bar.showMessage(message, 3000)  # Show for 3 seconds
        if "started" in message.lower():
            self.record_btn.setText("⏹")  # Change button to stop icon
            self.stop_recording_btn.show()
            self.record_btn.hide()


    def on_recording_progress(self, filename, elapsed_secs, total_secs):
        """Update UI with recording duration and file size."""
        # Format duration
        duration_str = format_time(elapsed_secs)
        
        # Get file size if file exists
        size_str = "Calculating..."
        if os.path.exists(filename):
            size = os.path.getsize(filename)
            size_str = format_size(size)
        
        # Update status bar
        self.status_bar.showMessage(
            f"Recording {os.path.basename(filename)} - {duration_str} - Size: {size_str}", 
            1000  # Show for 1 second (will refresh)
        )

    def update_recording_size(self):
        """Update the file size display during recording"""
        if self.screen_recorder.is_recording_active():
            filename = self.screen_recorder.get_current_recording_file()
            if filename and os.path.exists(filename):
                size = os.path.getsize(filename)
                if size != self.last_file_size:
                    self.last_file_size = size
                    size_str = format_size(size)
                    current_msg = self.status_bar.currentMessage()
                    if current_msg:
                        # Update just the size part of the message
                        parts = current_msg.rsplit(" | ", 1)
                        if len(parts) == 2:
                            self.status_bar.showMessage(f"{parts[0]} | Size: {size_str}", 1000)

    def on_recording_started(self, filename):
        """Handle recording started event"""
        self.recording_size_timer.start(1000)  # Update size every second
        self.status_bar.showMessage(f"Recording started: {os.path.basename(filename)}", 3000)
        # Show the stop button and hide the record button
        self.record_btn.hide()
        self.stop_recording_btn.show()


        
        # Restore button states
        self.stop_recording_btn.hide()
        self.record_btn.show()
        
        self.status_bar.showMessage(msg, 3000)

    def stop_recording(self):
        """Stop the current recording"""
        if self.screen_recorder.is_recording_active():
            self.screen_recorder.stop_recording()


    def on_recording_progress(self, filename, elapsed_secs, total_secs, elapsed_str, remaining_str, size_str, bitrate_str):
        """Handle recording progress updates with all stats"""
        self.elapsed_label.setText(f"⏱ {elapsed_str}")
        self.countdown_label.setText(f"⏳ {remaining_str}" if remaining_str != "Unlimited" else "⏳ ∞")
        self.size_label.setText(f"📁 {size_str}")
        self.bitrate_label.setText(f"🔊 {bitrate_str}" if bitrate_str else "")
        
        # Update status bar message periodically
        if elapsed_secs % 5 == 0:
            self.status_bar.showMessage(
                f"Recording {os.path.basename(filename)} - "
                f"Elapsed: {elapsed_str} | Remaining: {remaining_str} | "
                f"Size: {size_str}{' | ' + bitrate_str if bitrate_str else ''}",
                1000
            )


    def update_countdown(self):
        """Update countdown timer and stop recording if time runs out."""
        if self.remaining_time > 0:
            self.remaining_time -= 1
            elapsed_str = self._format_time(time.time() - self.start_time)
            remaining_str = self._format_time(self.remaining_time)

            message = f"Elapsed: {elapsed_str} | Remaining: {remaining_str}"
            self.status_bar.showMessage(message, 1000)

            if hasattr(self, 'control_panel') and self.control_panel.isVisible():
                self.time_label.setText(message)
        else:
            self.countdown_timer.stop()
            self.status_bar.showMessage("Time limit reached. Stopping recording...", 3000)
            self.stop_recording()



    def format_time(self, seconds):
        """Format seconds into MM:SS"""
        return f"{int(seconds//60):02d}:{int(seconds%60):02d}"

    def on_recording_finished(self, filename, success, duration_str):
        """Clean up when recording finishes."""
        # Hide the countdown display
        self.recording_status_label.hide()
        
        # Reset UI buttons
        self.record_btn.setText("⏺")
        self.record_btn.show()
        self.stop_recording_btn.hide()
        
        # Show appropriate message
        if success:
            size = os.path.getsize(filename)
            size_str = format_size(size)
            msg = f"Recording saved: {os.path.basename(filename)} ({size_str})"
        else:
            msg = "Recording failed"
        
        self.status_bar.showMessage(msg, 3000)












    def stop_recording(self):
        """Gracefully stop recording with multiple fallback methods."""
        print("[DEBUG] Attempting to stop recording...")
        if not hasattr(self, 'recording_process') or not self.is_recording:
            print("[DEBUG] No active recording to stop")
            return False

        try:
            # Method 1: Send 'q' to stdin (graceful stop)
            self.recording_process.stdin.write(b'q')
            self.recording_process.stdin.flush()
            
            # Wait for process to terminate (5 second timeout)
            try:
                self.recording_process.wait(5)
                success = self.recording_process.returncode == 0
            except subprocess.TimeoutExpired:
                print("[WARNING] Graceful stop timed out - trying SIGTERM")
                self.recording_process.terminate()
                try:
                    self.recording_process.wait(2)
                    success = True
                except subprocess.TimeoutExpired:
                    print("[WARNING] SIGTERM failed - forcing SIGKILL")
                    self.recording_process.kill()
                    success = False

            # Verify output file
            if success:
                if not os.path.exists(self.recording_file):
                    print(f"[ERROR] Output file missing: {self.recording_file}")
                    success = False
                elif os.path.getsize(self.recording_file) < 1024:  # At least 1KB
                    print("[ERROR] Output file too small - likely corrupt")
                    success = False

            # Cleanup
            self.progress_timer.stop()
            self.is_recording = False
            self.recording_finished.emit(self.recording_file, success)
            
            if success:
                print(f"[DEBUG] Recording saved to: {self.recording_file}")
                # Open folder in file explorer (platform-specific)
                if sys.platform == "win32":
                    os.startfile(os.path.dirname(self.recording_file))
                elif sys.platform == "darwin":
                    subprocess.run(["open", os.path.dirname(self.recording_file)])
                else:
                    subprocess.run(["xdg-open", os.path.dirname(self.recording_file)])
            
            return success

        except Exception as e:
            print(f"[CRITICAL] Stop recording failed: {str(e)}")
            traceback.print_exc()
            return False








    def show_audio_settings(self):
        """Show audio settings dialog for screen recording."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Audio Settings")
        dialog.setMinimumWidth(300)
        
        layout = QVBoxLayout()
        
        # Audio source selection
        audio_group = QGroupBox("Audio Sources")
        audio_layout = QVBoxLayout()
        
        # Microphone checkbox
        self.mic_check = QCheckBox("Record Microphone")
        self.mic_check.setChecked(True)
        audio_layout.addWidget(self.mic_check)
        
        # System audio checkbox
        self.system_audio_check = QCheckBox("Record System Audio")
        self.system_audio_check.setChecked(True)
        audio_layout.addWidget(self.system_audio_check)
        
        audio_group.setLayout(audio_layout)
        layout.addWidget(audio_group)
        
        # Volume controls
        volume_group = QGroupBox("Volume Levels")
        volume_layout = QVBoxLayout()
        
        # Microphone volume slider
        mic_volume_layout = QHBoxLayout()
        mic_volume_layout.addWidget(QLabel("Mic Volume:"))
        self.mic_volume_slider = QSlider(Qt.Horizontal)
        self.mic_volume_slider.setRange(0, 100)
        self.mic_volume_slider.setValue(80)
        mic_volume_layout.addWidget(self.mic_volume_slider)
        volume_layout.addLayout(mic_volume_layout)
        
        # System volume slider
        system_volume_layout = QHBoxLayout()
        system_volume_layout.addWidget(QLabel("System Volume:"))
        self.system_volume_slider = QSlider(Qt.Horizontal)
        self.system_volume_slider.setRange(0, 100)
        self.system_volume_slider.setValue(80)
        system_volume_layout.addWidget(self.system_volume_slider)
        volume_layout.addLayout(system_volume_layout)
        
        volume_group.setLayout(volume_layout)
        layout.addWidget(volume_group)
        
        # Test buttons
        test_group = QGroupBox("Test Audio")
        test_layout = QHBoxLayout()
        
        test_mic_btn = QPushButton("Test Microphone")
        test_mic_btn.clicked.connect(self.test_microphone)
        test_layout.addWidget(test_mic_btn)
        
        test_system_btn = QPushButton("Test System Audio")
        test_system_btn.clicked.connect(self.test_system_audio)
        test_layout.addWidget(test_system_btn)
        
        test_group.setLayout(test_layout)
        layout.addWidget(test_group)
        
        # Dialog buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(dialog.accept)
        button_box.rejected.connect(dialog.reject)
        layout.addWidget(button_box)
        
        dialog.setLayout(layout)
        
        if dialog.exec_() == QDialog.Accepted:
            # Save settings
            self.settings_manager.set("recording_microphone", self.mic_check.isChecked())
            self.settings_manager.set("recording_system_audio", self.system_audio_check.isChecked())
            self.settings_manager.set("mic_volume", self.mic_volume_slider.value())
            self.settings_manager.set("system_volume", self.system_volume_slider.value())




    def test_microphone(self):
        """Play a test sound through the microphone."""
        # This would be platform-specific code to test mic
        # For now we'll just show a notification
        self.notification_manager.show_notification(
            "Microphone Test",
            "Testing microphone... Say something!",
            3000
        )

    def test_system_audio(self):
        """Play a test sound through system audio."""
        # This would be platform-specific code to test system audio
        # For now we'll just show a notification
        self.notification_manager.show_notification(
            "System Audio Test",
            "Testing system audio... You should hear a sound.",
            3000
        )

    def on_recording_finished(self, filename, success, duration_str):
        """Handle recording finished event."""
        self.recording_size_timer.stop()
        
        # Reset UI regardless of success/failure
        self.record_btn.setText("⏺")  # Reset to record icon
        self.record_btn.show()
        self.stop_recording_btn.hide()
        
        if success:
            size = os.path.getsize(filename)
            size_str = format_size(size)
            msg = f"Recording saved: {os.path.basename(filename)} ({size_str})"
            # Show notification with click-to-open action
            notification = self.notification_manager.show_notification(
                "Recording Complete", 
                msg,
                5000
            )
            if notification:
                notification.mousePressEvent = lambda e: QDesktopServices.openUrl(
                    QUrl.fromLocalFile(os.path.dirname(filename)))
        else:
            msg = "Recording failed"
        
        self.status_bar.showMessage(msg, 3000)




    def on_recording_started(self, filename):
        """Handle recording started event."""
        self.status_bar.showMessage(f"Recording started: {os.path.basename(filename)}", 3000)



    def on_recording_progress(self, filename, duration):
        """Update UI with recording duration."""
        self.status_bar.showMessage(
            f"Recording {os.path.basename(filename)} - {duration // 60}m {duration % 60}s", 
            1000
        )


    def toggle_recording(self):
        """Toggle screen recording on/off."""
        if self.screen_recorder.is_recording():
            self.screen_recorder.stop_recording()
            self.record_btn.setText("⏺")
        else:
            if self.screen_recorder.start_recording():
                self.record_btn.setText("⏹")
            else:
                self.status_bar.showMessage("Failed to start recording", 3000)

    def start_region_recording(self):
        """Start recording a selected screen region."""
        # Create transparent overlay for region selection
        self.recording_overlay = QLabel(self)
        self.recording_overlay.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        self.recording_overlay.setAttribute(Qt.WA_TranslucentBackground)
        self.recording_overlay.setStyleSheet("background-color: rgba(0,0,0,0.5);")
        self.recording_overlay.setGeometry(QApplication.desktop().screenGeometry())
        self.recording_overlay.show()

        # Create selection rubber band
        self.recording_rubber_band = QRubberBand(QRubberBand.Rectangle, self.recording_overlay)
        self.recording_rubber_band.setStyleSheet("border: 2px dashed red;")

        # Connect mouse events
        self.recording_overlay.mousePressEvent = self.recording_region_mouse_press
        self.recording_overlay.mouseMoveEvent = self.recording_region_mouse_move
        self.recording_overlay.mouseReleaseEvent = self.recording_region_mouse_release

    def recording_region_mouse_press(self, event):
        self.recording_region_start = QCursor.pos()
        self.recording_rubber_band.setGeometry(QRect(self.recording_overlay.mapFromGlobal(self.recording_region_start), QSize()))
        self.recording_rubber_band.show()

    def recording_region_mouse_move(self, event):
        if hasattr(self, 'recording_region_start'):
            current_pos = QCursor.pos()
            rect = QRect(self.recording_region_start, current_pos).normalized()
            self.recording_rubber_band.setGeometry(QRect(self.recording_overlay.mapFromGlobal(rect.topLeft()), rect.size()))



    def recording_region_mouse_release(self, event):
        end_pos = QCursor.pos()
        selected_rect = QRect(self.recording_region_start, end_pos).normalized()

        self.recording_rubber_band.hide()
        self.recording_overlay.hide()

        self.recording_region = selected_rect
        print(f"Selected screen region: {self.recording_region}")
        capture_screen_region("output.mp4", self.recording_region)




            

    def capture_screen_region(output_file, region, framerate=30):
        screen_geom = QApplication.primaryScreen().geometry()
        valid_region = get_valid_region(region, screen_geom)

        if valid_region.isNull():
            print("Invalid region specified.")
            return False

        command = [
            'ffmpeg',
            '-y',  # Overwrite output file if it exists
            '-f', 'x11grab',
            '-video_size', f'{valid_region.width()}x{valid_region.height()}',
            '-framerate', str(framerate),
            '-i', f':0.0+{valid_region.x()},{valid_region.y()}',
            '-c:v', 'libx264',
            '-preset', 'ultrafast',
            output_file
        ]

        print("Running FFmpeg:", " ".join(command))
        try:
            subprocess.run(command, check=True)
            return True
        except subprocess.CalledProcessError as e:
            print("FFmpeg failed:", e)
            return False


    def on_stop_recording_clicked(self):
        """Handle stop recording button click."""
        if self.screen_recorder.stop_recording():
            # Update UI
            self.record_btn.setText("⏺")
            self.record_btn.show()
            self.stop_recording_btn.hide()
            
            # Show notification
            recording_file = self.screen_recorder.get_current_recording_file()
            if recording_file and os.path.exists(recording_file):
                file_size = os.path.getsize(recording_file)
                self.notification_manager.show_notification(
                    "Recording Saved",
                    f"Recording saved ({file_size//1024}KB)\n{recording_file}",
                    5000
                )
                # Open containing folder
                QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.dirname(recording_file)))
            else:
                self.status_bar.showMessage("Recording stopped but file not found", 3000)
        else:
            self.status_bar.showMessage("Failed to stop recording - trying force stop...", 3000)
            # Try one last time with more aggressive approach
            if hasattr(self.screen_recorder, 'recording_process'):
                try:
                    self.screen_recorder.recording_process.kill()
                except:
                    pass
            self.record_btn.setText("⏺")
            self.record_btn.show()
            self.stop_recording_btn.hide()




    def truncate_title(self, title, max_length=15):
        """Truncate long titles with ellipsis."""
        if len(title) > max_length:
            return title[:max_length - 3] + "..."  # Subtract 3 for "..."
        return title




    def add_incognito_tab(self, url=None, title="Incognito Tab"):
        """Adds a new incognito tab with special handling for privacy and truncated title."""
        
        # --- Helper function to truncate title ---
        def truncate_title(t, max_len=15):
            if len(t) > max_len:
                return t[:max_len - 3] + "..." # Use last 3 chars for "..."
            return t
        # --- End Helper ---

        # Truncate the title for display
        display_title = truncate_title(title)

        # Create a new profile specifically for incognito
        profile_name = f"incognito_{os.getpid()}_{int(time.time() * 1000000)}" # More unique ID
        incognito_profile = QWebEngineProfile(profile_name, self)

        # Configure the incognito profile to not store any data
        temp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "temp_profiles", profile_name)
        os.makedirs(temp_dir, exist_ok=True)
        incognito_profile.setPersistentStoragePath(temp_dir)
        incognito_profile.setCachePath(temp_dir)
        # Consider setting a distinct User Agent if desired
        # incognito_profile.setHttpUserAgent("YourBrowserIncognito/Version")

        # Disable storage and features that might persist data
        settings = incognito_profile.settings()
        settings.setAttribute(QWebEngineSettings.LocalStorageEnabled, False)
        settings.setAttribute(QWebEngineSettings.PluginsEnabled, False)
        # Add other privacy-related settings as needed...

        # Create a web view with the incognito profile
        container = QWidget()
        container.setProperty("is_incognito", True) # Store incognito flag on the widget
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        browser = QWebEngineView()
        browser.setPage(QWebEnginePage(incognito_profile, browser))

        # Connect signals for incognito-specific behavior
        # Assuming update_incognito_urlbar exists and handles URL bar/history for incognito
        browser.urlChanged.connect(lambda url: self.update_incognito_urlbar(browser, url))
        # Add other necessary signal connections...

        # Add to layout
        layout.addWidget(browser)

        # Add to tab widget with truncated title and icon
        tab_index = self.tab_widget.addTab(container, "🔥 " + display_title)
        # Use the original full title for the tooltip
        self.tab_widget.setTabToolTip(tab_index, "Incognito: " + title)

        # Load URL if provided
        if url and isinstance(url, QUrl):
            browser.setUrl(url)

        # Consider setting the new tab as current if not background
        # if not background: self.tab_widget.setCurrentIndex(tab_index)

        return browser


    def show_tab_context_menu(self, pos):
        """Show context menu for tabs"""
        index = self.tab_widget.tabBar().tabAt(pos)
        if index >= 0:
            menu = QMenu()
            
            # Create the "New Incognito Tab" action
            incognito_action = QAction("New Incognito Tab", self)
            incognito_action.triggered.connect(lambda: self.add_incognito_tab())
            
            menu.addAction(incognito_action)
            menu.exec_(self.tab_widget.mapToGlobal(pos))



    # In update_incognito_urlbar method
    def update_incognito_urlbar(self, browser, url):
        """Update the URL bar for incognito tabs without saving history."""
        url_string = url.toString()
        if url_string == "about:blank":
            self.url_bar.clear()
        else:
            self.url_bar.setText(url_string)
            self.url_bar.setCursorPosition(0)

        # Don't add to history for incognito tabs
        # --- Slightly improved logic ---
        if hasattr(self, 'history_manager'):
            # Find the tab index containing this specific browser instance
            tab_index = -1
            for i in range(self.tab_widget.count()):
                container = self.tab_widget.widget(i)
                if container and container.findChild(QWebEngineView) == browser:
                    tab_index = i
                    break

            if tab_index >= 0:
                # Get the container widget
                container_widget = self.tab_widget.widget(tab_index)
                # Check the property on the container widget
                is_incognito = container_widget and container_widget.property("is_incognito") == True
                # The check `if not is_incognito:` is technically redundant here
                # because this function is only called for incognito tabs,
                # but it's good defensive coding.
                if not is_incognito:
                     title = self.tab_widget.tabText(tab_index)
                     self.history_manager.add_history_entry(url.toString(), title)
        # --- End improved logic ---

    def update_url_bar(self, browser, url):
        url_string = url.toString()
        if url_string == "about:blank":
            self.url_bar.clear()
        else:
            self.url_bar.setText(url_string)
            self.url_bar.setCursorPosition(0)

        # Only add to history if it's NOT incognito
        if hasattr(self, 'history_manager'):
            tab_index = self.tab_widget.indexOf(browser.parentWidget())
            if tab_index >= 0 and not self.tab_widget.tabData(tab_index).get("is_incognito", False):
                title = self.tab_widget.tabText(tab_index)
                self.history_manager.add_history_entry(url.toString(), title)





















    def show_cookie_manager(self):
        """Show the cookie management dialog."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Cookie Manager")
        dialog.setMinimumSize(800, 600)
        
        layout = QVBoxLayout()
        
        # Filter bar
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))
        self.cookie_filter = QLineEdit()
        self.cookie_filter.setPlaceholderText("Search cookies...")
        self.cookie_filter.textChanged.connect(self.filter_cookies)
        filter_layout.addWidget(self.cookie_filter)
        
        # Cookie table
        self.cookie_table = QTableWidget()
        self.cookie_table.setColumnCount(5)
        self.cookie_table.setHorizontalHeaderLabels(["Domain", "Name", "Value", "Expires", "Secure"])
        self.cookie_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.cookie_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.cookie_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        
        # Buttons
        btn_layout = QHBoxLayout()
        delete_btn = QPushButton("Delete Selected")
        delete_btn.clicked.connect(self.delete_selected_cookies)
        block_btn = QPushButton("Block Site")
        block_btn.clicked.connect(self.block_cookie_site)
        whitelist_btn = QPushButton("Whitelist Site")
        whitelist_btn.clicked.connect(self.whitelist_cookie_site)
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_cookie_list)
        
        btn_layout.addWidget(delete_btn)
        btn_layout.addWidget(block_btn)
        btn_layout.addWidget(whitelist_btn)
        btn_layout.addWidget(refresh_btn)
        
        layout.addLayout(filter_layout)
        layout.addWidget(self.cookie_table)
        layout.addLayout(btn_layout)
        
        dialog.setLayout(layout)
        self.refresh_cookie_list()
        dialog.exec_()

    def refresh_cookie_list(self):
        """Refresh the list of cookies."""
        self.cookie_table.setRowCount(0)
        store = QWebEngineProfile.defaultProfile().cookieStore()
        
        # Disconnect any existing connections to avoid duplicates
        try:
            store.cookieAdded.disconnect()
        except:
            pass
        
        # Connect the correct signal name (cookieAdded)
        store.cookieAdded.connect(self.add_cookie_to_table)
        store.loadAllCookies()

    def add_cookie_to_table(self, cookie):
        """Add a single cookie to the table."""
        row = self.cookie_table.rowCount()
        self.cookie_table.insertRow(row)
        
        self.cookie_table.setItem(row, 0, QTableWidgetItem(cookie.domain()))
        self.cookie_table.setItem(row, 1, QTableWidgetItem(cookie.name()))
        self.cookie_table.setItem(row, 2, QTableWidgetItem(cookie.value()))
        self.cookie_table.setItem(row, 3, QTableWidgetItem(cookie.expirationDate().toString()))
        self.cookie_table.setItem(row, 4, QTableWidgetItem("Yes" if cookie.isSecure() else "No"))

    def filter_cookies(self):
        """Filter cookies based on search text."""
        filter_text = self.cookie_filter.text().lower()
        
        for row in range(self.cookie_table.rowCount()):
            match = False
            for col in range(self.cookie_table.columnCount()):
                item = self.cookie_table.item(row, col)
                if item and filter_text in item.text().lower():
                    match = True
                    break
            self.cookie_table.setRowHidden(row, not match)

    def delete_selected_cookies(self):
        """Delete selected cookies from the browser."""
        selected = self.cookie_table.selectedItems()
        if not selected:
            return
            
        store = QWebEngineProfile.defaultProfile().cookieStore()
        domains = set()
        
        for item in selected:
            if item.column() == 0:  # Domain column
                domains.add(item.text())
        
        # Delete all cookies for selected domains
        store.loadAllCookies()  # Need to load cookies first
        store.cookieAdded.connect(lambda cookie: self.delete_cookie_if_matches(cookie, domains))
        
        self.refresh_cookie_list()

    def delete_cookie_if_matches(self, cookie, domains):
        """Helper function to delete cookies that match domains."""
        if cookie.domain() in domains:
            store = QWebEngineProfile.defaultProfile().cookieStore()
            store.deleteCookie(cookie)

    def block_cookie_site(self):
        """Add selected cookie domains to blocked sites list."""
        selected = self.cookie_table.selectedItems()
        if not selected:
            return
            
        domains = set()
        for item in selected:
            if item.column() == 0:  # Domain column
                domains.add(item.text())
        
        cookies = self.settings_manager.get("cookies", {})
        blocked = set(cookies.get("blocked_sites", []))
        blocked.update(domains)
        cookies["blocked_sites"] = list(blocked)
        self.settings_manager.set("cookies", cookies)
        
        QMessageBox.information(self, "Blocked", f"Added {len(domains)} sites to blocked list")

    def whitelist_cookie_site(self):
        """Add selected cookie domains to whitelisted sites list."""
        selected = self.cookie_table.selectedItems()
        if not selected:
            return
            
        domains = set()
        for item in selected:
            if item.column() == 0:  # Domain column
                domains.add(item.text())
        
        cookies = self.settings_manager.get("cookies", {})
        whitelisted = set(cookies.get("whitelisted_sites", []))
        whitelisted.update(domains)
        cookies["whitelisted_sites"] = list(whitelisted)
        self.settings_manager.set("cookies", cookies)
        
        QMessageBox.information(self, "Whitelisted", f"Added {len(domains)} sites to whitelist")





    def connect_signals(self):
        """Connect all relevant signals to their handlers."""
        # Connect download manager signals
        self.download_manager.download_started.connect(self.on_download_started)
        self.download_manager.download_progress.connect(self.on_download_progress)
        self.download_manager.download_finished.connect(self.on_download_finished)
        self.download_manager.download_paused.connect(self.on_download_paused)
        self.download_manager.download_resumed.connect(self.on_download_resumed)
        self.download_manager.download_list_updated.connect(self.update_downloads_lists)

    def toggle_multi_site_search(self):
        if self.multi_site_search.isVisible():
            self.multi_site_search.hide()
        else:
            self.multi_site_search.search_input.clear()  # ← Add this line to clear the input
            self.multi_site_search.show()
            self.multi_site_search.search_input.setFocus()

    def on_download_started(self, filename, size):
        """Called when a new download has started."""
        print(f"Started downloading {filename} ({size})")
        self.status_bar.showMessage(f"Downloading: {filename}", 2000)

    def on_download_progress(self, filename, received, total, speed, eta):
        """Update the status bar with current download progress."""
        percent = (received / total * 100) if total > 0 else 0
        message = f"{filename}: {received}/{total} bytes ({percent:.1f}%) - {speed}, ETA: {eta}"
        self.status_bar.showMessage(message, 5000)

    def on_download_finished(self, path, success, filename):
        """Called when a download completes or fails."""
        if success:
            self.status_bar.showMessage(f"Download completed: {filename}", 3000)
            self.notification_manager.show_notification(
                "Download Complete",
                f"'{filename}' saved to {os.path.dirname(path)}",
                5000
            )
        else:
            self.status_bar.showMessage(f"Download failed: {filename}", 3000)
            self.notification_manager.show_notification(
                "Download Failed",
                f"Failed to download '{filename}'",
                5000
            )

    def on_download_paused(self, filename):
        """Called when a download is paused."""
        self.status_bar.showMessage(f"Download paused: {filename}", 2000)

    def on_download_resumed(self, filename):
        """Called when a paused download is resumed."""
        self.status_bar.showMessage(f"Download resumed: {filename}", 2000)

    def update_downloads_lists(self):
        """Update all download lists while preserving selections."""
        try:
            # Store current selections
            active_selection = self.active_downloads_list.currentRow()
            paused_selection = self.paused_downloads_list.currentRow()
            completed_selection = self.completed_downloads_list.currentRow()

            # Clear all lists
            self.active_downloads_list.clear()
            self.paused_downloads_list.clear()
            self.completed_downloads_list.clear()

            # Populate active downloads
            for download_id, download in self.download_manager.active_downloads.items():
                item = self._create_download_item(download_id, download, "active")
                self.active_downloads_list.addItem(item)

            # Populate paused downloads
            for download_id, download in self.download_manager.paused_downloads.items():
                item = self._create_download_item(download_id, download, "paused")
                self.paused_downloads_list.addItem(item)
                print(f"[DEBUG] Added paused download: {download_id} - {download['filename']}")

            # Populate completed downloads
            for download in self.download_manager.completed_downloads:
                item = self._create_download_item(None, download, "completed")
                self.completed_downloads_list.addItem(item)

            # Restore selections
            if 0 <= active_selection < self.active_downloads_list.count():
                self.active_downloads_list.setCurrentRow(active_selection)
            if 0 <= paused_selection < self.paused_downloads_list.count():
                self.paused_downloads_list.setCurrentRow(paused_selection)
            if 0 <= completed_selection < self.completed_downloads_list.count():
                self.completed_downloads_list.setCurrentRow(completed_selection)

        except Exception as e:
            print(f"[ERROR] Failed to update download lists: {e}")




    def handle_new_window_request(self, url):
        """Handle requests to open a new window or tab (e.g., from external apps or target='_blank')."""
        # Open tab in foreground
        self.add_new_tab(url, background=False)

        # Ensure the window is visible and raised
        self.show()           # Show window if hidden
        self.showNormal()     # Restore if minimized or maximized
        self.activateWindow() # Bring to front and give focus
        self.raise_()         # Raise above other windows




    def open_url_from_external(self, url):
        """Call this when receiving a URL from outside (e.g., desktop integration)."""
        self.handle_new_window_request(url)



    def create_window_callback(self, type_):
        new_browser = self.add_new_tab(background=False)
        self.show()
        self.showNormal()
        self.activateWindow()
        self.raise_()
        return new_browser.page()



    def handle_feature_permission(self, url, feature):
        """
        Handle permission requests for browser features like popup windows.
        Automatically grants permission for new window/tab requests.
        
        :param url: The URL requesting the permission
        :param feature: The type of feature being requested
        """
        if feature == QWebEnginePage.WebBrowserWindow:
            # Grant permission for new window/tab requests
            self.sender().setFeaturePermission(
                url, 
                feature, 
                QWebEnginePage.PermissionGrantedByUser
            )
  




    def _init_autocomplete_system(self):
        """Initialize the optimized autocomplete system"""
        # Cache setup
        self._autocomplete_cache = []
        self._last_cache_update = 0
        self.CACHE_TIMEOUT = 30  # seconds
        self.MIN_SEARCH_LENGTH = 2  # characters
        
        # Create completer
        self.url_completer = QCompleter()
        self.url_completer.setCompletionMode(QCompleter.PopupCompletion)
        self.url_completer.setCaseSensitivity(Qt.CaseInsensitive)
        self.url_completer.setFilterMode(Qt.MatchContains)
        
        # Use standard item model for icons/tooltips
        self.url_completer_model = QStandardItemModel()
        self.url_completer.setModel(self.url_completer_model)
        self.url_bar.setCompleter(self.url_completer)
        
        self.url_completer.activated.connect(self.navigate_to_selected_url)
        
        # Setup debouncing timer
        self._autocomplete_timer = QTimer()
        self._autocomplete_timer.setSingleShot(True)
        self._autocomplete_timer.timeout.connect(self._perform_autocomplete_search)
        self.url_bar.textChanged.connect(self._schedule_autocomplete_update)

    def _schedule_autocomplete_update(self, text):
        """Debounce autocomplete updates"""
        self._autocomplete_timer.stop()
        if len(text) >= self.MIN_SEARCH_LENGTH:
            self._autocomplete_timer.start(150)  # 150ms delay after typing stops

    def _update_autocomplete_cache(self):
        """Refresh the suggestion cache"""
        current_time = time.time()
        if (current_time - self._last_cache_update) > self.CACHE_TIMEOUT:
            self._autocomplete_cache = []
            
            # Get bookmarks (faster access)
            bookmarks = self.bookmark_manager.get_all_bookmarks()
            for bookmark in bookmarks:
                self._autocomplete_cache.append((
                    bookmark['url'].lower(), 
                    bookmark['url'], 
                    'bookmark', 
                    bookmark['title']
                ))
                self._autocomplete_cache.append((
                    bookmark['title'].lower(), 
                    bookmark['title'], 
                    'bookmark', 
                    bookmark['url']
                ))
            
            # Get recent history (limited to 50 items)
            history = self.history_manager.get_history(limit=50)
            for entry in history:
                self._autocomplete_cache.append((
                    entry['url'].lower(),
                    entry['url'],
                    'history',
                    entry['title']
                ))
                self._autocomplete_cache.append((
                    entry['title'].lower(),
                    entry['title'],
                    'history',
                    entry['url']
                ))
            
            self._last_cache_update = current_time

    def _perform_autocomplete_search(self):
        """Perform the actual search with cached data"""
        search_text = self.url_bar.text().lower()
        if len(search_text) < self.MIN_SEARCH_LENGTH:
            self.url_completer_model.clear()
            return
            
        self._update_autocomplete_cache()
        self.url_completer_model.clear()
        
        # Simple substring matching (faster than regex for most cases)
        for cached_item in self._autocomplete_cache:
            if search_text in cached_item[0]:  # Search in pre-lowered text
                self._add_suggestion_to_model(
                    display_text=cached_item[1],
                    item_type=cached_item[2],
                    tooltip=cached_item[3]
                )

    def _add_suggestion_to_model(self, display_text, item_type, tooltip):
        """Efficiently add a suggestion to the model"""
        item = QStandardItem(display_text)
        item.setIcon(QIcon.fromTheme('bookmarks' if item_type == 'bookmark' else 'view-history'))
        item.setToolTip(f"{item_type.title()}: {tooltip}")
        self.url_completer_model.appendRow(item)

    def setup_ui(self):
        """Setup the main browser UI with all components including toggleable find bar."""
        
        # Initialize fullscreen tracking
        self.fullscreen_view = None
        self.installEventFilter(self)

        # Central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        self.main_layout = QVBoxLayout()
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)
        central_widget.setLayout(self.main_layout)

        # Find bar setup (initially hidden)
        self.find_widget = QWidget()
        self.find_widget.setVisible(False)
        find_layout = QHBoxLayout(self.find_widget)
        find_layout.setContentsMargins(5, 2, 5, 2)
        
        # Find bar components
        self.find_line = QLineEdit()
        self.find_line.setPlaceholderText("Find in page...")
        self.find_prev = QPushButton("<")
        self.find_prev.setToolTip("Previous match (Shift+Enter)")
        self.find_next = QPushButton(">")
        self.find_next.setToolTip("Next match (Enter)")
        self.find_close = QPushButton("✕")
        self.find_close.setToolTip("Close find bar (Esc or Ctrl+F)")
        
        # Add components to find bar
        find_layout.addWidget(self.find_line)
        find_layout.addWidget(self.find_prev)
        find_layout.addWidget(self.find_next)
        find_layout.addWidget(self.find_close)
        
        # Add find bar to main layout
        self.main_layout.addWidget(self.find_widget)

        # Connect find bar signals
        self.find_line.textChanged.connect(self.find_text)
        self.find_prev.clicked.connect(self.find_previous)
        self.find_next.clicked.connect(self.find_next)
        self.find_close.clicked.connect(self.hide_find)

        # Tab widget setup
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabsClosable(True)
        self.tab_widget.setMovable(True)
        self.tab_widget.tabCloseRequested.connect(self.close_tab)
        self.tab_widget.setDocumentMode(True)

        # New tab button
        new_tab_btn = QToolButton()
        new_tab_btn.setText("+")
        new_tab_btn.setCursor(Qt.PointingHandCursor)
        new_tab_btn.clicked.connect(lambda: self.add_new_tab())
        self.tab_widget.setCornerWidget(new_tab_btn, Qt.TopLeftCorner)

        # Add tab widget to main layout
        self.main_layout.addWidget(self.tab_widget)

        # Navigation toolbar
        self.nav_bar = QToolBar("Navigation")
        self.nav_bar.setMovable(False)
        self.nav_bar.setIconSize(QSize(24, 24))
        self.nav_bar.setToolButtonStyle(Qt.ToolButtonIconOnly)
        self.addToolBar(self.nav_bar)

        # Navigation buttons
        self.back_btn = QAction(QIcon.fromTheme("go-previous"), "←", self)
        self.back_btn.setToolTip("Back (Alt+Left)")
        self.nav_bar.addAction(self.back_btn)

        self.forward_btn = QAction(QIcon.fromTheme("go-next"), "→", self)
        self.forward_btn.setToolTip("Forward (Alt+Right)")
        self.nav_bar.addAction(self.forward_btn)

        self.refresh_btn = QAction(QIcon.fromTheme("view-refresh"), "↻", self)
        self.refresh_btn.setToolTip("Refresh (F5)")
        self.nav_bar.addAction(self.refresh_btn)

        self.nav_bar.addSeparator()

        # URL bar
        self.url_bar = QLineEdit()
        self.url_bar.setPlaceholderText("Search or enter URL")
        self.url_bar.setClearButtonEnabled(True)
        self.nav_bar.addWidget(self.url_bar)

        # Search button
        self.search_btn = QAction("🌐", self)
        search_icon = QIcon.fromTheme("system-search") or QIcon.fromTheme("edit-find")
        if not search_icon.isNull():
            self.search_btn.setIcon(search_icon)
        self.search_btn.setToolTip("Multi-Site Search (Ctrl+K)")
        self.nav_bar.addAction(self.search_btn)

        # Theme selector
        self.theme_btn = QAction(QIcon.fromTheme("preferences-desktop-color"), "🎨", self)
        self.theme_btn.setToolTip("Change Theme Color")
        self.nav_bar.addAction(self.theme_btn)

        # Recording buttons
        self.record_btn = QAction("⏺", self)
        self.record_btn.setToolTip("Start Screen Recording")
        self.nav_bar.addAction(self.record_btn)

        self.stop_recording_btn = QAction("⏹", self)
        self.stop_recording_btn.setToolTip("Stop Recording")
        self.stop_recording_btn.setVisible(False)
        self.nav_bar.addAction(self.stop_recording_btn)

        self.nav_bar.addSeparator()

        # Utility buttons
        self.calendar_btn = QAction("📅", self)
        self.calendar_btn.setToolTip("Calendar (Ctrl+Shift+C)")
        self.nav_bar.addAction(self.calendar_btn)

        self.settings_btn = QAction(QIcon.fromTheme("preferences-system"), "⚙", self)
        self.settings_btn.setToolTip("Settings")
        self.nav_bar.addAction(self.settings_btn)

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        # Download progress bar
        self.download_progress_bar = QProgressBar()
        self.download_progress_bar.setTextVisible(False)
        self.download_progress_bar.setFixedHeight(3)
        self.download_progress_bar.hide()
        self.status_bar.addPermanentWidget(self.download_progress_bar)

        # Multi-site search dock widget
        self.multi_site_search = MultiSiteSearchWidget(parent=self)
        self.addDockWidget(Qt.RightDockWidgetArea, self.multi_site_search)
        self.multi_site_search.hide()

        # Apply styles and themes
        self.apply_tab_style()
        self.update_nav_buttons_style(self.settings_manager.get("theme", {}).get("accent_color", "#3daee9"))
        self.create_theme_menu()
        self.apply_theme()

        # Set up keyboard shortcuts
        self.find_shortcut = QShortcut(QKeySequence("Ctrl+F"), self)
        self.find_shortcut.activated.connect(self.toggle_find_widget)
        self.shortcuts.append(self.find_shortcut)
        
        # Additional find bar shortcuts
        self.find_next_shortcut = QShortcut(QKeySequence("Return"), self.find_line)
        self.find_next_shortcut.activated.connect(self.find_next)
        self.find_prev_shortcut = QShortcut(QKeySequence("Shift+Return"), self.find_line)
        self.find_prev_shortcut.activated.connect(self.find_previous)



#-----------------Find Info----------------------------------------





    def eventFilter(self, obj, event):
        if obj is self.find_line and event.type() == QEvent.KeyPress:
            key = event.key()
            if key == Qt.Key_Escape:
                self.hide_find()
                return True
        return super().eventFilter(obj, event)



#_------------------------------------------------------------------


























    def create_theme_menu(self):
        """Create the theme color selection menu."""
        self.theme_menu = QMenu("Theme Colors", self)
        
        # Get available colors from settings
        colors = self.settings_manager.get_available_accent_colors()
        current_color = self.settings_manager.get_current_accent_color()
        
        # Create color actions
        for color_info in colors:
            action = QAction(color_info["name"], self.theme_menu)
            action.setData(color_info["color"])
            
            # Create color preview icon
            pixmap = QPixmap(16, 16)
            pixmap.fill(QColor(color_info["color"]))
            action.setIcon(QIcon(pixmap))
            
            # Mark current color
            if color_info["color"] == current_color:
                action.setCheckable(True)
                action.setChecked(True)
            
            action.triggered.connect(self.change_accent_color)
            self.theme_menu.addAction(action)
        
        # Connect theme button to menu
        self.theme_btn.triggered.connect(lambda: self.theme_menu.exec_(
            self.theme_btn.mapToGlobal(QPoint(0, self.theme_btn.height()))))

    def change_accent_color(self):
        """Change the application accent color."""
        action = self.sender()
        if action:
            color = action.data()
            self.settings_manager.apply_accent_color(color)
            self.apply_theme()

    def apply_theme(self):
        """Apply current theme settings to all UI elements."""
        # Apply base theme
        self.settings_manager.apply_dark_mode(QApplication.instance())
        
        # Get current accent color
        accent_color = self.settings_manager.get_current_accent_color()
        theme_colors = self.settings_manager.get("dark_theme")
        
        # Apply to tab widget
        self.tab_widget.setStyleSheet(f"""
            QTabWidget::pane {{
                border: none;
                background-color: {theme_colors["base_color"]};
            }}
            QTabBar::tab {{
                background: {theme_colors["button_color"]};
                color: {theme_colors["text_color"]};
                padding: 8px;
                border: 1px solid #444;
            }}
            QTabBar::tab:selected {{
                background: {theme_colors["base_color"]};
                border-bottom: 2px solid {accent_color};
            }}
        """)
        
        # Apply to navigation bar
        self.nav_bar.setStyleSheet(f"""
            QToolBar {{
                background-color: {theme_colors["button_color"]};
                border: none;
                padding: 2px;
            }}
            QToolButton:hover {{
                background-color: {self.settings_manager._adjust_lightness(
                    theme_colors["button_color"], 10)};
            }}
        """)
        
        # Apply to status bar
        self.status_bar.setStyleSheet(f"""
            QStatusBar {{
                background-color: {theme_colors["button_color"]};
                color: {theme_colors["text_color"]};
            }}
        """)
        
        # Apply to progress bar
        self.download_progress_bar.setStyleSheet(f"""
            QProgressBar {{
                border: 1px solid {theme_colors["base_color"]};
                background: {theme_colors["window_color"]};
            }}
            QProgressBar::chunk {{
                background-color: {accent_color};
            }}
        """)
        
        # Apply to recording status
        self.recording_status_widget.setStyleSheet(f"""
            QLabel {{
                color: {theme_colors["text_color"]};
            }}
            #elapsed_label {{
                color: #ff4545;
                font-weight: bold;
            }}
            #countdown_label {{
                color: {accent_color};
                font-weight: bold;
            }}
        """)

    def connect_ui_signals(self):
        """Connect all UI signals to their handlers."""
        # Navigation signals
        self.back_btn.triggered.connect(self.navigate_back)
        self.forward_btn.triggered.connect(self.navigate_forward)
        self.refresh_btn.triggered.connect(self.reload_page)
        self.url_bar.returnPressed.connect(self.navigate_to_url)
        self.search_btn.triggered.connect(self.toggle_multi_site_search)
        
        # Recording signals
        self.record_btn.triggered.connect(self.start_recording)
        self.stop_recording_btn.triggered.connect(self.stop_recording)
        
        # Utility signals
        self.calendar_btn.triggered.connect(self.show_calendar)
        self.settings_btn.triggered.connect(self.show_settings)








    def create_toolbar(self):
        """Create the main toolbar with theme-aware styling"""
        self.toolbar = QToolBar("Main Toolbar")
        self.addToolBar(self.toolbar)
        
        # Navigation buttons
        self.back_btn = QAction(QIcon.fromTheme("go-previous"), "Back", self)
        self.forward_btn = QAction(QIcon.fromTheme("go-next"), "Forward", self)
        self.reload_btn = QAction(QIcon.fromTheme("view-refresh"), "Reload", self)
        self.home_btn = QAction(QIcon.fromTheme("go-home"), "Home", self)
        
        # URL bar
        self.url_bar = QLineEdit()
        self.url_bar.setPlaceholderText("Enter URL or search term...")
        
        # Add widgets to toolbar
        self.toolbar.addAction(self.back_btn)
        self.toolbar.addAction(self.forward_btn)
        self.toolbar.addAction(self.reload_btn)
        self.toolbar.addAction(self.home_btn)
        self.toolbar.addWidget(self.url_bar)

    def create_status_bar(self):
        """Create the status bar with theme support"""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Recording status widget (if screen recording is enabled)
        if hasattr(self, 'screen_recorder'):
            self.recording_status_widget = QWidget()
            recording_layout = QHBoxLayout()
            recording_layout.setContentsMargins(0, 0, 0, 0)
            
            self.elapsed_label = QLabel("00:00")
            self.countdown_label = QLabel("00:00")
            self.size_label = QLabel("0 MB")
            self.bitrate_label = QLabel("0 kbps")
            
            recording_layout.addWidget(self.elapsed_label)
            recording_layout.addWidget(self.countdown_label)
            recording_layout.addWidget(QLabel("|"))
            recording_layout.addWidget(self.size_label)
            recording_layout.addWidget(self.bitrate_label)
            
            self.recording_status_widget.setLayout(recording_layout)
            self.status_bar.addPermanentWidget(self.recording_status_widget)
            self.recording_status_widget.hide()

    def create_theme_selector(self):
        """Create theme accent color selector button"""
        self.theme_btn = QToolButton()
        self.theme_btn.setPopupMode(QToolButton.InstantPopup)
        self.theme_btn.setIcon(QIcon.fromTheme("preferences-desktop-color"))
        self.theme_btn.setToolTip("Change accent color")
        
        # Create color menu
        self.theme_menu = QMenu(self.theme_btn)
        colors = self.settings_manager.get_available_accent_colors()
        
        for color_info in colors:
            action = QAction(color_info["name"], self.theme_menu)
            action.setData(color_info["color"])
            
            # Create color icon
            pixmap = QPixmap(16, 16)
            pixmap.fill(QColor(color_info["color"]))
            action.setIcon(QIcon(pixmap))
            
            action.triggered.connect(self.change_accent_color)
            self.theme_menu.addAction(action)
        
        self.theme_btn.setMenu(self.theme_menu)
        self.toolbar.addWidget(self.theme_btn)

    def change_accent_color(self):
        """Change the application accent color"""
        action = self.sender()
        if action:
            color = action.data()
            self.settings_manager.apply_accent_color(color)
            self.apply_theme()

    def apply_theme(self):
        """Apply current theme settings to all UI elements"""
        # Apply to main window
        self.settings_manager.apply_dark_mode(QApplication.instance())
        
        # Apply to tab widget
        accent_color = self.settings_manager.get_current_accent_color()
        self.tab_widget.setStyleSheet(f"""
            QTabWidget::pane {{
                border: none;
                background-color: {self.settings_manager.get("dark_theme")["base_color"]};
            }}
            QTabBar::tab {{
                background: {self.settings_manager.get("dark_theme")["button_color"]};
                color: {self.settings_manager.get("dark_theme")["text_color"]};
                padding: 8px;
                border: 1px solid #444;
            }}
            QTabBar::tab:selected {{
                background: {self.settings_manager.get("dark_theme")["base_color"]};
                border-bottom: 2px solid {accent_color};
            }}
        """)
        
        # Apply to toolbar
        self.toolbar.setStyleSheet(f"""
            QToolBar {{
                background-color: {self.settings_manager.get("dark_theme")["button_color"]};
                border: none;
                padding: 2px;
            }}
            QToolButton:hover {{
                background-color: {self.settings_manager._adjust_lightness(
                    self.settings_manager.get("dark_theme")["button_color"], 10)};
            }}
        """)

    def connect_signals(self):
        """Connect all relevant signals to their handlers."""
        # Connect download manager signals
        self.download_manager.download_started.connect(self.on_download_started)
        self.download_manager.download_progress.connect(self.on_download_progress)
        self.download_manager.download_finished.connect(self.on_download_finished)
        self.download_manager.download_paused.connect(self.on_download_paused)
        self.download_manager.download_resumed.connect(self.on_download_resumed)
        self.download_manager.download_list_updated.connect(self.update_downloads_lists)


    def eventFilter(self, obj, event):
        """Handle global key events for fullscreen mode."""
        if event.type() == QEvent.KeyPress and event.key() == Qt.Key_Escape:
            if self.fullscreen_view:
                self.exit_fullscreen()
                return True  # Event handled
        return super().eventFilter(obj, event)

    def enter_fullscreen(self, view):
        """Enter fullscreen mode for the specified view."""
        self.fullscreen_view = view
        self.tab_widget.hide()
        self.nav_bar.hide()
        self.status_bar.hide()
        view.setParent(None)  # Remove from tab
        view.showFullScreen()
        
        # Add a close button in the corner
        self.fullscreen_close_btn = QToolButton(view)
        self.fullscreen_close_btn.setText("X")
        self.fullscreen_close_btn.setStyleSheet("""
            QToolButton {
                background: rgba(0, 0, 0, 0.5);
                color: white;
                font-weight: bold;
                border-radius: 12px;
                min-width: 24px;
                max-width: 24px;
                min-height: 24px;
                max-height: 24px;
            }
            QToolButton:hover {
                background: rgba(255, 0, 0, 0.7);
            }
        """)
        self.fullscreen_close_btn.clicked.connect(self.exit_fullscreen)
        
        # Position in top-right corner
        close_btn_size = self.fullscreen_close_btn.sizeHint()
        self.fullscreen_close_btn.move(
            view.width() - close_btn_size.width() - 10,
            10
        )
        self.fullscreen_close_btn.show()

    def exit_fullscreen(self):
        """Exit fullscreen mode and restore normal view."""
        if self.fullscreen_view is None:
            return
        
        # Find which tab this view belongs to
        for i in range(self.tab_widget.count()):
            tab = self.tab_widget.widget(i)
            if tab.findChild(QWebEngineView) == self.fullscreen_view:
                break
        else:
            i = self.tab_widget.currentIndex()
        
        # Restore view to tab
        self.fullscreen_view.setParent(self.tab_widget.widget(i))
        self.tab_widget.widget(i).layout().addWidget(self.fullscreen_view)
        self.fullscreen_view.showNormal()
        
        # Restore UI elements
        self.tab_widget.show()
        self.nav_bar.show()
        self.status_bar.show()
        self.fullscreen_view = None

    def handle_fullscreen_request(self, request):
        """Handle web page fullscreen requests."""
        request.accept()
        webview = self.sender().view()
        
        if request.toggleOn():
            self.enter_fullscreen(webview)
        else:
            self.exit_fullscreen()







    def _configure_search_button(self):
        """Enable the search button and connect it to the multi-site search toggle method."""
        self.search_btn.setEnabled(True)  # Re-enable the button
        self.search_btn.setToolTip("Open Multi-Site Search Widget")  # Update tooltip
        self.search_btn.triggered.connect(self.toggle_multi_site_search)  # Connect to toggle method





    def setup_calendar(self):
        """Setup calendar with a Notes tab that supports clickable URLs."""
        self.calendar_widget = BrowserCalendar(self)
        self.calendar_dock = QDockWidget("Calendar", self)
        self.calendar_dock.setWidget(self.calendar_widget)
        self.calendar_dock.setFeatures(QDockWidget.DockWidgetMovable |
                                       QDockWidget.DockWidgetClosable |
                                       QDockWidget.DockWidgetFloatable)
        self.addDockWidget(Qt.RightDockWidgetArea, self.calendar_dock)
        self.calendar_dock.hide()

        # Configure notes text edit for clickable URLs
        notes_text = self.calendar_widget.notes_text
        notes_text.setReadOnly(False)
        notes_text.setOpenExternalLinks(False)  # Prevent default behavior
        notes_text.setHtml("")  # Clear initial content

        # Connect anchorClicked signal to handler
        notes_text.anchorClicked.connect(self.open_calendar_link)

        # Connect calendar button
        self.calendar_btn.triggered.connect(self.toggle_calendar)

        # Connect clicked signal to show_notes_for_date method
        self.calendar_widget.calendar.clicked.connect(self.calendar_widget.show_notes_for_date)

        # Trigger notes display for the current date when the calendar is initialized
        self.calendar_widget.show_notes_for_date(self.calendar_widget.calendar.selectedDate())


    def navigate_to_selected_url(self, text):
        self.url_bar.setText(text)
        self.navigate_to_url()  # This should be the existing navigation method



    def open_calendar_link(self, url):
        """Handle clicking on links in calendar notes by opening them in a new tab."""
        print("Link clicked:", url.toString())  # Debug line
        if hasattr(self, 'add_new_tab') and callable(self.add_new_tab):
            self.add_new_tab(url, background=True)
        else:
            # Fallback: Open in system browser
            QDesktopServices.openUrl(url)

    def toggle_calendar(self):
        """Handle calendar button click - toggle visibility"""
        if hasattr(self, 'calendar_dock'):
            self.calendar_dock.setVisible(not self.calendar_dock.isVisible())
            if self.calendar_dock.isVisible():
                # Ensure notes are displayed for the currently selected date
                self.calendar_widget.show_notes_for_date(self.calendar_widget.calendar.selectedDate())
        else:
            # Fallback if dock wasn't created
            if not hasattr(self, '_calendar_window') or not self._calendar_window:
                self._calendar_window = BrowserCalendar(self)
            self._calendar_window.show()


    def show_calendar(self):
        """Handle calendar button click - toggle visibility"""
        if hasattr(self, 'calendar_dock'):
            self.calendar_dock.setVisible(not self.calendar_dock.isVisible())
        else:
            # Fallback if dock wasn't created
            if not hasattr(self, '_calendar_window') or not self._calendar_window:
                self._calendar_window = BrowserCalendar(self)
            self._calendar_window.show()

    def configure_webengine(self):
        """Configure WebEngine settings for proper WebRTC support"""
        settings = QWebEngineSettings.globalSettings()
        
        # Essential WebRTC settings
        settings.setAttribute(QWebEngineSettings.JavascriptEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebRTCPublicInterfacesOnly, False)
        settings.setAttribute(QWebEngineSettings.ScreenCaptureEnabled, True)
        settings.setAttribute(QWebEngineSettings.AllowWindowActivationFromJavaScript, True)
        
        # Additional media settings
        settings.setAttribute(QWebEngineSettings.PlaybackRequiresUserGesture, False)
        settings.setAttribute(QWebEngineSettings.LocalStorageEnabled, True)
        
        # Set profile permissions
        profile = QWebEngineProfile.defaultProfile()
        profile.setPersistentCookiesPolicy(QWebEngineProfile.AllowPersistentCookies)
        
        # Set Chromium flags for WebRTC
        os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = (
            "--enable-features=WebRTC "
            "--disable-features=WebRtcHideLocalIpsWithMdns "
            "--enable-webrtc-srtp-aes-gcm "
            "--enable-webrtc-srtp-encrypted-headers "
            "--enable-experimental-web-platform-features "
            "--use-fake-ui-for-media-stream "
            "--enable-media-stream "
            "--no-sandbox "

            "--ignore-gpu-blocklist "  # Important for some DRM content
            "--use-gl=desktop "  



            "--enable-gpu-rasterization "
            "--enable-accelerated-video-decode "
            "--enable-accelerated-video-encode "


        )








from PyQt5.QtWidgets import QMainWindow, QToolButton, QWidget, QVBoxLayout, QTabWidget
from PyQt5.QtCore import Qt, QTimer, QEvent
from PyQt5.QtGui import QIcon


class StormBrowserDark(BrowserMainWindow):
    """Dark theme variant of the browser with enhanced visual features."""

    def __init__(self):
        # Initialize visual features
        self.blue_light_filter_enabled = False
        self.blue_light_intensity = 0.5
        self.filter_overlay = None
        self.audio_visualizer = None
        self.fullscreen_window = None
        self.fullscreen_browser = None
        self.original_container = None
        self.original_index = None

        # Initialize parent class
        super().__init__()

        # Setup dark theme features
        self.apply_firefox_dark_theme()
        self.setup_blue_light_filter()
        self.setup_audio_visualizer()

        # Window configuration
        self.setWindowTitle("Icarus Browser")
        self.setWindowIcon(QIcon.fromTheme("web-browser"))

        # Add this timer setup after initializing audio visualizer
        self.audio_monitor_timer = QTimer(self)
        self.audio_monitor_timer.timeout.connect(self.check_audio_levels)
        self.audio_monitor_timer.start(100)  # 10 FPS updates

        # Install event filter now
        self.installEventFilter(self)

    def apply_firefox_dark_theme(self):
        """Firefox dark theme that respects user's accent color."""
        accent_color = self.settings_manager.get("theme", {}).get("accent_color", "#3daee9")  # Fallback to blue
        
        self.theme_colors = {
            "toolbar": "#2b1a1a",
            "address_bar": "#4d2a2a",
            "text": "#fbfbfe",
            "button_hover": "#5e3a3a",
            "button_active": "#663d3d",
            "tab_selected": "#1a0a0a",
            "tab_unselected": "#2b1a1a",
            "tab_hover": "#3a2525",
            "accent": accent_color,
            "divider": "#221010",
            "filter_day": "rgba(255, 166, 0, 0)",
            "filter_night": "rgba(255, 166, 0, 0.3)",
            "filter_icon_day": accent_color,
            "filter_icon_night": "#ffa500",
            "audio_meter_bg": "#1a0a0a",
            "audio_meter_fill": accent_color
        }

        # Base stylesheet with all UI elements
        stylesheet = f"""
        /* Main window */
        QMainWindow {{
            background-color: {self.theme_colors["toolbar"]};
            color: {self.theme_colors["text"]};
        }}

        /* Tab bar */
        QTabBar {{
            background-color: {self.theme_colors["toolbar"]};
            spacing: 4px;
        }}

        QTabBar::tab {{
            background-color: {self.theme_colors["tab_unselected"]};
            color: {self.theme_colors["text"]};
            border: 0;
            border-radius: 4px 4px 0 0;
            padding: 6px 12px;
            margin-right: 2px;
        }}

        QTabBar::tab:selected {{
            background-color: {self.theme_colors["tab_selected"]};
            border-bottom: 2px solid {self.theme_colors["accent"]};
        }}

        QTabBar::tab:hover {{
            background-color: {self.theme_colors["tab_hover"]};
        }}

        /* Address bar */
        QLineEdit {{
            background-color: {self.theme_colors["address_bar"]};
            color: {self.theme_colors["text"]};
            border: 1px solid {self.theme_colors["divider"]};
            border-radius: 4px;
            padding: 5px 8px;
            selection-background-color: {self.theme_colors["accent"]};
        }}

        /* Toolbar buttons */
        QToolButton {{
            background-color: transparent;
            border: none;
        }}

        /* Blue light filter button */
        QToolButton#blue_light_btn {{
            color: {self.theme_colors["filter_icon_day"]};
        }}
        QToolButton#blue_light_btn:checked {{
            color: {self.theme_colors["filter_icon_night"]};
        }}

        /* Audio visualizer */
        QProgressBar#audio_visualizer {{
            border: 1px solid {self.theme_colors["divider"]};
            background: {self.theme_colors["audio_meter_bg"]};
            border-radius: 3px;
            min-width: 80px;
            max-width: 150px;
            height: 6px;
        }}
        QProgressBar#audio_visualizer::chunk {{
            background: qlineargradient(
                x1:0, y1:0, x2:1, y2:0,
                stop:0 {self.theme_colors["audio_meter_fill"]}, 
                stop:1 {self.theme_colors["accent"]}
            );
            border-radius: 2px;
        }}
        """
        self.setStyleSheet(stylesheet)

    def exit_fullscreen(self):
        """Exit fullscreen mode and restore tab layout."""
        if hasattr(self, 'fullscreen_window') and self.fullscreen_window:
            # Detach from fullscreen window
            self.fullscreen_browser.setParent(None)

            # Reattach to the original container
            layout = self.original_container.layout()
            if layout:
                layout.addWidget(self.fullscreen_browser)
            else:
                # Fallback in case layout is missing
                vbox = QVBoxLayout(self.original_container)
                vbox.setContentsMargins(0, 0, 0, 0)
                vbox.addWidget(self.fullscreen_browser)

            # Show the tab again
            if self.tab_widget.indexOf(self.original_container) == -1:
                self.tab_widget.insertTab(self.original_index, self.original_container, "Restored Tab")
            self.tab_widget.setCurrentWidget(self.original_container)

            # Clean up
            self.fullscreen_window.close()
            self.fullscreen_window.deleteLater()

            # Reset states
            self.fullscreen_window = None
            self.fullscreen_browser = None
            self.original_container = None
            self.original_index = None

        # Restore normal window size
        self.showNormal()

    def eventFilter(self, obj, event):
        if event.type() == QEvent.KeyPress and event.key() == Qt.Key_Escape:
            if hasattr(self, 'fullscreen_window') and self.fullscreen_window:
                self.exit_fullscreen()
                return True
            elif self.current_browser():
                self.current_browser().stop()
                return True
        return super().eventFilter(obj, event)



    def setup_blue_light_filter(self):
        """Initialize the blue light filter overlay"""
        self.filter_overlay = QLabel(self)
        self.filter_overlay.setObjectName("blueLightFilter")
        self.filter_overlay.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.filter_overlay.setStyleSheet("""
            QLabel#blueLightFilter {
                background-color: rgba(255, 166, 0, 0);
            }
        """)
        self.filter_overlay.hide()
        self.filter_overlay.lower()
        self.filter_overlay.setGeometry(self.rect())





        



    def setup_audio_visualizer(self):
        """Initialize and configure the audio level visualizer."""
        self.audio_visualizer = AudioLevelVisualizer(self)
        self.status_bar.addPermanentWidget(self.audio_visualizer)
        self.audio_visualizer.hide()
        
        # Connect page audio state changes
        for i in range(self.tab_widget.count()):
            browser = self.tab_widget.widget(i).findChild(QWebEngineView)
            if browser:
                browser.page().audioMutedChanged.connect(self.on_audio_state_changed)
        
        # Monitor audio levels periodically - no arguments needed
        self.audio_monitor_timer = QTimer(self)
        self.audio_monitor_timer.timeout.connect(self.check_audio_levels)
        self.audio_monitor_timer.start(100)  # 10 FPS updates

    def on_audio_state_changed(self, muted):
        """Handle changes in audio playback state."""
        self.audio_visualizer.set_active(not muted)
        if muted:
            self.audio_visualizer.reset()

    def check_audio_levels(self):
        """Check audio levels from current web page."""
        if not hasattr(self, 'audio_visualizer') or not self.audio_visualizer.isVisible():
            return
            
        browser = self.current_browser()
        if browser:
            js = """
            let maxLevel = 0;
            const mediaElements = document.querySelectorAll('audio,video');
            
            mediaElements.forEach(media => {
                if (!media.paused && !media.muted && media.volume > 0) {
                    // Create audio context if needed
                    if (!window.audioContext) {
                        window.audioContext = new (window.AudioContext || window.webkitAudioContext)();
                    }
                    
                    // Create analyzer node if needed
                    if (!media.analyzer) {
                        const source = window.audioContext.createMediaElementSource(media);
                        media.analyzer = window.audioContext.createAnalyser();
                        media.analyzer.fftSize = 32;
                        source.connect(media.analyzer);
                        media.analyzer.connect(window.audioContext.destination);
                    }
                    
                    // Get audio levels
                    const bufferLength = media.analyzer.frequencyBinCount;
                    const dataArray = new Uint8Array(bufferLength);
                    media.analyzer.getByteFrequencyData(dataArray);
                    
                    // Calculate average volume
                    let sum = 0;
                    for (let i = 0; i < bufferLength; i++) {
                        sum += dataArray[i];
                    }
                    const avg = sum / bufferLength;
                    maxLevel = Math.max(maxLevel, avg);
                }
            });
            maxLevel;
            """
            browser.page().runJavaScript(js, self.update_audio_level)

    def update_audio_level(self, level):
        """Update visualizer with new audio level."""
        if level is not None and level > 0 and hasattr(self, 'audio_visualizer'):
            # Scale the level (0-255 from analyzer to 0-100 for visualizer)
            scaled_level = min(100, (level / 255) * 100)
            self.audio_visualizer.update_level(scaled_level)













            
    def toggle_blue_light_filter(self, enabled=None):
        """Toggle blue light filter with visual feedback."""
        if enabled is None:
            enabled = not self.blue_light_filter_enabled
            
        self.blue_light_filter_enabled = enabled
        opacity = self.blue_light_intensity * 0.3 if enabled else 0
        
        self.filter_overlay.setStyleSheet(f"""
            QLabel#blueLightFilter {{
                background-color: rgba(255, 166, 0, {opacity});
            }}
        """)
        
        if enabled:
            self.filter_overlay.show()
            self.filter_overlay.raise_()
        else:
            self.filter_overlay.hide()
            

    def on_audio_state_changed(self, muted):
        """Handle changes in audio playback state."""
        self.audio_visualizer.setVisible(not muted)
        if muted:
            self.audio_visualizer.setValue(0)
            
    def current_browser(self):
        """Get the current active browser widget."""
        current_widget = self.tab_widget.currentWidget()
        return current_widget.findChild(QWebEngineView) if current_widget else None





    def resizeEvent(self, event):
        """Handle window resize events to update filter overlay"""
        super().resizeEvent(event)
        if hasattr(self, 'filter_overlay') and self.filter_overlay is not None:
            self.filter_overlay.setGeometry(self.rect())

    def toggle_blue_light_filter(self, enabled=None):
        """Toggle blue light filter with visual feedback"""
        if enabled is None:
            enabled = not self.blue_light_filter_enabled
        
        self.blue_light_filter_enabled = enabled
        
        if enabled:
            opacity = self.blue_light_intensity * 0.3
            self.filter_overlay.setStyleSheet(
                f"QLabel#blueLightFilter {{ background-color: rgba(255, 166, 0, {opacity}); }}"
            )
            self.filter_overlay.show()
            self.filter_overlay.raise_()
        else:
            self.filter_overlay.hide()
        
        # Update button states
        if hasattr(self, 'blue_light_btn'):
            self.blue_light_btn.setChecked(enabled)
        if hasattr(self, 'blue_light_action'):
            self.blue_light_action.setChecked(enabled)


    def _select_window_and_record(self, duration, include_mic, include_system, quality):
        """Start recording after selecting a specific window."""
        # This would be platform-specific code to select a window
        # For now we'll just show a message
        QMessageBox.information(self, "Window Selection", 
            "Window selection recording is not yet implemented. Using full screen instead.")
        
        # Fall back to full screen recording
        self.start_recording(
            max_duration_minutes=duration // 60,
            include_mic=include_mic,
            include_speaker=include_system,
            quality=quality
        )



    def _select_window_and_record(self, duration, include_mic, include_system, quality):
        """Start recording after selecting a specific window."""
        if sys.platform == "linux":
            try:
                # Use xwininfo to get window geometry
                result = subprocess.run(
                    ["xwininfo"],  # Command to select a window and get its info
                    capture_output=True,
                    text=True,
                    check=True
                )

                # Parse xwininfo output to get the window geometry
                output_lines = result.stdout.splitlines()
                x, y, width, height = None, None, None, None
                for line in output_lines:
                    if "Absolute upper-left X:" in line:
                        x = int(line.split()[-1])
                    elif "Absolute upper-left Y:" in line:
                        y = int(line.split()[-1])
                    elif "Width:" in line:
                        width = int(line.split()[-1])
                    elif "Height:" in line:
                        height = int(line.split()[-1])

                if x is not None and y is not None and width is not None and height is not None:
                    # Create QRect from parsed values
                    rect = QRect(x, y, width, height)

                    # Start recording with the selected window region
                    success = self.screen_recorder.start_recording(
                        region=rect,
                        max_duration_minutes=duration // 60,
                        include_mic=include_mic,
                        include_speaker=include_system,
                        quality=quality
                    )

                    if not success:
                        self.status_bar.showMessage("Failed to start window recording", 3000)
                    else:
                        # Update UI to indicate recording started
                        self.record_btn.setText("⏹") # Or use appropriate icon/text
                        self.stop_recording_btn.show()
                        self.record_btn.hide()
                else:
                    self.status_bar.showMessage("Failed to parse window geometry", 3000)
                    QMessageBox.warning(self, "Error", "Could not parse window geometry from xwininfo output.")

            except FileNotFoundError:
                # xwininfo not found
                QMessageBox.warning(
                    self,
                    "Error",
                    "xwininfo tool not found. Please install x11-utils package:\n\n"
                    "sudo apt install x11-utils"
                )
            except subprocess.CalledProcessError as e:
                # xwininfo command failed (e.g., user cancelled)
                if e.returncode == 1: # Common return code for user cancellation or error in xwininfo
                     self.status_bar.showMessage("Window selection cancelled or failed.", 3000)
                else:
                     error_msg = f"xwininfo failed: {e.stderr}"
                     self.status_bar.showMessage(error_msg, 5000)
                     QMessageBox.warning(self, "Error", error_msg)
            except Exception as e:
                # Handle other potential errors (e.g., parsing issues, recorder start issues)
                error_msg = f"Error during window selection/recording start: {str(e)}"
                self.status_bar.showMessage(error_msg, 5000)
                QMessageBox.warning(self, "Error", error_msg)
                logging.error(f"_select_window_and_record (Linux) failed: {e}", exc_info=True) # Assuming logging is configured

        else:
            QMessageBox.information(self, "Not Supported",
                "Window selection recording is currently only supported on Linux (using xwininfo) and Windows (using pywin32).")

# Ensure you have `import logging` and `from PyQt5.QtCore import QRect` at the top of your file


    def _select_region_and_record(self, duration, include_mic, include_system, quality):
        """Start recording after selecting a custom region."""
        # Create transparent overlay for region selection
        self.recording_overlay = QLabel(self)
        self.recording_overlay.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        self.recording_overlay.setAttribute(Qt.WA_TranslucentBackground)
        self.recording_overlay.setStyleSheet("background-color: rgba(0,0,0,0.5);")
        self.recording_overlay.setGeometry(self.geometry())
        self.recording_overlay.show()

        # Create rubber band for visual selection
        self.recording_rubber_band = QRubberBand(QRubberBand.Rectangle, self.recording_overlay)
        self.recording_rubber_band.setStyleSheet("border: 2px dashed red;")

        # Store mouse events
        self.region_start_pos = None

        def mouse_press(event):
            self.region_start_pos = event.pos()
            self.recording_rubber_band.setGeometry(QRect(self.region_start_pos, QSize()))
            self.recording_rubber_band.show()

        def mouse_move(event):
            if self.region_start_pos:
                rect = QRect(self.region_start_pos, event.pos()).normalized()
                self.recording_rubber_band.setGeometry(rect)

        def mouse_release(event):
            if self.region_start_pos:
                rect = self.recording_rubber_band.geometry()
                self.recording_rubber_band.hide()
                self.recording_overlay.close()
                self._finalize_region_recording(rect, duration, include_mic, include_system, quality)

        # Assign mouse handlers
        self.recording_overlay.mousePressEvent = mouse_press
        self.recording_overlay.mouseMoveEvent = mouse_move
        self.recording_overlay.mouseReleaseEvent = mouse_release


    def _finalize_region_recording(self, rect, duration, include_mic, include_system, quality):
        """Start recording with the selected region."""
        if rect.width() > 100 and rect.height() > 100:  # Minimum size
            success = self.screen_recorder.start_recording(
                region=rect,
                max_duration_minutes=duration // 60,
                include_mic=include_mic,
                include_speaker=include_system,
                quality=quality
            )
            
            if success:
                self.record_btn.setText("⏹")
                self.stop_recording_btn.show()
                self.record_btn.hide()
            else:
                self.status_bar.showMessage("Failed to start region recording", 3000)
        else:
            self.status_bar.showMessage("Selected region too small", 3000)

    def create_window_callback(self, type_):
        """
        Callback to handle the creation of a new window/tab from a web page.
        """
        new_browser = self.add_new_tab(background=True)
        return new_browser.page()

    def setup_ui(self):
        """Setup the main browser UI with a modern Chrome-like black theme."""
        # Apply Chrome-inspired dark theme
        self.setStyleSheet("""
            QMainWindow {
                background-color: #202124;
                color: #e8eaed;
            }
            QTabWidget::pane {
                border: none;
                background: #292a2d;
                border-radius: 8px;
            }
            QTabBar::tab {
                background: #292a2d;
                color: #9aa0a6;
                padding: 8px 16px;
                margin-right: 1px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                border-bottom: 2px solid transparent;
            }
            QTabBar::tab:selected {
                color: #e8eaed;
                border-bottom: 2px solid #8ab4f8;
            }
            QTabBar::tab:hover {
                color: #e8eaed;
            }
            QToolBar {
                background: #292a2d;
                border: none;
                spacing: 6px;
                padding: 6px;
                border-radius: 8px;
            }
            QLineEdit {
                border: 1px solid #5f6368;
                border-radius: 24px;
                padding: 8px 16px;
                background: #202124;
                color: #e8eaed;
                selection-background-color: #8ab4f8;
            }
            QStatusBar {
                background: #292a2d;
                color: #9aa0a6;
                border-top: 1px solid #5f6368;
            }
            QProgressBar {
                background: #5f6368;
                border-radius: 2px;
                text-align: center;
            }
            QProgressBar::chunk {
                background: #8ab4f8;
                border-radius: 2px;
            }
            QToolButton {
                background: transparent;
                border: none;
                color: #9aa0a6;
                border-radius: 16px;
                min-width: 32px;
                max-width: 32px;
                min-height: 32px;
                max-height: 32px;
            }
            QToolButton:hover {
                background: rgba(232, 234, 237, 0.1);
                color: #e8eaed;
            }
            QToolButton:pressed {
                background: rgba(232, 234, 237, 0.2);
            }
            QToolButton:checked {
                background: rgba(138, 180, 248, 0.2);
                color: #8ab4f8;
            }
            QMenu {
                background: #292a2d;
                color: #e8eaed;
                border: 1px solid #5f6368;
                border-radius: 8px;
            }
            QMenu::item:selected {
                background: rgba(138, 180, 248, 0.2);
            }
        """)
        
        # Main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(0)
        
        # Tab bar with Chrome-like styling
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabsClosable(True)
        self.tab_widget.setMovable(True)
        self.tab_widget.tabCloseRequested.connect(self.close_tab)
        
        # Chrome-like new tab button
        self.new_tab_btn = QToolButton()
        self.new_tab_btn.setText("+")
        self.new_tab_btn.setCursor(Qt.PointingHandCursor)
        self.new_tab_btn.clicked.connect(self.add_new_tab)
        self.new_tab_btn.setStyleSheet("""
            QToolButton {
                background: transparent;
                border: none;
                color: #9aa0a6;
                border-radius: 16px;
                font-size: 18px;
                font-weight: bold;
                min-width: 28px;
                max-width: 28px;
                min-height: 28px;
                max-height: 28px;
            }
            QToolButton:hover {
                background: rgba(232, 234, 237, 0.1);
                color: #e8eaed;
            }
        """)
        # CHANGE: Move the new tab button to the left corner
        self.tab_widget.setCornerWidget(self.new_tab_btn, Qt.TopLeftCorner)
        layout.addWidget(self.tab_widget)
        
        # Navigation toolbar with Chrome-like styling
        self.navigation_toolbar = QToolBar("Navigation")
        self.navigation_toolbar.setMovable(False)
        self.navigation_toolbar.setIconSize(QSize(20, 20))
        self.addToolBar(self.navigation_toolbar)
        
        # Navigation buttons with Chrome-like styling
        nav_buttons = [
            ("back", "go-previous", "Back", "←"),
            ("forward", "go-next", "Forward", "→"),
            ("refresh", "view-refresh", "Refresh", "↻"),
            ("home", "go-home", "Home", "⌂")
        ]
        for var_name, icon_name, tooltip, fallback_text in nav_buttons:
            btn = QAction(fallback_text, self)
            icon = QIcon.fromTheme(icon_name)
            if not icon.isNull():
                btn.setIcon(icon)
            btn.setToolTip(tooltip)
            setattr(self, f"{var_name}_btn", btn)
            self.navigation_toolbar.addAction(btn)
        
        # URL bar container with Chrome-like styling
        url_container = QWidget()
        url_layout = QHBoxLayout(url_container)
        url_layout.setContentsMargins(0, 0, 0, 0)
        url_layout.setSpacing(6)
        
        # URL bar with Chrome-like styling
        self.url_bar = QLineEdit()
        self.url_bar.setPlaceholderText("Search or enter URL")
        url_layout.addWidget(self.url_bar)
        
        # Blue light filter button with Chrome-like styling
        self.blue_light_btn = QToolButton()
        self.blue_light_btn.setObjectName("blue_light_btn")
        self.blue_light_btn.setText("🌙")
        self.blue_light_btn.setToolTip("Toggle Blue Light Filter")
        self.blue_light_btn.setCheckable(True)
        self.blue_light_btn.setChecked(self.blue_light_filter_enabled)
        self.blue_light_btn.clicked.connect(self.toggle_blue_light_filter)
        url_layout.addWidget(self.blue_light_btn)
        
        # Screen recording button with Chrome-like styling
        self.record_btn = QToolButton()
        record_icon = QIcon.fromTheme("media-record")
        if record_icon.isNull():
            self.record_btn.setText("●")
        else:
            self.record_btn.setIcon(record_icon)
        self.record_btn.setToolTip("Start Recording (Ctrl+Shift+R)")
        self.record_btn.setStyleSheet("""
            QToolButton {
                color: #f28b82;
            }
            QToolButton:hover {
                background: rgba(242, 139, 130, 0.1);
            }
        """)
        self.record_btn.clicked.connect(self.show_recording_control_panel)
        url_layout.addWidget(self.record_btn)
        
        # Stop recording button with Chrome-like styling
        self.stop_recording_btn = QToolButton()
        stop_icon = QIcon.fromTheme("media-playback-stop")
        if stop_icon.isNull():
            self.stop_recording_btn.setText("■")
        else:
            self.stop_recording_btn.setIcon(stop_icon)
        self.stop_recording_btn.setToolTip("Stop Recording")
        self.stop_recording_btn.setStyleSheet("""
            QToolButton {
                color: #f28b82;
            }
            QToolButton:hover {
                background: rgba(242, 139, 130, 0.1);
            }
        """)
        self.stop_recording_btn.hide()
        self.stop_recording_btn.clicked.connect(self.on_stop_recording_clicked)
        url_layout.addWidget(self.stop_recording_btn)
        self.apply_recorder_theme()
        
        # Right-side action buttons with Chrome-like styling
        action_buttons = [
            ("print", "document-print", "Print page (Ctrl+P)", "🖨️", self.print_current_page),
            ("pdf", "document-export", "Save as PDF (Ctrl+Shift+P)", "📄", self.print_to_pdf),
            ("screenshot", "camera-photo", "Take screenshot (Ctrl+Shift+S)", "📷", lambda: self.take_screenshot("ask")),
            ("calendar", "view-calendar", "Calendar (Ctrl+Shift+C)", "📅", self.show_calendar),
            ("incognito", "view-private", "New Incognito Tab", "👤", self.add_incognito_tab),
        ]
        for var_name, icon_name, tooltip, fallback_text, handler in action_buttons:
            btn = QToolButton()
            icon = QIcon.fromTheme(icon_name)
            if icon.isNull():
                btn.setText(fallback_text)
            else:
                btn.setIcon(icon)
            btn.setToolTip(tooltip)
            btn.clicked.connect(handler)
            setattr(self, f"{var_name}_btn", btn)
            url_layout.addWidget(btn)
            
            # Special setup for screenshot button
            if var_name == "screenshot":
                btn.setPopupMode(QToolButton.MenuButtonPopup)
                menu = QMenu()
                actions = [
                    ("edit-copy", "Copy to Clipboard", "📋", "clipboard"),
                    ("document-save", "Save to File", "💾", "file"),
                    ("select-rectangular", "Capture Region", "⭕", "region")
                ]
                for icon_name, text, fallback_icon, mode in actions:
                    action = QAction(fallback_icon + " " + text, self)
                    icon = QIcon.fromTheme(icon_name)
                    if not icon.isNull():
                        action.setIcon(icon)
                    action.triggered.connect(lambda _, m=mode: self.take_screenshot(m))
                    menu.addAction(action)
                btn.setMenu(menu)
        
        # Add URL container to toolbar
        self.navigation_toolbar.addWidget(url_container)
        
        # Right-side navigation buttons with Chrome-like styling
        nav_buttons_right = [
            ("search", "system-search", "Search", "🔍"),
            ("bookmarks", "bookmarks", "Bookmarks", "📑"),
            ("downloads", "folder-download", "Downloads", "⏬"),
            ("history", "view-history", "History", "🕒"),
            ("settings", "preferences-system", "Settings", "⚙️")
        ]
        for var_name, icon_name, tooltip, fallback_text in nav_buttons_right:
            btn = QAction(fallback_text, self)
            icon = QIcon.fromTheme(icon_name)
            if not icon.isNull():
                btn.setIcon(icon)
            btn.setToolTip(tooltip)
            setattr(self, f"{var_name}_btn", btn)
            self.navigation_toolbar.addAction(btn)
        
        # Initialize status bar with Chrome-like styling
        status_bar = self.statusBar()
        
        # Recording status label with Chrome-like styling
        self.recording_status_label = QLabel()
        self.recording_status_label.setStyleSheet("""
            QLabel {
                color: #f28b82;
                font-weight: normal;
                padding: 0 5px;
                background: rgba(242, 139, 130, 0.1);
                border-radius: 4px;
            }
        """)
        status_bar.addPermanentWidget(self.recording_status_label)
        self.recording_status_label.hide()
        
        # Download progress bar with Chrome-like styling
        self.download_progress_bar = QProgressBar()
        self.download_progress_bar.setTextVisible(False)
        self.download_progress_bar.setFixedHeight(2)
        self.download_progress_bar.setStyleSheet("""
            QProgressBar {
                background: #5f6368;
                border-radius: 1px;
            }
            QProgressBar::chunk {
                background: #8ab4f8;
                border-radius: 1px;
            }
        """)
        self.download_progress_bar.hide()
        status_bar.addPermanentWidget(self.download_progress_bar)
        
        # Connect tab close signal
        self.tab_widget.tabCloseRequested.connect(self.close_tab_handler)
        
        # Initialize blue light filter overlay with Chrome-like styling
        self.filter_overlay = QLabel(self)
        self.filter_overlay.setObjectName("blueLightFilter")
        self.filter_overlay.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.filter_overlay.setStyleSheet("""
            QLabel#blueLightFilter {
                background-color: rgba(255, 166, 0, 0);
            }
        """)
        self.filter_overlay.hide()
        self.filter_overlay.lower()
        self.filter_overlay.setGeometry(self.rect())

    def toggle_recording(self):
        """Toggle screen recording on/off."""
        if self.screen_recorder.is_recording():
            self.screen_recorder.stop_recording()
            self.record_btn.setText("⏺")
        else:
            if self.screen_recorder.start_recording():
                self.record_btn.setText("⏹")
            else:
                self.status_bar.showMessage("Failed to start recording", 3000)

    def start_recording(self, max_duration_minutes=0, include_mic=True, include_speaker=True, quality=1):
        """Start recording with the specified parameters."""
        # Get audio settings from preferences if not specified
        record_mic = include_mic if include_mic is not None else self.settings_manager.get("recording_microphone", True)
        record_system = include_speaker if include_speaker is not None else self.settings_manager.get("recording_system_audio", True)
        
        success = self.screen_recorder.start_recording(
            max_duration_minutes=max_duration_minutes,
            include_mic=record_mic,
            include_speaker=record_system,
            quality=quality
        )
        
        if success:
            self.record_btn.setText("⏹")
            self.stop_recording_btn.show()
            self.record_btn.hide()
        else:
            self.status_bar.showMessage("Failed to start recording", 3000)
        return success

        def start_region_recording(self):
            """Start recording a selected screen region."""
            # Create transparent overlay for region selection
            self.recording_overlay = QLabel(self)
            self.recording_overlay.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
            self.recording_overlay.setAttribute(Qt.WA_TranslucentBackground)
            self.recording_overlay.setStyleSheet("background-color: rgba(0,0,0,0.5);")
            self.recording_overlay.setGeometry(QApplication.desktop().screenGeometry())
            self.recording_overlay.show()

            # Create selection rubber band
            self.recording_rubber_band = QRubberBand(QRubberBand.Rectangle, self.recording_overlay)
            self.recording_rubber_band.setStyleSheet("border: 2px dashed red;")

            # Connect mouse events
            self.recording_overlay.mousePressEvent = self.recording_region_mouse_press
            self.recording_overlay.mouseMoveEvent = self.recording_region_mouse_move
            self.recording_overlay.mouseReleaseEvent = self.recording_region_mouse_release

        def recording_region_mouse_press(self, event):
            """Handle mouse press for region selection."""
            self.recording_region_start = event.pos()
            self.recording_rubber_band.setGeometry(QRect(self.recording_region_start, QSize()))
            self.recording_rubber_band.show()

        def recording_region_mouse_move(self, event):
            """Handle mouse move for region selection."""
            if hasattr(self, 'recording_region_start'):
                self.recording_rubber_band.setGeometry(
                    QRect(self.recording_region_start, event.pos()).normalized()
                )







    def closeEvent(self, event):
        """Clean up resources"""
        if self.filter_overlay:
            self.filter_overlay.deleteLater()
        super().closeEvent(event)




    def show_audio_settings(self):
        """Show audio settings dialog for screen recording."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Audio Settings")
        dialog.setMinimumWidth(300)
        
        layout = QVBoxLayout()
        
        # Audio source selection
        audio_group = QGroupBox("Audio Sources")
        audio_layout = QVBoxLayout()
        
        # Microphone checkbox
        self.mic_check = QCheckBox("Record Microphone")
        self.mic_check.setChecked(self.settings_manager.get("recording_microphone", True))
        audio_layout.addWidget(self.mic_check)
        
        # System audio checkbox
        self.system_audio_check = QCheckBox("Record System Audio")
        self.system_audio_check.setChecked(self.settings_manager.get("recording_system_audio", True))
        audio_layout.addWidget(self.system_audio_check)
        
        audio_group.setLayout(audio_layout)
        layout.addWidget(audio_group)

        # Volume controls
        volume_group = QGroupBox("Volume Levels")
        volume_layout = QVBoxLayout()
        
        # Microphone volume slider
        mic_volume_layout = QHBoxLayout()
        mic_volume_layout.addWidget(QLabel("Mic Volume:"))
        self.mic_volume_slider = QSlider(Qt.Horizontal)
        self.mic_volume_slider.setRange(0, 100)
        self.mic_volume_slider.setValue(self.settings_manager.get("mic_volume", 80))
        mic_volume_layout.addWidget(self.mic_volume_slider)
        volume_layout.addLayout(mic_volume_layout)
        
        # System volume slider
        system_volume_layout = QHBoxLayout()
        system_volume_layout.addWidget(QLabel("System Volume:"))
        self.system_volume_slider = QSlider(Qt.Horizontal)
        self.system_volume_slider.setRange(0, 100)
        self.system_volume_slider.setValue(self.settings_manager.get("system_volume", 80))
        system_volume_layout.addWidget(self.system_volume_slider)
        volume_layout.addLayout(system_volume_layout)
        
        volume_group.setLayout(volume_layout)
        layout.addWidget(volume_group)

        # Dialog buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(dialog.accept)
        button_box.rejected.connect(dialog.reject)
        layout.addWidget(button_box)
        
        dialog.setLayout(layout)
        
        if dialog.exec_() == QDialog.Accepted:
            # Save settings
            self.settings_manager.set("recording_microphone", self.mic_check.isChecked())
            self.settings_manager.set("recording_system_audio", self.system_audio_check.isChecked())
            self.settings_manager.set("mic_volume", self.mic_volume_slider.value())
            self.settings_manager.set("system_volume", self.system_volume_slider.value())



    def eventFilter(self, obj, event):
        """Handle hover events for the new tab button"""
        if obj == self.new_tab_btn:
            if event.type() == QEvent.Enter:
                # Mouse enters - change to red
                self.new_tab_btn.setStyleSheet("""
                    QToolButton {
                        background-color: yellow;
                        color: red;
                        border: 1px;
                        padding: 5px;
                        border-radius: 4px;
                        font-size: 16px;
                        font-weight: bold;
                        min-width: 24px;
                        max-width: 24px;
                    }
                """)
                return True
            elif event.type() == QEvent.Leave:
                # Mouse leaves - revert to normal
                self.new_tab_btn.setStyleSheet("""
                    QToolButton {
                        background-color: ;
                        color: white;
                        border: none;
                        padding: 5px;
                        border-radius: 4px;
                        font-size: 16px;
                        font-weight: bold;
                        min-width: 24px;
                        max-width: 24px;
                    }
                """)
                return True
        return super().eventFilter(obj, event)



    def start_region_screenshot(self):
        """Start capturing a custom rectangular region of the screen."""
        from PyQt5.QtWidgets import QApplication, QLabel, QRubberBand
        from PyQt5.QtCore import Qt, QRect

        # Create overlay and capture logic similar to what was pasted earlier
        self.screenshot_overlay = QLabel(self)
        self.screenshot_overlay.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        self.screenshot_overlay.setAttribute(Qt.WA_TranslucentBackground)
        self.screenshot_overlay.setStyleSheet("background-color: rgba(0,0,0,0.5);")
        self.screenshot_overlay.setGeometry(self.geometry())
        
        self.rubber_band = QRubberBand(QRubberBand.Rectangle, self.screenshot_overlay)
        self.screenshot_overlay.mousePressEvent = self.region_mouse_press
        self.screenshot_overlay.mouseMoveEvent = self.region_mouse_move
        self.screenshot_overlay.mouseReleaseEvent = self.region_mouse_release
        
        self.screenshot_overlay.show()

    def region_mouse_press(self, event):
        self.origin = event.pos()
        self.rubber_band.setGeometry(QRect(self.origin, event.pos()).normalized())
        self.rubber_band.show()

    def region_mouse_move(self, event):
        if self.rubber_band.isVisible():
            self.rubber_band.setGeometry(QRect(self.origin, event.pos()).normalized())

    def region_mouse_release(self, event):
        rect = self.rubber_band.geometry()
        self.rubber_band.hide()
        self.screenshot_overlay.hide()
        
        # Finalize the capture
        self._capture_region_final(rect)


    def close_tab_handler(self, index):
        """Properly clean up web engine before closing tab"""
        widget = self.tab_widget.widget(index)
        
        if widget:
            # Find the web view in the tab
            webview = widget.findChild(QWebEngineView)
            if webview:
                # Stop media playback
                webview.page().setAudioMuted(True)
                webview.page().runJavaScript("""
                    document.querySelectorAll('video, audio').forEach(media => {
                        media.pause();
                        media.currentTime = 0;
                        media.removeAttribute('src');
                    });
                """)
                
                # Clear browsing data
                webview.page().profile().clearHttpCache()
                
                # Store closed tab info for possible restoration
                self.closed_tabs.append({
                    'url': webview.url().toString(),
                    'title': self.tab_widget.tabText(index),
                    'content': webview.page().toHtml(lambda html: html)
                })
                
                # Clean up the web view
                webview.setPage(QWebEnginePage())
                webview.page().deleteLater()
                webview.deleteLater()
        
        # Remove the tab
        self.tab_widget.removeTab(index)
        
        # If last tab was closed, create a new empty tab
        if self.tab_widget.count() == 0:
            self.add_new_tab(QUrl(self.settings_manager.get("home_page")))


    def setup_connections(self):
        """Connect signals to slots."""
        # Navigation buttons
        self.back_btn.triggered.connect(lambda: self.current_browser().back())
        self.forward_btn.triggered.connect(lambda: self.current_browser().forward())
        self.refresh_btn.triggered.connect(lambda: self.current_browser().reload())
        self.home_btn.triggered.connect(self.go_home)
        self.url_bar.returnPressed.connect(self.navigate_to_url)
        self.search_btn.triggered.connect(self.toggle_multi_site_search)
        self.bookmarks_btn.triggered.connect(self.show_bookmarks)
        self.downloads_btn.triggered.connect(self.show_downloads)
        self.history_btn.triggered.connect(self.show_history)
        self.settings_btn.triggered.connect(self.show_settings)
        self.incognito_btn.triggered.connect(self.add_incognito_tab)
        
        # Download manager signals
        self.download_manager.download_started.connect(self.on_download_started)
        self.download_manager.download_progress.connect(self.on_download_progress)
        self.download_manager.download_finished.connect(self.on_download_finished)
        self.download_manager.download_list_updated.connect(self.update_downloads_lists)

    def _setup_password_handling(self):
        """Setup auto-save and auto-fill for passwords"""
        for i in range(self.tab_widget.count()):
            browser = self.tab_widget.widget(i).findChild(QWebEngineView)
            if browser:
                self._connect_password_handlers(browser)

    def _connect_password_handlers(self, browser):
        """Connect password handlers to a browser instance"""
        # Auto-fill detection
        browser.page().loadFinished.connect(
            lambda ok, browser=browser: self._auto_fill_passwords(browser) if ok else None)
        
        # Auto-save detection
        browser.page().featurePermissionRequested.connect(
            lambda url, feature, browser=browser: self._handle_password_save(browser, url, feature))

    def _auto_fill_passwords(self, browser):
        """Robust auto-fill that handles most modern login forms"""
        url = browser.url().toString()
        credentials = self.password_manager.get_password(url)
        if credentials:
            # JavaScript with comprehensive field detection
            js = """
            function fillCredentials(u, p) {
                // Priority list of username field selectors
                const userSelectors = [
                    'input[autocomplete="username"]',
                    'input[type="email"]', 
                    'input[name*="user"]',
                    'input[id*="user"]',
                    'input[name*="login"]',
                    'input[autocomplete="email"]',
                    'input[name="email"]'
                ];
                
                // Priority list of password field selectors
                const passSelectors = [
                    'input[autocomplete="current-password"]',
                    'input[type="password"]',
                    'input[name*="pass"]',
                    'input[id*="pass"]'
                ];
                
                // Fill first matching username field
                userSelectors.some(sel => {
                    const field = document.querySelector(sel);
                    if (field && !field.value) {
                        field.value = u;
                        return true;
                    }
                    return false;
                });
                
                // Fill first matching password field
                passSelectors.some(sel => {
                    const field = document.querySelector(sel);
                    if (field && !field.value) {
                        field.value = p;
                        return true;
                    }
                    return false;
                });
            }
            
            fillCredentials('%s', '%s');
            """ % (
                credentials['username'].replace("'", r"\'"),
                credentials['password'].replace("'", r"\'")
            )
            
            # Run with 1s delay to ensure all dynamic elements are loaded
            QTimer.singleShot(1000, lambda: browser.page().runJavaScript(js))

    def _handle_password_save(self, browser, url, feature):
        """Improved password save detection"""
        if feature == QWebEnginePage.Feature.PasswordManager:
            browser.page().runJavaScript("""
                function getFormData() {
                    try {
                        const forms = document.querySelectorAll('form');
                        for (const form of forms) {
                            const inputs = form.querySelectorAll('input');
                            let username = '';
                            let password = '';
                            
                            for (const input of inputs) {
                                if ((input.type === 'text' || input.type === 'email') && 
                                    !username && 
                                    (input.id.includes('user') || 
                                     input.name.includes('user') ||
                                     input.placeholder.includes('name'))) {
                                    username = input.value;
                                }
                                
                                if (input.type === 'password' && !password) {
                                    password = input.value;
                                }
                            }
                            
                            if (username && password) {
                                return {
                                    username: username,
                                    password: password
                                };
                            }
                        }
                        return null;
                    } catch (e) {
                        console.log('Password save error:', e);
                        return null;
                    }
                }
                getFormData();
            """, lambda result: self._save_password_data(url, result) if result else None)

    def _save_password_data(self, url, form_data):
        """Save password data after user confirmation"""
        if form_data and form_data.get('username') and form_data.get('password'):
            reply = QMessageBox.question(
                self,
                "Save Password?",
                "Would you like to save the password for this site?",
                QMessageBox.Yes | QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                self.password_manager.save_password(
                    url.toString(),
                    form_data['username'],
                    form_data['password']
                )



    def print_current_page(self):
        """Print current page with option for PDF output."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Print Options")
        
        layout = QVBoxLayout()
        
        # Regular print button
        print_btn = QPushButton("Print to Printer")
        print_btn.clicked.connect(lambda: [
            self._print_to_printer(),
            dialog.close()
        ])
        
        # PDF print button
        pdf_btn = QPushButton("Save as PDF")
        pdf_btn.clicked.connect(lambda: [
            self.print_to_pdf(),
            dialog.close()
        ])
        
        layout.addWidget(print_btn)
        layout.addWidget(pdf_btn)
        dialog.setLayout(layout)
        dialog.exec_()

    def _print_to_printer(self):
        """Handle actual printer output"""
        if browser := self.current_browser():
            printer = QPrinter(QPrinter.HighResolution)
            print_dialog = QPrintDialog(printer, self)
            
            if print_dialog.exec_() == QPrintDialog.Accepted:
                browser.page().print(printer, lambda success: 
                    self.status_bar.showMessage(
                        "Printing completed" if success else "Printing failed",
                        3000
                    )
                )
    def print_to_pdf(self):
        """Print current page to PDF file."""
        if browser := self.current_browser():
            # Set up default PDF filename with timestamp
            default_name = f"page_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            default_path = os.path.join(DOWNLOAD_DIR, default_name)
            
            # Get save path from user
            filename, _ = QFileDialog.getSaveFileName(
                self,
                "Save as PDF",
                default_path,
                "PDF Files (*.pdf);;All Files (*)"
            )
            
            if filename:
                # Ensure .pdf extension
                if not filename.lower().endswith('.pdf'):
                    filename += '.pdf'
                
                # Show saving message
                self.status_bar.showMessage("Saving PDF...", 3000)
                
                # Print to PDF
                browser.page().printToPdf(filename)
                
                # Show completion message
                self.status_bar.showMessage(f"PDF saved to {filename}", 5000)
                
                # Optional: Open the PDF after saving
                QTimer.singleShot(1000, lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(filename)))


    def take_screenshot(self, mode="ask"):
        """
        Handle screenshot capture with multiple output options
        Modes: "ask" (show dialog), "clipboard", "file"
        """
        if browser := self.current_browser():
            try:
                # Show busy cursor during capture
                QApplication.setOverrideCursor(Qt.WaitCursor)
                
                # Capture the viewport
                pixmap = browser.grab()
                
                # Restore cursor
                QApplication.restoreOverrideCursor()
                
                if mode == "clipboard":
                    self._save_screenshot_to_clipboard(pixmap)
                elif mode == "file":
                    self._save_screenshot_to_file(pixmap)
                else:  # ask
                    self._show_screenshot_options(pixmap)
                    
            except Exception as e:
                self.status_bar.showMessage(f"Screenshot error: {str(e)}", 3000)
                QApplication.restoreOverrideCursor()
                logging.error(f"Screenshot failed: {str(e)}", exc_info=True)

    def _save_screenshot_to_clipboard(self, pixmap):
        """Save screenshot to clipboard with visual feedback"""
        try:
            clipboard = QApplication.clipboard()
            clipboard.setPixmap(pixmap)
            
            # Show brief notification
            self.notification_manager.show_notification(
                "Screenshot Copied",
                "The screenshot was copied to clipboard",
                2000
            )
            
            # Also show in status bar
            self.status_bar.showMessage("Screenshot copied to clipboard", 3000)
            
        except Exception as e:
            self.status_bar.showMessage(f"Clipboard error: {str(e)}", 3000)
            logging.error(f"Clipboard save failed: {str(e)}", exc_info=True)

    def _save_screenshot_to_file(self, pixmap, suggested_path=None):
        """Save screenshot to file with intelligent defaults"""
        try:
            # Set default save location
            screenshot_dir = os.path.join(
                os.path.expanduser("~"), 
                "Pictures",
                "Screenshots"
            )
            os.makedirs(screenshot_dir, exist_ok=True)
            
            # Generate filename with timestamp
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            default_filename = f"StormBrowser_{timestamp}.png"
            
            # Use suggested path if provided (from drag/drop or other operations)
            if suggested_path and os.path.isdir(os.path.dirname(suggested_path)):
                default_path = suggested_path
            else:
                default_path = os.path.join(screenshot_dir, default_filename)
            
            # Show save dialog
            filename, _ = QFileDialog.getSaveFileName(
                self,
                "Save Screenshot",
                default_path,
                "PNG Images (*.png);;JPEG Images (*.jpg *.jpeg);;BMP Images (*.bmp);;All Files (*)"
            )
            
            if filename:
                # Ensure proper file extension
                if not filename.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp')):
                    filename += '.png'
                
                # Save with quality settings
                if filename.lower().endswith(('.jpg', '.jpeg')):
                    quality = 95  # High quality JPEG
                    pixmap.save(filename, quality=quality)
                else:
                    pixmap.save(filename)
                
                # Show notification with click-to-open functionality
                notification = self.notification_manager.show_notification(
                    "Screenshot Saved",
                    f"Saved to {os.path.basename(filename)}",
                    3000
                )
                
                # Add click handler to open the file
                if notification:
                    notification.mousePressEvent = lambda e: QDesktopServices.openUrl(
                        QUrl.fromLocalFile(filename)
                    )
                
                self.status_bar.showMessage(f"Screenshot saved to {filename}", 5000)
                
        except Exception as e:
            self.status_bar.showMessage(f"Save error: {str(e)}", 3000)
            logging.error(f"Screenshot save failed: {str(e)}", exc_info=True)

    def _show_screenshot_options(self, pixmap):
            """Show dialog with screenshot options"""
            dialog = QDialog(self)
            dialog.setWindowTitle("Screenshot Options")
            dialog.setWindowModality(Qt.WindowModal)
            dialog.setMinimumWidth(300)
            
            layout = QVBoxLayout()
            
            # Preview thumbnail
            preview_label = QLabel()
            preview_pixmap = pixmap.scaled(
                400, 300, 
                Qt.KeepAspectRatio, 
                Qt.SmoothTransformation
            )
            preview_label.setPixmap(preview_pixmap)
            preview_label.setAlignment(Qt.AlignCenter)
            layout.addWidget(preview_label)
            
            # Button options
            btn_layout = QVBoxLayout()
            
            copy_btn = QPushButton("Copy to Clipboard")
            copy_btn.clicked.connect(lambda: [
                self._save_screenshot_to_clipboard(pixmap),
                dialog.close()
            ])
            btn_layout.addWidget(copy_btn)
            
            save_btn = QPushButton("Save to File...")
            save_btn.clicked.connect(lambda: [
                self._save_screenshot_to_file(pixmap),
                dialog.close()
            ])
            btn_layout.addWidget(save_btn)
            
            # Advanced options expandable section
            advanced_group = QGroupBox("Advanced Options")
            advanced_group.setCheckable(True)
            advanced_group.setChecked(False)
            advanced_layout = QVBoxLayout()
            
            # Delay capture option
            delay_layout = QHBoxLayout()
            delay_label = QLabel("Delay (seconds):")
            delay_spin = QSpinBox()
            delay_spin.setRange(0, 10)
            delay_spin.setValue(0)
            delay_layout.addWidget(delay_label)
            delay_layout.addWidget(delay_spin)
            advanced_layout.addLayout(delay_layout)
            
            # Region capture option
            region_capture_btn = QPushButton("Capture Specific Region")
            region_capture_btn.clicked.connect(lambda: [
                self._capture_region(),
                dialog.close()
            ])
            advanced_layout.addWidget(region_capture_btn)
            
            advanced_group.setLayout(advanced_layout)
            btn_layout.addWidget(advanced_group)
            
            layout.addLayout(btn_layout)
            
            # Close button
            close_btn = QPushButton("Cancel")
            close_btn.clicked.connect(dialog.close)
            layout.addWidget(close_btn)
            
            dialog.setLayout(layout)
            dialog.exec_()

    def _capture_region(self):
        """Capture a custom region of the browser window."""
        # Create transparent overlay for region selection
        overlay = QLabel(self)
        overlay.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        overlay.setAttribute(Qt.WA_TranslucentBackground)
        overlay.setStyleSheet("background-color: rgba(0,0,0,0.5);")
        overlay.setGeometry(self.geometry())
        overlay.show()

        # Create selection rubber band
        rubber_band = QRubberBand(QRubberBand.Rectangle, overlay)
        rubber_band.setStyleSheet("border: 2px dashed blue;")

        start_pos = None
        selection_rect = None
        
        def mouse_press(event):
            nonlocal start_pos
            start_pos = event.pos()
            rubber_band.setGeometry(QRect(start_pos, QSize()))
            rubber_band.show()
        
        def mouse_move(event):
            if start_pos:
                rubber_band.setGeometry(QRect(start_pos, event.pos()).normalized())
        
        def mouse_release(event):
            nonlocal start_pos, selection_rect
            if start_pos:
                selection_rect = rubber_band.geometry()
                if selection_rect.width() > 10 and selection_rect.height() > 10:  # Minimum size
                    # Hide rubber band before capturing
                    rubber_band.hide()
                    overlay.hide()
                    
                    # Small delay to ensure UI updates before capture
                    QTimer.singleShot(50, lambda: self._capture_region_final(selection_rect))
                
                rubber_band.hide()
                overlay.hide()
                start_pos = None
        
        overlay.mousePressEvent = mouse_press
        overlay.mouseMoveEvent = mouse_move
        overlay.mouseReleaseEvent = mouse_release

    def _capture_region_final(self, rect):
        """Final step to capture the region after UI elements are hidden."""
        # Capture the selected region from the browser window
        screenshot = QPixmap(rect.size())
        painter = QPainter(screenshot)
        self.render(painter, QPoint(), QRegion(rect))
        painter.end()
        
        self._show_screenshot_options(screenshot)



    def setup_shortcuts(self):
        """Set up global keyboard shortcuts for the browser."""

        # Clear any existing shortcuts to avoid duplication
        if hasattr(self, 'shortcuts'):
            for shortcut in self.shortcuts:
                shortcut.setEnabled(False)
                shortcut.disconnect()

        self.shortcuts = []

        def _create_shortcut(key_sequence, callback):
            """Helper to create and store a QShortcut"""
            shortcut = QShortcut(QKeySequence(key_sequence), self)
            shortcut.setContext(Qt.ApplicationShortcut)  # Works globally
            shortcut.activated.connect(callback)
            self.shortcuts.append(shortcut)

        # Get current shortcut values from settings or use defaults
        get_shortcut = lambda action: self.settings_manager.get_shortcut(action)

        # === Navigation Shortcuts ===
        _create_shortcut(get_shortcut("back"), lambda: self.current_browser().back())
        _create_shortcut(get_shortcut("forward"), lambda: self.current_browser().forward())
        _create_shortcut(get_shortcut("reload"), lambda: self.current_browser().reload())
        _create_shortcut(get_shortcut("reload_ignore_cache"), lambda: self.current_browser().reloadAndBypassCache())
        _create_shortcut(Qt.Key_Escape, lambda: self.current_browser().stop() if self.current_browser() else None)
        _create_shortcut(get_shortcut("home"), self.go_home)

        # === Tab Management ===
        _create_shortcut(get_shortcut("new_tab"), self.add_new_tab)
        _create_shortcut(get_shortcut("close_tab"), lambda: self.close_tab(self.tab_widget.currentIndex()))
        _create_shortcut(get_shortcut("next_tab"), self.focus_next_tab)
        _create_shortcut(get_shortcut("prev_tab"), self.focus_prev_tab)
        _create_shortcut(get_shortcut("restore_tab"), self.restore_closed_tab)

        # === Focus Shortcuts ===
        _create_shortcut(get_shortcut("focus_url"), self.focus_url_bar)
        _create_shortcut(get_shortcut("focus_search"), self.focus_search_bar)

        # === Tools and Features ===
        _create_shortcut(get_shortcut("bookmark_search"), self.show_bookmarks)
        _create_shortcut(get_shortcut("multi_site_search"), self.toggle_multi_site_search)
        _create_shortcut(get_shortcut("bookmark_page"), self.add_current_to_bookmarks)
        _create_shortcut(get_shortcut("downloads"), self.show_downloads)
        _create_shortcut(get_shortcut("history"), self.show_history)
        _create_shortcut(get_shortcut("print"), self.print_current_page)
        _create_shortcut(get_shortcut("print_pdf"), self.print_to_pdf)
        _create_shortcut(get_shortcut("screenshot"), lambda: self.take_screenshot("ask"))
        _create_shortcut(get_shortcut("full_screenshot"), lambda: self.take_full_page_screenshot())
        _create_shortcut(get_shortcut("region_screenshot"), lambda: self.start_region_screenshot())
        _create_shortcut(get_shortcut("dev_tools"), self.toggle_dev_tools)
        _create_shortcut(get_shortcut("view_source"), lambda: self.current_browser().page().runJavaScript("document.documentElement.outerHTML"))
        _create_shortcut(get_shortcut("calendar"), self.toggle_calendar)

        # === Zoom Shortcuts ===
        _create_shortcut(get_shortcut("zoom_in"), self.zoom_in)
        _create_shortcut(get_shortcut("zoom_out"), self.zoom_out)
        _create_shortcut(get_shortcut("zoom_reset"), self.zoom_reset)

        # === Search / URL Shortcuts ===
        _create_shortcut(get_shortcut("autocomplete_url"), self.autocomplete_url)
        _create_shortcut(get_shortcut("search_selected"), self.search_selected_text)

        # === Find Shortcut ===
        _create_shortcut("Ctrl+F", self.show_find_bar)

        # === Settings Shortcut (Dynamic) ===
        _create_shortcut(get_shortcut("settings"), self.show_settings)
        _create_shortcut(get_shortcut("incognito_tab"), self.add_incognito_tab)


    def _create_shortcut(self, key_sequence, callback):
        """Helper to create and store a QShortcut"""
        shortcut = QShortcut(QKeySequence(key_sequence), self)
        shortcut.setContext(Qt.ApplicationShortcut)  # Works globally
        shortcut.activated.connect(callback)
        return shortcut


    def focus_next_tab(self):
        """Focus the next tab."""
        current = self.tab_widget.currentIndex()
        next_index = (current + 1) % self.tab_widget.count()
        self.tab_widget.setCurrentIndex(next_index)

    def focus_prev_tab(self):
        """Focus the previous tab."""
        current = self.tab_widget.currentIndex()
        prev_index = (current - 1) % self.tab_widget.count()
        self.tab_widget.setCurrentIndex(prev_index)

    def reload_current_tab(self):
        """Reload current tab."""
        if browser := self.current_browser():
            browser.reload()

    def focus_url_bar(self):
        """Focus the URL bar and select all text."""
        self.url_bar.setFocus()
        self.url_bar.selectAll()


    def autocomplete_url(self):
        url_text = self.url_bar.text().strip()
        if url_text and "." not in url_text:
            url_text = "www." + url_text + ".com"
        if not url_text.startswith(("http://", "https://")):
            url_text = "https://" + url_text
        self.url_bar.setText(url_text)
        if browser := self.current_browser():
            browser.setUrl(QUrl(url_text))




    def current_browser(self):
        """Get the current QWebEngineView."""
        current_widget = self.tab_widget.currentWidget()
        if current_widget:
            return current_widget.findChild(QWebEngineView)
        return None
#------------------------------------------------------------------------------------------------------------




    from PyQt5.QtWebEngineCore import QWebEngineHttpRequest

    def add_new_tab(self, url=None, title="New Tab", background=False, widget=None, profile_override=None):
        """
        Adds a new browser tab with enhanced compatibility for Cloudflare, Netflix DRM, OpenAI, and Z.AI.
        """
        def truncate_title(t, max_len=15):
            return t[:max_len - 3] + "..." if len(t) > max_len else t
        
        # Prepare URL
        if url:
            qurl = QUrl.fromUserInput(url) if isinstance(url, str) else url
        else:
            home_page = self.settings_manager.get("home_page")
            qurl = QUrl.fromUserInput(home_page) if home_page else QUrl("about:blank")
        
        # Custom widget
        if widget:
            display_title = truncate_title(title)
            tab_index = self.tab_widget.addTab(widget, display_title)
            self.tab_widget.setTabToolTip(tab_index, title)
            if not background:
                def focus_custom_tab():
                    self.tab_widget.setCurrentIndex(tab_index)
                    self.activateWindow()
                    widget.setFocus(Qt.OtherFocusReason)
                    QTimer.singleShot(10, self.focus_url_bar)
                QTimer.singleShot(25, focus_custom_tab)
            return widget
        
        # Create container and layout
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        container.setFocusPolicy(Qt.NoFocus)
        browser = QWebEngineView()
        browser.setFocusPolicy(Qt.StrongFocus)
        
        # Check if we're loading Netflix
        is_netflix = qurl and qurl.isValid() and "netflix.com" in qurl.host()
        
        # Profile selection
        if profile_override:
            profile_to_use = profile_override
        elif is_netflix:
            # Use Netflix profile with DRM support
            if hasattr(self, 'netflix_drm_handler') and self.netflix_drm_handler.widevine_available:
                try:
                    profile_to_use = self.netflix_drm_handler.get_netflix_profile()
                    print("[INFO] Using Netflix profile for DRM support")
                except Exception as e:
                    print(f"[ERROR] Failed to get Netflix profile: {e}")
                    # Fall back to shared profile
                    if not hasattr(self, 'shared_profile') or not self.shared_profile:
                        self._init_shared_profile()
                    profile_to_use = self.shared_profile
            else:
                print("[WARNING] Netflix DRM not available, using default profile")
                if not hasattr(self, 'shared_profile') or not self.shared_profile:
                    self._init_shared_profile()
                profile_to_use = self.shared_profile
        elif getattr(self, 'use_imported_profile_for_new_tabs', False) and hasattr(self, 'google_imported_profile'):
            profile_to_use = self.google_imported_profile
        else:
            if not hasattr(self, 'shared_profile') or not self.shared_profile:
                self._init_shared_profile()
            profile_to_use = self.shared_profile
        
        # Set a realistic User-Agent string (Latest Chrome)
        REALISTIC_UA = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/125.0.0.0 Safari/537.36"
        )
        
        # Configure profile for enhanced compatibility
        try:
            profile_to_use.setHttpCacheType(QWebEngineProfile.HttpCacheType.DiskHttpCache)
            profile_to_use.setPersistentCookiesPolicy(QWebEngineProfile.PersistentCookiesPolicy.ForcePersistentCookies)
            profile_to_use.setHttpCacheMaximumSize(1024 * 1024 * 100)  # 100MB
            profile_to_use.settings().setAttribute(QWebEngineSettings.LocalStorageEnabled, True)
            
            # Enable DRM for Netflix (Widevine)
            profile_to_use.settings().setAttribute(QWebEngineSettings.PluginsEnabled, True)
            profile_to_use.settings().setAttribute(QWebEngineSettings.DnsPrefetchEnabled, True)
            # Enable fullscreen support
            profile_to_use.settings().setAttribute(QWebEngineSettings.FullScreenSupportEnabled, True)
        except Exception as e:
            print(f"[WARNING] Could not configure profile: {e}")
        
        # Override user agent on profile and page
        try:
            profile_to_use.setHttpUserAgent(REALISTIC_UA)
        except Exception as e:
            print(f"[WARNING] Could not set User-Agent on profile: {e}")
        
        try:
            page = WebPage(profile_to_use, browser)
            page.profile().setHttpUserAgent(REALISTIC_UA)
        except Exception as e:
            print(f"[WARNING] Could not create page: {e}")
            # Fallback to default page
            page = WebPage(QWebEngineProfile.defaultProfile(), browser)
        
        browser.setPage(page)
        
        # Request Interceptor for enhanced headers
        class RequestInterceptor(QWebEngineUrlRequestInterceptor):
            def interceptRequest(self, info):
                # Add headers to all requests
                info.setHttpHeader(b"Accept", b"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
                info.setHttpHeader(b"Accept-Language", b"en-US,en;q=0.9")
                info.setHttpHeader(b"Cache-Control", b"max-age=0")
                
                # For main frame requests
                if info.resourceType() == QWebEngineUrlRequestInfo.ResourceTypeMainFrame:
                    info.setHttpHeader(b"sec-fetch-dest", b"document")
                    info.setHttpHeader(b"sec-fetch-mode", b"navigate")
                    info.setHttpHeader(b"sec-fetch-site", b"none")
                    info.setHttpHeader(b"sec-fetch-user", b"?1")
                    info.setHttpHeader(b"Upgrade-Insecure-Requests", b"1")
                
                # Special headers for OpenAI and Z.AI
                if info.requestUrl().host().endswith(('openai.com', 'z.ai')):
                    info.setHttpHeader(b"Origin", b"https://chat.openai.com" if "openai" in info.requestUrl().host() else b"https://z.ai")
                    info.setHttpHeader(b"Referer", b"https://chat.openai.com/" if "openai" in info.requestUrl().host() else b"https://z.ai/")
                
                # Special handling for Cloudflare resources
                if "challenges.cloudflare.com" in info.requestUrl().toString():
                    # Don't interfere with Cloudflare challenge resources
                    return
        
        try:
            interceptor = RequestInterceptor()
            page.profile().setUrlRequestInterceptor(interceptor)
        except Exception as e:
            print(f"[WARNING] Could not set request interceptor: {e}")
        
        # Enhanced JavaScript injection for all platforms
        def inject_enhanced_js(ok):
            if ok:
                try:
                    netflix_js = ""
                    if hasattr(self, 'netflix_drm_handler'):
                        netflix_js = self.netflix_drm_handler.get_netflix_js_injection()
                    
                    js_code = f"""
                        // User-Agent override
                        Object.defineProperty(navigator, 'userAgent', {{
                            get: () => "{REALISTIC_UA}"
                        }});
                        console.log('User-Agent set to: {REALISTIC_UA}');
                        
                        // Override navigator properties for anti-bot detection
                        Object.defineProperty(navigator, 'webdriver', {{
                            get: () => undefined
                        }});
                        
                        // Add plugins array
                        Object.defineProperty(navigator, 'plugins', {{
                            get: () => [
                                {{
                                    0: {{type: "application/x-google-chrome-pdf"}},
                                    description: "Portable Document Format",
                                    filename: "internal-pdf-viewer",
                                    length: 1,
                                    name: "Chrome PDF Plugin"
                                }}
                            ]
                        }});
                        
                        // Add languages
                        Object.defineProperty(navigator, 'languages', {{
                            get: () => ['en-US', 'en']
                        }});
                        
                        // Override permissions
                        const originalQuery = window.navigator.permissions.query;
                        window.navigator.permissions.query = (parameters) => (
                            parameters.name === 'notifications' ?
                                Promise.resolve({{ state: Notification.permission }}) :
                                originalQuery(parameters)
                        );
                        
                        // Add chrome runtime
                        window.chrome = {{
                            runtime: {{}},
                            webstore: {{}}
                        }};
                        
                        // WebGL fixes
                        const getContext = HTMLCanvasElement.prototype.getContext;
                        HTMLCanvasElement.prototype.getContext = function(contextType, ...args) {{
                            const context = getContext.call(this, contextType, ...args);
                            if (contextType === 'webgl' || contextType === 'experimental-webgl') {{
                                const getParameter = context.getParameter;
                                context.getParameter = function(parameter) {{
                                    if (parameter === 37445) {{
                                        return "Intel Inc."; // Vendor
                                    }}
                                    if (parameter === 37446) {{
                                        return "Intel(R) Iris(TM) Graphics 6100"; // Renderer
                                    }}
                                    return getParameter.call(this, parameter);
                                }};
                            }}
                            return context;
                        }};
                        
                        // Fix deprecated webkitStorageInfo API
                        if (window.webkitStorageInfo && !navigator.webkitTemporaryStorage) {{
                            navigator.webkitTemporaryStorage = {{
                                queryUsageAndQuota: function(callback) {{
                                    window.webkitStorageInfo.queryUsageAndQuota(window.webkitStorageInfo.TEMPORARY, callback);
                                }},
                                requestQuota: function(bytes, callback) {{
                                    window.webkitStorageInfo.requestQuota(window.webkitStorageInfo.TEMPORARY, bytes, callback);
                                }}
                            }};
                            
                            navigator.webkitPersistentStorage = {{
                                queryUsageAndQuota: function(callback) {{
                                    window.webkitStorageInfo.queryUsageAndQuota(window.webkitStorageInfo.PERSISTENT, callback);
                                }},
                                requestQuota: function(bytes, callback) {{
                                    window.webkitStorageInfo.requestQuota(window.webkitStorageInfo.PERSISTENT, bytes, callback);
                                }}
                            }};
                        }}
                        
                        // Cloudflare challenge handler - improved approach
                        if (document.title.includes("Just a moment") || 
                            document.title.includes("Attention Required") ||
                            document.querySelector("#cf-challenge-running")) {{
                            
                            console.log("Cloudflare challenge detected");
                            
                            // Wait for challenge to load properly
                            setTimeout(() => {{
                                const verifyButton = document.querySelector("#challenge-stage input[type='button']");
                                if (verifyButton) {{
                                    console.log("Found Cloudflare verify button, clicking...");
                                    verifyButton.click();
                                }} else {{
                                    console.log("Cloudflare button not found, waiting...");
                                    // Try again after a delay
                                    setTimeout(() => {{
                                        const retryButton = document.querySelector("#challenge-stage input[type='button']");
                                        if (retryButton) {{
                                            retryButton.click();
                                        }}
                                    }}, 2000);
                                }}
                            }}, 3000); // Increased wait time
                        }}
                        
                        // Netflix DRM compatibility
                        if (window.location.hostname.includes('netflix.com')) {{
                            {netflix_js}
                        }}
                        
                        // OpenAI specific fixes
                        if (window.location.hostname.includes('openai.com')) {{
                            // Ensure proper event listeners for chat interface
                            document.addEventListener('DOMContentLoaded', () => {{
                                // Fix for potential event listener issues
                                const originalAdd = EventTarget.prototype.addEventListener;
                                EventTarget.prototype.addEventListener = function(type, listener, options) {{
                                    originalAdd.call(this, type, listener, options);
                                    // Special handling for OpenAI's custom events
                                    if (type === 'message' || type === 'submit') {{
                                        this.dispatchEvent(new Event(type, {{ bubbles: true }}));
                                    }}
                                }};
                            }});
                            
                            // Ensure proper fetch handling
                            const originalFetch = window.fetch;
                            window.fetch = function(...args) {{
                                return originalFetch.apply(this, args).then(response => {{
                                    // Clone response to avoid body lock issues
                                    const cloned = response.clone();
                                    return cloned;
                                }});
                            }};
                        }}
                        
                        // Z.AI specific fixes
                        if (window.location.hostname.includes('z.ai')) {{
                            // Ensure proper WebSocket support
                            if (typeof WebSocket === 'undefined') {{
                                window.WebSocket = class {{
                                    constructor(url) {{
                                        this.url = url;
                                        this.readyState = 1; // OPEN
                                        this.onopen = null;
                                        this.onmessage = null;
                                        this.onerror = null;
                                        this.onclose = null;
                                        
                                        // Simulate connection
                                        setTimeout(() => {{
                                            if (this.onopen) this.onopen();
                                        }}, 100);
                                    }}
                                    
                                    send(data) {{
                                        // Simulate message reception
                                        setTimeout(() => {{
                                            if (this.onmessage) {{
                                                this.onmessage({{
                                                    data: JSON.stringify({{
                                                        type: "response",
                                                        content: "Simulated response"
                                                    }})
                                                }});
                                            }}
                                        }}, 200);
                                    }}
                                    
                                    close() {{
                                        this.readyState = 3; // CLOSED
                                        if (this.onclose) this.onclose();
                                    }}
                                }};
                            }}
                        }}
                    """
                    page.runJavaScript(js_code)
                except Exception as e:
                    print(f"[WARNING] Could not inject JavaScript: {e}")
        
        page.loadFinished.connect(inject_enhanced_js)
        
        # Set important HTTP request headers mimicking Chrome on Windows
        request = QWebEngineHttpRequest(qurl if qurl and qurl.isValid() else QUrl("about:blank"))
        request.setMethod(QWebEngineHttpRequest.Get)
        request.setHeader(b"Accept-Language", b"en-US,en;q=0.9")
        request.setHeader(b"sec-ch-ua", b'"Google Chrome";v="125", "Chromium";v="125", "Not/A)Brand";v="24"')
        request.setHeader(b"sec-ch-ua-mobile", b"?0")
        request.setHeader(b"sec-ch-ua-platform", b'"Windows"')
        # Additional headers for compatibility
        request.setHeader(b"Accept", b"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
        request.setHeader(b"Cache-Control", b"max-age=0")
        request.setHeader(b"sec-fetch-dest", b"document")
        request.setHeader(b"sec-fetch-mode", b"navigate")
        request.setHeader(b"sec-fetch-site", b"none")
        request.setHeader(b"sec-fetch-user", b"?1")
        request.setHeader(b"Upgrade-Insecure-Requests", b"1")
        browser.load(request)
        
        # Enable WebRTC features fully to avoid anti-bot detection
        settings = QWebEngineSettings.globalSettings()
        settings.setAttribute(QWebEngineSettings.WebRTCPublicInterfacesOnly, False)
        settings.setAttribute(QWebEngineSettings.ScreenCaptureEnabled, True)
        settings.setAttribute(QWebEngineSettings.AllowWindowActivationFromJavaScript, True)
        
        # Connect necessary signals
        page.fullScreenRequested.connect(self.handle_fullscreen_request)
        browser.urlChanged.connect(lambda u: self.update_urlbar(u))
        browser.titleChanged.connect(lambda t: self.update_tab_title(browser, t))
        page.windowCloseRequested.connect(lambda: self.close_tab(self.tab_widget.currentIndex()))
        page.linkHovered.connect(lambda u: self.status_bar.showMessage(u, 2000))
        page.createWindow = self.create_window
        
        # Progress bar
        progress_bar = QProgressBar()
        progress_bar.setMaximumHeight(3)
        progress_bar.setTextVisible(False)
        progress_bar.setStyleSheet("""
            QProgressBar { border: 0px; background: transparent; }
            QProgressBar::chunk { background-color: #3daee9; }
        """)
        layout.addWidget(browser)
        layout.addWidget(progress_bar)
        browser.loadProgress.connect(progress_bar.setValue)
        browser.iconChanged.connect(lambda icon: self.update_tab_icon(browser, icon))
        
        # Browser settings
        browser_settings = browser.settings()
        browser_settings.setAttribute(QWebEngineSettings.JavascriptEnabled,
                                      self.settings_manager.get("javascript_enabled", True))
        browser_settings.setAttribute(QWebEngineSettings.JavascriptCanOpenWindows, True)
        browser_settings.setAttribute(QWebEngineSettings.LinksIncludedInFocusChain, True)
        browser_settings.setAttribute(QWebEngineSettings.AutoLoadImages,
                                      self.settings_manager.get("auto_load_images", True))
        browser_settings.setAttribute(QWebEngineSettings.LocalContentCanAccessRemoteUrls, True)
        browser_settings.setAttribute(QWebEngineSettings.PluginsEnabled, True)
        browser_settings.setAttribute(QWebEngineSettings.LocalStorageEnabled, True)
        browser_settings.setAttribute(QWebEngineSettings.DnsPrefetchEnabled, True)
        browser_settings.setAttribute(QWebEngineSettings.WebGLEnabled, True)
        # Enable fullscreen support
        browser_settings.setAttribute(QWebEngineSettings.FullScreenSupportEnabled, True)
        
        # Add tab
        display_title = truncate_title(title)
        tab_index = self.tab_widget.addTab(container, display_title)
        self.tab_widget.setTabToolTip(tab_index, title)
        try:
            self.tab_widget.currentChanged.disconnect(self.on_tab_changed)
        except (TypeError, RuntimeError):
            pass
        self.tab_widget.currentChanged.connect(self.on_tab_changed)
        if qurl.isValid():
            self.load_favicon_for_url(qurl)
        page.audioMutedChanged.connect(self.on_audio_state_changed)
        
        # Enhanced WebRTC and media constraints
        def inject_constraints(ok):
            if ok:
                try:
                    page.runJavaScript("""
                        if (navigator.mediaDevices?.getUserMedia) {
                            const originalGUM = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
                            navigator.mediaDevices.getUserMedia = async (constraints) => {
                                if (constraints?.audio) {
                                    constraints.audio = {
                                        ...(typeof constraints.audio === 'boolean' ? {} : constraints.audio),
                                        echoCancellation: {exact: true},
                                        noiseSuppression: {exact: true},
                                        autoGainControl: {exact: true}
                                    };
                                }
                                if (constraints?.video) {
                                    constraints.video = {
                                        ...(typeof constraints.video === 'boolean' ? {} : constraints.video),
                                        width: {ideal: 1280},
                                        height: {ideal: 720},
                                        frameRate: {ideal: 30}
                                    };
                                }
                                return originalGUM(constraints);
                            };
                        }
                        
                        // Enhanced WebRTC for all platforms
                        const originalCreateOffer = window.RTCPeerConnection.prototype.createOffer;
                        window.RTCPeerConnection.prototype.createOffer = function() {
                            const offer = originalCreateOffer.apply(this, arguments);
                            return offer.then(description => {
                                return description;
                            });
                        };
                        
                        // AddgetDisplayMedia support
                        if (navigator.mediaDevices && !navigator.mediaDevices.getDisplayMedia) {
                            navigator.mediaDevices.getDisplayMedia = (constraints) => {
                                return navigator.mediaDevices.getUserMedia({
                                    video: {
                                        mediaSource: 'screen'
                                    }
                                });
                            };
                        }
                        
                        // Fix for OpenAI's media requirements
                        if (window.location.hostname.includes('openai.com')) {
                            // Ensure audio context is available
                            if (typeof AudioContext === 'undefined') {
                                window.AudioContext = window.webkitAudioContext;
                            }
                            
                            // Fix for potential MediaStream issues
                            if (navigator.mediaDevices && !navigator.mediaDevices.enumerateDevices) {
                                navigator.mediaDevices.enumerateDevices = () => {
                                    return Promise.resolve([
                                        { kind: 'audioinput', deviceId: 'default', label: 'Default' },
                                        { kind: 'videoinput', deviceId: 'default', label: 'Default' }
                                    ]);
                                };
                            }
                        }
                    """)
                except Exception as e:
                    print(f"[WARNING] Could not inject WebRTC constraints: {e}")
        
        browser.loadFinished.connect(inject_constraints)
        
        # Focus tab unless background
        if not background:
            def activate_new_tab():
                self.tab_widget.setCurrentIndex(tab_index)
                self.activateWindow()
                self.raise_()
                browser.setFocus(Qt.OtherFocusReason)
                QTimer.singleShot(10, self.focus_url_bar)
            QTimer.singleShot(30, activate_new_tab)
        else:
            print(f"[DEBUG] Tab opened in background: {title}")
        
        return browser





    def debug_netflix_support(self):
        """Print debugging information about Netflix support."""
        print("[DEBUG] Netflix Support Information:")
        if hasattr(self, 'netflix_drm_handler'):
            self.netflix_drm_handler.debug_widevine_status()
        else:
            print("  - Netflix DRM handler not initialized")
        
        # Check current tab
        current_tab = self.tab_widget.currentWidget()
        if current_tab:
            browser = current_tab.findChild(QWebEngineView)
            if browser:
                url = browser.url().toString()
                print(f"  - Current URL: {url}")
                if "netflix.com" in url:
                    print("  - Current tab is Netflix")
                else:
                    print("  - Current tab is not Netflix")






    def on_google_import_failed(self, error_message=None):
        """
        Slot to handle Google import failure signal.
        """
        print(f"[ERROR] Google import failed: {error_message}")
        from PyQt5.QtWidgets import QMessageBox
        dialog = QMessageBox(self)
        dialog.setWindowTitle("Google Import Failed")
        dialog.setIcon(QMessageBox.Warning)
        if error_message:
            dialog.setText(f"Google import failed: {error_message}")
        else:
            dialog.setText("Google import failed due to unknown error.")
        dialog.exec_()






    # --- Helper method to initialize shared profile (call this in your setup) ---
    def _init_shared_profile(self):
        """Initialize the shared QWebEngineProfile."""
        if not hasattr(self, 'shared_profile') or not self.shared_profile:
            CONFIG_DIR = os.path.expanduser("~/.config/StormBrowser") # Or your config path
            os.makedirs(CONFIG_DIR, exist_ok=True)
            self.shared_profile = QWebEngineProfile("StormBrowserProfile", self)
            self.shared_profile.setPersistentCookiesPolicy(QWebEngineProfile.AllowPersistentCookies)
            self.shared_profile.setCachePath(os.path.join(CONFIG_DIR, "cache"))
            self.shared_profile.setPersistentStoragePath(os.path.join(CONFIG_DIR, "storage"))
            # Connect download handler once here
            self.shared_profile.downloadRequested.connect(self.download_manager.handle_download)
            print(f"[INFO] Initialized shared profile at {CONFIG_DIR}")

    def handle_fullscreen_request(self, request):
        """
        Handle fullscreen requests from QWebEngineView.
        Fully restores original layout and tab state without visual glitches.
        """
        page = self.sender()

        if request.toggleOn():
            # Get the current browser view
            self.fullscreen_browser = self.current_browser()
            if not self.fullscreen_browser:
                request.reject()
                return

            # Save original parent widget and layout container
            self.original_container = self.fullscreen_browser.parent()
            self.original_index = self.tab_widget.indexOf(self.original_container)

            # Hide tab widget container
            self.original_container.hide()

            # Remove the browser from its parent (but don't delete)
            self.fullscreen_browser.setParent(None)

            # Create fullscreen window
            self.fullscreen_window = QMainWindow()
            self.fullscreen_window.setWindowFlags(Qt.Window | Qt.FramelessWindowHint)
            self.fullscreen_window.setCentralWidget(self.fullscreen_browser)
            self.fullscreen_window.showFullScreen()
            self.fullscreen_window.installEventFilter(self)

            request.accept()

        else:
            # Exit fullscreen
            if hasattr(self, 'fullscreen_window') and self.fullscreen_window:
                # Detach from fullscreen window
                self.fullscreen_browser.setParent(None)

                # Reattach to the original container
                layout = self.original_container.layout()
                if layout:
                    layout.addWidget(self.fullscreen_browser)
                else:
                    # Fallback in case layout is missing
                    vbox = QVBoxLayout(self.original_container)
                    vbox.setContentsMargins(0, 0, 0, 0)
                    vbox.addWidget(self.fullscreen_browser)

                # Show the tab again
                if self.tab_widget.indexOf(self.original_container) == -1:
                    self.tab_widget.insertTab(self.original_index, self.original_container, "Restored Tab")
                self.original_container.show()
                self.tab_widget.setCurrentWidget(self.original_container)

                # Optionally pause any playing media
                self.fullscreen_browser.page().runJavaScript("""
                    document.querySelectorAll('video, audio').forEach(media => {
                        media.pause();
                    });
                """)

                # Clean up
                self.fullscreen_window.close()
                self.fullscreen_window.deleteLater()

                # Reset state
                self.fullscreen_window = None
                self.fullscreen_browser = None
                self.original_container = None
                self.original_index = None

                request.accept()







    def create_window(self, type_):
        """
        Handle all new window/tab requests from web content.
        This includes target="_blank" links and JavaScript window.open() calls.
        
        :param type_: The type of window being requested (QWebEnginePage.WebBrowserWindow)
        :return: The QWebEnginePage for the new window/tab
        """
        new_tab = self.add_new_tab(background=True)
        return new_tab.page()

     

    def load_favicon_for_url(self, url):
        """Load favicon for the given URL."""
        if not url or not url.host():
            return
            
        domain = url.host()
        if domain.startswith('www.'):
            domain = domain[4:]
            
        # Use favicon manager to get or fetch the icon
        self.favicon_manager.get_favicon(url.toString())

    def update_tab_icon(self, browser, icon):
        """
        Update the tab icon for the specified browser.
        
        :param browser: The QWebEngineView whose icon changed
        :param icon: The new QIcon to display
        """
        # Use a default icon if none is provided
        if icon.isNull():
            icon = QIcon.fromTheme("web-browser", QIcon(":default-icon.png"))
        
        # Find the tab containing this browser and update its icon
        for i in range(self.tab_widget.count()):
            tab_widget = self.tab_widget.widget(i)
            if tab_widget and tab_widget.findChild(QWebEngineView) == browser:
                self.tab_widget.setTabIcon(i, icon)
                break

    def update_tab_favicon(self, domain, icon):
        """Update tab icon when favicon is loaded."""
        current_browser = self.current_browser()
        if not current_browser:
            return
            
        current_domain = current_browser.url().host()
        if current_domain.startswith('www.'):
            current_domain = current_domain[4:]
            
        if current_domain == domain:
            self.update_tab_icon(current_browser, icon)  # Pass browser AND icon


    def update_tab_title(self, browser, title):
        """Update tab title when page title changes."""
        for i in range(self.tab_widget.count()):
            if self.tab_widget.widget(i).findChild(QWebEngineView) == browser:
                # Truncate long titles
                display_title = title[:20] + "..." if len(title) > 20 else title
                self.tab_widget.setTabText(i, display_title)
                self.tab_widget.setTabToolTip(i, title)
                
                # Update favicon if needed
                self.load_favicon_for_url(browser.url())
                break




        

    # In update_urlbar method
    def update_urlbar(self, url):
        """Update the URL bar when navigation occurs."""
        url_string = url.toString()
        # Optionally hide 'about:blank' from showing in the URL bar
        if url_string == "about:blank":
            self.url_bar.clear()
        else:
            self.url_bar.setText(url_string)
            self.url_bar.setCursorPosition(0)

        # Only add to history if it's NOT incognito
        # --- Fix starts here ---
        if hasattr(self, 'history_manager'):
            tab_index = self.tab_widget.currentIndex() # Get current index
            if tab_index >= 0:
                # Get the container widget that was added to the tab
                container_widget = self.tab_widget.widget(tab_index)
                # Check the property on the container widget
                is_incognito = container_widget and container_widget.property("is_incognito") == True
                if not is_incognito: # Only add if NOT incognito
                    title = self.tab_widget.tabText(tab_index)
                    self.history_manager.add_history_entry(url.toString(), title)
        # --- Fix ends here ---

    def on_tab_changed(self, index):
        """Handle tab changes to update URL bar and other UI elements."""
        if index >= 0:  # Check for valid index
            browser = self.tab_widget.widget(index).findChild(QWebEngineView)
            if browser:
                self.update_urlbar(browser.url())

    def close_tab(self, index):
        """
        Safely closes a tab at the given index without affecting adjacent tabs.
        Uses direct widget reference for reliability and avoids index shifting issues.
        """

        # Step 1: Validate index
        if index < 0 or index >= self.tab_widget.count():
            print(f"[ERROR] Invalid tab index: {index}")
            return

        # Step 2: Get the tab widget at this index
        tab_to_remove = self.tab_widget.widget(index)

        if not tab_to_remove:
            print(f"[ERROR] No widget found at index: {index}")
            return

        # Step 3: Find the QWebEngineView inside the tab
        browser = tab_to_remove.findChild(QWebEngineView)
        if browser:
            # Stop audio playback
            browser.page().setAudioMuted(True)

            # Pause all video/audio elements using JavaScript
            browser.page().runJavaScript("""
                document.querySelectorAll('video, audio').forEach(media => {
                    media.pause();
                    media.currentTime = 0;
                    media.src = '';
                    media.load();
                });
            """)

            # Store closed tab info for restoration
            if not hasattr(self, 'closed_tabs'):
                self.closed_tabs = []
            self.closed_tabs.append({
                'url': browser.url().toString(),
                'title': self.tab_widget.tabText(index),
                'timestamp': datetime.now().isoformat()
            })

            # Clean up resources
            browser.setPage(QWebEnginePage())
            browser.page().deleteLater()

        # Step 4: Remove only one tab at a time
        try:
            self.tab_widget.removeTab(index)
        except Exception as e:
            print(f"[ERROR] Failed to remove tab at index {index}: {str(e)}")
            return

        # Step 5: Ensure at least one tab remains open
        if self.tab_widget.count() == 0:
            self.add_new_tab(QUrl(self.settings_manager.get("home_page")))

        # Optional: Log confirmation
        print(f"[INFO] Tab closed successfully. Remaining tabs: {self.tab_widget.count()}")










    def update_tab_title(self, browser, title):
        """Update tab title when page title changes."""
        for i in range(self.tab_widget.count()):
            if self.tab_widget.widget(i).findChild(QWebEngineView) == browser:
                # Truncate long titles
                display_title = title[:20] + "..." if len(title) > 20 else title
                self.tab_widget.setTabText(i, display_title)
                self.tab_widget.setTabToolTip(i, title)
                break



    def perform_search(self):
        """Perform a web search."""
        query = self.url_bar.text().strip()
        if not query:
            return

        search_url = self.settings_manager.get("search_engine").format(query)
        self.current_browser().setUrl(QUrl(search_url))

    def go_home(self):
        """Navigate to the home page."""
        self.current_browser().setUrl(QUrl(self.settings_manager.get("home_page")))

    def toggle_dev_tools(self):
        """Toggle developer tools for current page."""
        browser = self.current_browser()
        if browser:
            browser.page().triggerAction(QWebEnginePage.InspectElement)

    def show_bookmark_search(self):
        """Show the bookmark search dialog."""
        searcher = BookmarkSearcher(self)
        searcher.exec_()



    def browse_download_dir(self):
        """Open a directory dialog to choose download location."""
        dir_path = QFileDialog.getExistingDirectory(
            self,
            "Select Download Directory",
            self.download_dir_edit.text() or DOWNLOAD_DIR
        )
        if dir_path:
            self.download_dir_edit.setText(dir_path)

    def configure_webengine(self):
        """Configure WebEngine settings for HLS and DRM support."""
        # Enable HLS if configured
        if self.settings_manager.get("hls_enabled", HLS_ENABLED):
            settings = QWebEngineSettings.globalSettings()
            settings.setAttribute(QWebEngineSettings.PlaybackRequiresUserGesture, False)
            settings.setAttribute(QWebEngineSettings.FullScreenSupportEnabled, True)
            settings.setAttribute(QWebEngineSettings.JavascriptEnabled, True)
            settings.setAttribute(QWebEngineSettings.PluginsEnabled, True)

        # Enable DRM if configured
        if self.settings_manager.get("drm_enabled", DRM_ENABLED):
            profile = QWebEngineProfile.defaultProfile()
            profile.setHttpUserAgent(self.settings_manager.get("user_agent", USER_AGENT))

            # Enable Widevine
            profile.setProperty("httpAccept", "application/x-mpegURL,application/dash+xml,application/vnd.apple.mpegurl")
            profile.setProperty("enableMediaSource", True)
            profile.setProperty("enableMedia", True)
            profile.setProperty("enableWebAudio", True)

            # Set common DRM flags
            os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = (
                "--enable-media-stream "
                "--enable-features=WidevineCdm "
                "--disable-features=UseChromeOSDirectVideoDecoder"
            )

    def reset_shortcuts_to_defaults(self):
        default_shortcuts = {
            "back": "Alt+Left",
            "forward": "Alt+Right",
            "reload": "F5",
            "reload_ignore_cache": "Shift+F5",
            "stop": "Esc",
            "home": "Alt+Home",
            "new_tab": "Ctrl+T",
            "close_tab": "Ctrl+W",
            "next_tab": "Ctrl+Tab",
            "prev_tab": "Ctrl+Shift+Tab",
            "restore_tab": "Ctrl+Shift+T",
            "focus_url": "Ctrl+L",
            "focus_search": "Ctrl+K",
            "bookmark_search": "Ctrl+B",
            "bookmark_page": "Ctrl+D",
            "downloads": "Ctrl+J",
            "history": "Ctrl+H",
            "settings": "Ctrl+,",
            "print": "Ctrl+P",
            "print_pdf": "Ctrl+Shift+P",
            "screenshot": "Ctrl+Shift+S",
            "calendar": "Ctrl+Shift+C",  # Add this line
            "full_screenshot": "Ctrl+Alt+Shift+S",
            "region_screenshot": "Ctrl+Shift+R",
            "search_selected": "Ctrl+E",
            "autocomplete_url": "Ctrl+Return",
            "dev_tools": "F12",
            "view_source": "Ctrl+U",
            "zoom_in": "Ctrl++",
            "zoom_out": "Ctrl+-",
            "zoom_reset": "Ctrl+0"
        }

        for name, editor in self.shortcut_editors.items():
            if name in default_shortcuts:
                editor.setKeySequence(QKeySequence(default_shortcuts[name]))

    def restore_closed_tab(self):
        """Restore the most recently closed tab."""
        if hasattr(self, 'closed_tabs') and self.closed_tabs:
            tab_info = self.closed_tabs.pop()  # Get the dictionary
            self.add_new_tab(QUrl(tab_info['url']), tab_info['title'])
        else:
            self.status_bar.showMessage("No tabs to restore", 2000)

    def zoom_in(self):
        """Increase zoom level by 10%."""
        if browser := self.current_browser():
            current_zoom = browser.zoomFactor()
            browser.setZoomFactor(min(current_zoom + 0.1, 3.0))  # Max zoom 300%
            self.status_bar.showMessage(f"Zoom: {int(browser.zoomFactor() * 100)}%", 1500)

    def zoom_out(self):
        """Decrease zoom level by 10%."""
        if browser := self.current_browser():
            current_zoom = browser.zoomFactor()
            browser.setZoomFactor(max(current_zoom - 0.1, 0.3))  # Min zoom 30%
            self.status_bar.showMessage(f"Zoom: {int(browser.zoomFactor() * 100)}%", 1500)

    def zoom_reset(self):
        """Reset zoom level to 100%."""
        if browser := self.current_browser():
            browser.setZoomFactor(1.0)
            self.status_bar.showMessage("Zoom reset to 100%", 1500)

    def search_selected_text(self):
        """Search for currently selected text."""
        if browser := self.current_browser():
            browser.page().toPlainText(lambda text: self._perform_search_for_selection(text))

    def _perform_search_for_selection(self, page_text):
        """Helper method to handle selected text search."""
        cursor = self.current_browser().page().cursor()
        selected_text = page_text[cursor.selectionStart():cursor.selectionEnd()].strip()
        
        if selected_text:
            search_url = self.settings_manager.get("search_engine").format(selected_text)
            self.add_new_tab(QUrl(search_url))
        else:
            self.status_bar.showMessage("No text selected", 2000)

    def focus_search_bar(self):
        """Focus the search/URL bar and select all text."""
        self.url_bar.setFocus()
        self.url_bar.selectAll()

    # ====================== BOOKMARKS ======================
    def show_bookmarks(self, quick_access=False):
        """
        Show bookmarks interface with two modes:
        - quick_access=True: Simple search dialog with multi-select (Ctrl+Click)
        - quick_access=False: Full bookmark manager with tree view
        """
        if quick_access or self.settings_manager.get("quick_bookmark_access", False):
            # Show the fast search dialog
            searcher = BookmarkSearcher(self)
            searcher.finished.connect(lambda: searcher.search_bar.clear())  # Clear search bar when closed
            searcher.exec_()
        else:
            # Show full bookmark manager
            if not hasattr(self, 'bookmarks_dialog') or not self.bookmarks_dialog:
                self._init_bookmark_manager_dialog()
            self.refresh_bookmarks_tree()
            self.bookmarks_dialog.finished.connect(lambda: self.bookmark_search_bar.clear())  # Clear search bar when closed
            self.bookmark_search_bar.setFocus()  # Set focus to the search bar
            self.bookmarks_dialog.exec_()


    def _init_bookmark_manager_dialog(self):
        """
        Initialize the full bookmark manager dialog.
        """
        self.bookmarks_dialog = QDialog(self)
        self.bookmarks_dialog.setWindowTitle("Bookmark Manager")
        self.bookmarks_dialog.setMinimumSize(900, 700)

        layout = QVBoxLayout()

        # Add quick access button to switch modes
        quick_access_btn = QPushButton("Switch to Quick Access Mode")
        quick_access_btn.clicked.connect(
            lambda: [self.bookmarks_dialog.close(), self.show_bookmarks(quick_access=True)]
        )
        layout.addWidget(quick_access_btn)

        # Search bar
        search_layout = QHBoxLayout()
        self.bookmark_search_bar = QLineEdit()
        self.bookmark_search_bar.setPlaceholderText("Search bookmarks...")
        self.bookmark_search_bar.textChanged.connect(self.filter_bookmarks)

        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(
            lambda: [self.bookmark_search_bar.clear(), self.filter_bookmarks()]
        )

        search_layout.addWidget(QLabel("Search:"))
        search_layout.addWidget(self.bookmark_search_bar)
        search_layout.addWidget(clear_btn)
        layout.addLayout(search_layout)

        # Import buttons
        import_layout = QHBoxLayout()
        chrome_btn = QPushButton("Import from Chrome")
        firefox_btn = QPushButton("Import from Firefox")
        import_layout.addWidget(chrome_btn)
        import_layout.addWidget(firefox_btn)
        layout.addLayout(import_layout)

        # Bookmarks tree with multi-select enabled
        self.bookmarks_tree = QTreeWidget()
        self.bookmarks_tree.setHeaderLabels(["Name", "URL", "Description", "Folder"])
        self.bookmarks_tree.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.bookmarks_tree.setColumnWidth(0, 250)
        self.bookmarks_tree.setColumnWidth(1, 400)
        self.bookmarks_tree.itemDoubleClicked.connect(self.open_bookmark)
        self.bookmarks_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.bookmarks_tree.customContextMenuRequested.connect(self.show_bookmark_context_menu)

        layout.addWidget(self.bookmarks_tree)

        # Button panel
        btn_layout = QHBoxLayout()
        # --- Updated Section for Open Selected Button ---
        self.open_selected_btn = QPushButton("Open Selected (Ctrl+Enter)")
        self.open_selected_btn.setShortcut("Ctrl+Return")
        # Add the tooltip explaining the incognito option
        self.open_selected_btn.setToolTip("Open selected bookmarks. Hold Ctrl while clicking to open in incognito mode.")
        self.open_selected_btn.clicked.connect(self.open_selected_bookmarks)
        # --- End Update ---

        btn_layout.addWidget(self.open_selected_btn)
        btn_layout.addWidget(QPushButton("Add Current Page", clicked=self.add_current_to_bookmarks))
        btn_layout.addWidget(QPushButton("Remove Selected", clicked=self.remove_selected_bookmark))
        btn_layout.addWidget(QPushButton("New Folder", clicked=self.create_new_folder))

        layout.addLayout(btn_layout)

        self.bookmarks_dialog.setLayout(layout)

        # Apply dark mode if needed
        if self.settings_manager.get("dark_mode"):
            self._apply_dark_mode_to_dialog(self.bookmarks_dialog)

    def open_selected_bookmarks(self):
        """Open all selected bookmarks in new tabs (works in both modes).
        If Ctrl is held, opens in incognito tabs."""
        modifiers = QApplication.keyboardModifiers()
        incognito = modifiers & Qt.ControlModifier # Check if Ctrl is pressed

        if hasattr(self, 'bookmarks_tree'):
            # Full manager mode
            selected = self.bookmarks_tree.selectedItems()
            
            # Show status message
            if incognito:
                self.status_bar.showMessage(f"Opening {len(selected)} bookmark(s) in incognito mode...", 3000)
            else:
                self.status_bar.showMessage(f"Opening {len(selected)} bookmark(s)...", 3000)

            for item in selected:
                if not item.childCount(): # Only open leaf nodes (not folders)
                    bookmark = item.data(0, Qt.UserRole)
                    if bookmark:
                        if incognito:
                            # Open in new incognito tab - Shortened title prefix
                            self.add_incognito_tab(QUrl(bookmark["url"]), f"IC: {bookmark['title']}")
                        else:
                            # Open in new regular tab
                            self.add_new_tab(QUrl(bookmark["url"]))
        elif hasattr(self, 'results_list'): # Quick access mode (BookmarkSearcher)
           
            selected = self.results_list.selectedItems()
            
            # Show status message (assuming BookmarkSearcher has access to parent's status_bar)
            if hasattr(self, 'parent') and hasattr(self.parent, 'status_bar'):
                 if incognito:
                     self.parent.status_bar.showMessage(f"Opening {len(selected)} bookmark(s) in incognito mode...", 3000)
                 else:
                     self.parent.status_bar.showMessage(f"Opening {len(selected)} bookmark(s)...", 3000)

            for item in selected:
                url = item.data(Qt.UserRole)
                title = item.text() # Get title from item text
                if url:
                    if incognito:
                        # Open in new incognito tab - Shortened title prefix
                        self.add_incognito_tab(QUrl(url), f"IC: {title}") # Derive title from item
                    else:
                        # Open in new regular tab
                        self.add_new_tab(QUrl(url))

    def open_bookmark(self, item, column):
        """Open bookmark in current tab."""
        if item.childCount() == 0:  # Not a folder
            bookmark = item.data(0, Qt.UserRole)
            if bookmark and self.current_browser():
                self.current_browser().setUrl(QUrl(bookmark["url"]))

    def filter_bookmarks(self):
        """Filter bookmarks based on search text."""
        search_text = self.bookmark_search_bar.text().lower()
        
        def filter_items(item):
            search_text = self.bookmark_search_bar.text().lower()
            
            if item.childCount() > 0:  # Folder
                any_visible = False
                for i in range(item.childCount()):
                    child = item.child(i)
                    if filter_items(child):
                        any_visible = True
                item.setHidden(not any_visible)
                return any_visible
            else:
                title = item.text(0).lower()
                url = item.text(1).lower()
                folder = item.text(2).lower()
                bookmark_data = item.data(0, Qt.UserRole)
                description = bookmark_data.get("description", "").lower()

                matches = (search_text in title or 
                           search_text in url or 
                           search_text in folder or 
                           search_text in description)
                
                item.setHidden(not matches)
                return matches
        
        root = self.bookmarks_tree.invisibleRootItem()
        for i in range(root.childCount()):
            folder_item = root.child(i)
            filter_items(folder_item)

    def refresh_bookmarks_tree(self):
        """Refresh the bookmarks tree view with all bookmarks."""
        if not hasattr(self, 'bookmarks_tree') or not self.bookmarks_tree:
            return  # Exit if tree not initialized
            
        try:
            # Clear existing items but preserve column settings
            self.bookmarks_tree.clear()
            
            # Get all bookmarks including folder information
            all_bookmarks = []
            for folder, bookmarks in self.bookmark_manager.bookmarks["folders"].items():
                for bookmark in bookmarks:
                    bookmark_copy = bookmark.copy()
                    bookmark_copy["folder"] = folder
                    all_bookmarks.append(bookmark_copy)
            
            # Create folder structure
            folders = {}
            for bookmark in all_bookmarks:
                folder_name = bookmark.get("folder", "Main")
                if folder_name not in folders:
                    folders[folder_name] = []
                folders[folder_name].append(bookmark)
            
            # Add to tree with sorting
            for folder_name, bookmarks in sorted(folders.items()):
                folder_item = QTreeWidgetItem(self.bookmarks_tree, [folder_name, "", folder_name])
                for bookmark in sorted(bookmarks, key=lambda x: x["title"].lower()):
                    item = QTreeWidgetItem(folder_item, [
                        bookmark["title"][:50] + "..." if len(bookmark["title"]) > 50 else bookmark["title"],
                        bookmark["url"][:100] + "..." if len(bookmark["url"]) > 100 else bookmark["url"],
                        bookmark.get("folder", "Main")
                    ])
                    item.setData(0, Qt.UserRole, bookmark)
                    item.setToolTip(0, bookmark["title"])
                    item.setToolTip(1, bookmark["url"])
                folder_item.setExpanded(True)
            
            # Auto-resize columns
            for i in range(self.bookmarks_tree.columnCount()):
                self.bookmarks_tree.resizeColumnToContents(i)
                
        except Exception as e:
            print(f"Error refreshing bookmarks tree: {str(e)}")
            self.notification_manager.show_notification(
                "Bookmarks Error",
                f"Failed to refresh bookmarks: {str(e)}",
                3000
            )


    def ensure_bookmarks_tree_exists(self):
        """Ensure the bookmarks tree widget is initialized."""
        if not hasattr(self, 'bookmarks_tree') or not self.bookmarks_tree:
            self.bookmarks_tree = QTreeWidget()
            self.bookmarks_tree.setHeaderLabels(["Name", "URL", "Description", "Folder"])
            self.bookmarks_tree.setColumnWidth(0, 200)
            self.bookmarks_tree.setColumnWidth(1, 350)
            self.bookmarks_tree.setColumnWidth(2, 150)
            self.bookmarks_tree.itemDoubleClicked.connect(self.open_bookmark)
            self.bookmarks_tree.setContextMenuPolicy(Qt.CustomContextMenu)
            self.bookmarks_tree.customContextMenuRequested.connect(self.show_bookmark_context_menu)            

    def show_bookmark_context_menu(self, pos):
        """Show context menu for bookmarks with incognito option."""
        item = self.bookmarks_tree.itemAt(pos)
        if not item or item.childCount() > 0: # Skip if no item selected or it's a folder
            return

        menu = QMenu()
        # Get the bookmark data
        bookmark = item.data(0, Qt.UserRole)

        # Regular open actions
        open_action = QAction("Open", self)
        open_action.triggered.connect(lambda: self.open_bookmark(item, 0))

        open_new_tab_action = QAction("Open in New Tab", self)
        open_new_tab_action.triggered.connect(lambda: self.add_new_tab(QUrl(bookmark["url"]), background=True))

        # Incognito open action - Shortened title prefix
        open_incognito_action = QAction("Open in Incognito Tab", self)
        open_incognito_action.triggered.connect(
            lambda: self.add_incognito_tab(QUrl(bookmark["url"]), f"IC: {bookmark['title']}"))

        # Add actions to menu
        menu.addAction(open_action)
        menu.addAction(open_new_tab_action)
        menu.addAction(open_incognito_action)
        menu.addSeparator()

        # Edit/delete actions
        edit_action = QAction("Edit Bookmark", self)
        edit_action.triggered.connect(lambda: self.edit_bookmark(item))

        delete_action = QAction("Delete Bookmark", self)
        delete_action.triggered.connect(lambda: self.remove_selected_bookmark())

        menu.addAction(edit_action)
        menu.addAction(delete_action)

        menu.exec_(self.bookmarks_tree.viewport().mapToGlobal(pos))



    def create_new_folder(self):
        """Create a new bookmark folder."""
        folder_name, ok = QInputDialog.getText(
            self, "New Folder", "Enter folder name:"
        )
        if ok and folder_name:
            if folder_name not in self.bookmark_manager.bookmarks["folders"]:
                self.bookmark_manager.bookmarks["folders"][folder_name] = []
                self.refresh_bookmarks_tree()

    def rename_folder(self, folder_item):
        """Rename an existing bookmark folder."""
        old_name = folder_item.text(0)
        new_name, ok = QInputDialog.getText(
            self, "Rename Folder", "New folder name:", text=old_name
        )
        if ok and new_name and new_name != old_name:
            if new_name not in self.bookmark_manager.bookmarks["folders"]:
                self.bookmark_manager.bookmarks["folders"][new_name] = self.bookmark_manager.bookmarks["folders"].pop(old_name)
                self.refresh_bookmarks_tree()
            else:
                QMessageBox.warning(self, "Error", "A folder with that name already exists")

    def delete_folder(self, folder_item):
        """Delete a bookmark folder."""
        folder_name = folder_item.text(0)
        reply = QMessageBox.question(
            self, "Delete Folder",
            f"Delete folder '{folder_name}' and all its bookmarks?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            del self.bookmark_manager.bookmarks["folders"][folder_name]
            self.refresh_bookmarks_tree()

    def edit_bookmark(self, item):
        """Edit an existing bookmark."""
        bookmark = item.data(0, Qt.UserRole)
        if not bookmark:
            return
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Edit Bookmark")
        layout = QFormLayout()
        
        title_edit = QLineEdit(bookmark["title"])
        url_edit = QLineEdit(bookmark["url"])
        
        # Folder selection
        folder_combo = QComboBox()
        folder_combo.addItems(self.bookmark_manager.bookmarks["folders"].keys())
        if "folder" in bookmark:
            folder_combo.setCurrentText(bookmark["folder"])
        
        layout.addRow("Title:", title_edit)
        layout.addRow("URL:", url_edit)
        layout.addRow("Folder:", folder_combo)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)
        
        dialog.setLayout(layout)
        
        if dialog.exec_() == QDialog.Accepted:
            # Remove from old folder
            old_folder = bookmark.get("folder", "Main")
            if old_folder in self.bookmark_manager.bookmarks["folders"]:
                self.bookmark_manager.bookmarks["folders"][old_folder] = [
                    b for b in self.bookmark_manager.bookmarks["folders"][old_folder]
                    if b["url"] != bookmark["url"]
                ]
            
            # Add to new folder
            new_folder = folder_combo.currentText()
            bookmark["title"] = title_edit.text()
            bookmark["url"] = url_edit.text()
            bookmark["folder"] = new_folder
            
            if new_folder not in self.bookmark_manager.bookmarks["folders"]:
                self.bookmark_manager.bookmarks["folders"][new_folder] = []
            
            self.bookmark_manager.bookmarks["folders"][new_folder].append(bookmark)
            self.refresh_bookmarks_tree()

    def import_bookmarks(self, browser):
        """Import bookmarks from another browser."""
        count = self.bookmark_manager.import_browser_bookmarks(browser)
        self.refresh_bookmarks_tree()
        self.notification_manager.show_notification(
            "Bookmarks Imported", 
            f"Successfully imported {count} bookmarks from {browser.capitalize()}"
        )

    def add_current_to_bookmarks(self):
        """Add current page to bookmarks with a dialog to include a description."""
        browser = self.current_browser()
        if not browser:
            return

        url = browser.url().toString()
        title = browser.page().title()

        dialog = QDialog(self)
        dialog.setWindowTitle("Add Bookmark")
        layout = QVBoxLayout(dialog)

        # Title
        title_edit = QLineEdit(title)
        layout.addWidget(QLabel("Title:"))
        layout.addWidget(title_edit)

        # URL
        url_edit = QLineEdit(url)
        layout.addWidget(QLabel("URL:"))
        layout.addWidget(url_edit)

        # Description
        description_edit = QLineEdit()
        layout.addWidget(QLabel("Description (optional):"))
        layout.addWidget(description_edit)

        # Folder selection
        folder_combo = QComboBox()
        folder_combo.addItems(self.bookmark_manager.bookmarks["folders"].keys())
        layout.addWidget(QLabel("Folder:"))
        layout.addWidget(folder_combo)

        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        dialog.setLayout(layout)

        if dialog.exec_() == QDialog.Accepted:
            final_title = title_edit.text()
            final_url = url_edit.text()
            final_description = description_edit.text()
            final_folder = folder_combo.currentText()

            self.bookmark_manager.add_bookmark(final_url, final_title, final_folder, final_description)
            self.refresh_bookmarks_tree()

    def remove_selected_bookmark(self):
        """Remove selected bookmark."""
        selected = self.bookmarks_tree.currentItem()
        if selected and selected.childCount() == 0:  # Not a folder
            bookmark = selected.data(0, Qt.UserRole)
            if bookmark:
                self.bookmark_manager.remove_bookmark(bookmark["url"])
                self.refresh_bookmarks_tree()

    # ====================== DOWNLOADS ======================
    def on_download_started(self, filename, size):
        """Handle when a download starts."""
        self.download_progress_bar.show()
        self.download_progress_bar.setValue(0)
        self.status_bar.showMessage(f"Downloading: {filename}")

    def on_download_progress(self, filename, received, total, speed, eta):
        """Update download progress."""
        percent = int((received / total) * 100) if total > 0 else 0
        self.download_progress_bar.setMaximum(total)
        self.download_progress_bar.setValue(received)
        
        message = (
            f"Downloading {filename}: {format_size(received)} of {format_size(total)} "
            f"({percent}%) - {speed} - ETA: {eta}"
        )
        self.status_bar.showMessage(message)

    def on_download_finished(self, path, success, filename):
        """Handle download completion."""
        self.download_progress_bar.hide()
        self.status_bar.clearMessage()
        
        if success:
            self.notification_manager.show_notification(
                "Download Complete",
                f"'{filename}' saved to {os.path.dirname(path)}",
                5000
            )
        else:
            self.notification_manager.show_notification(
                "Download Failed",
                f"Failed to download '{filename}'",
                5000
            )

    def show_downloads(self):
        """Show the download manager dialog with active and completed downloads."""
        self.downloads_dialog = QDialog(self)  # Make it an instance variable
        self.downloads_dialog.setWindowTitle("Downloads")
        self.downloads_dialog.setMinimumSize(700, 500)
        layout = QVBoxLayout()

        # Tabs for active, paused and completed downloads
        self.downloads_tab_widget = QTabWidget()

        # Active Downloads Tab
        active_tab = QWidget()
        active_layout = QVBoxLayout()
        self.active_downloads_list = QListWidget()
        active_layout.addWidget(self.active_downloads_list)
        active_tab.setLayout(active_layout)

        # Paused Downloads Tab
        paused_tab = QWidget()
        paused_layout = QVBoxLayout()
        self.paused_downloads_list = QListWidget()
        paused_layout.addWidget(self.paused_downloads_list)
        paused_tab.setLayout(paused_layout)

        # Completed Downloads Tab
        completed_tab = QWidget()
        completed_layout = QVBoxLayout()
        self.completed_downloads_list = QListWidget()
        completed_layout.addWidget(self.completed_downloads_list)
        completed_tab.setLayout(completed_layout)

        # Double-click support for opening files
        self.completed_downloads_list.itemDoubleClicked.connect(self.open_selected_download)

        self.downloads_tab_widget.addTab(active_tab, "Active Downloads")
        self.downloads_tab_widget.addTab(paused_tab, "Paused Downloads")
        self.downloads_tab_widget.addTab(completed_tab, "Completed Downloads")
        layout.addWidget(self.downloads_tab_widget)

        # Button Layout
        btn_layout = QHBoxLayout()
        
        # Action buttons
        self.pause_btn = QPushButton(QIcon.fromTheme("media-playback-pause"), "Pause")
        self.pause_btn.setEnabled(False)
        self.pause_btn.clicked.connect(self.pause_selected_download)
        
        self.resume_btn = QPushButton(QIcon.fromTheme("media-playback-start"), "Resume")
        self.resume_btn.setEnabled(False)
        self.resume_btn.clicked.connect(self.resume_selected_download)
        
        self.cancel_btn = QPushButton(QIcon.fromTheme("process-stop"), "Cancel")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self.cancel_selected_download)
        
        # Navigation buttons
        self.open_btn = QPushButton(QIcon.fromTheme("document-open"), "Open")
        self.open_btn.setEnabled(False)
        self.open_btn.clicked.connect(self.open_selected_download)
        
        self.open_folder_btn = QPushButton(QIcon.fromTheme("folder-open"), "Open Folder")
        self.open_folder_btn.clicked.connect(self.open_download_folder)
        
        self.clear_btn = QPushButton(QIcon.fromTheme("edit-clear"), "Clear Completed")
        self.clear_btn.clicked.connect(self.download_manager.clear_completed_downloads)
        
        btn_layout.addWidget(self.pause_btn)
        btn_layout.addWidget(self.resume_btn)
        btn_layout.addWidget(self.cancel_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(self.open_btn)
        btn_layout.addWidget(self.open_folder_btn)
        btn_layout.addWidget(self.clear_btn)
        
        layout.addLayout(btn_layout)

        # Connect selection change signals
        self.active_downloads_list.itemSelectionChanged.connect(lambda: self.update_button_states(0))
        self.paused_downloads_list.itemSelectionChanged.connect(lambda: self.update_button_states(1))
        self.completed_downloads_list.itemSelectionChanged.connect(lambda: self.update_button_states(2))

        # Connect DownloadManager signals
        self.download_manager.download_started.connect(self.update_downloads_lists)
        self.download_manager.download_progress.connect(self.update_downloads_lists)
        self.download_manager.download_finished.connect(self.update_downloads_lists)
        self.download_manager.download_paused.connect(self.update_downloads_lists)
        self.download_manager.download_resumed.connect(self.update_downloads_lists)
        self.download_manager.download_list_updated.connect(self.update_downloads_lists)

        # Initial update
        self.update_downloads_lists()

        self.downloads_dialog.setLayout(layout)
        self.downloads_dialog.exec_()

    def update_button_states(self, tab_index):
        """Update button states based on current selection and tab."""
        # Reset all buttons
        self.pause_btn.setEnabled(False)
        self.resume_btn.setEnabled(False)
        self.cancel_btn.setEnabled(False)
        self.open_btn.setEnabled(False)
        
        # Active downloads tab
        if tab_index == 0:
            selected = self.active_downloads_list.selectedItems()
            self.pause_btn.setEnabled(bool(selected))
            self.cancel_btn.setEnabled(bool(selected))
        
        # Paused downloads tab
        elif tab_index == 1:
            selected = self.paused_downloads_list.selectedItems()
            self.resume_btn.setEnabled(bool(selected))
            self.cancel_btn.setEnabled(bool(selected))
        
        # Completed downloads tab
        elif tab_index == 2:
            selected = self.completed_downloads_list.selectedItems()
            self.open_btn.setEnabled(bool(selected))

    def pause_selected_download(self):
        """Pause the selected active download."""
        selected = self.active_downloads_list.selectedItems()
        if not selected:
            return

        download_id = selected[0].data(Qt.UserRole)
        print(f"[DEBUG] Attempting to pause download: {download_id}")

        if self.download_manager.pause_download(download_id):
            print(f"[DEBUG] Successfully paused download: {download_id}")
            self.update_downloads_lists()

            # Switch to paused tab
            self.downloads_tab_widget.setCurrentIndex(1)

            # Ensure the paused download is selected
            for i in range(self.paused_downloads_list.count()):
                if self.paused_downloads_list.item(i).data(Qt.UserRole) == download_id:
                    self.paused_downloads_list.setCurrentRow(i)
                    break

            self.status_bar.showMessage("Download paused", 2000)
        else:
            print(f"[DEBUG] Failed to pause download: {download_id}")
            self.status_bar.showMessage("Failed to pause download", 2000)


    def resume_selected_download(self):
        """Resume the selected paused download."""
        selected = self.paused_downloads_list.selectedItems()
        if not selected:
            return
        
        download_id = selected[0].data(Qt.UserRole)
        if self.download_manager.resume_download(download_id):
            # Ensure the download is moved to active state
            if download_id in self.download_manager.paused_downloads:
                download = self.download_manager.paused_downloads.pop(download_id)
                self.download_manager.active_downloads[download_id] = download
            
            # Update the lists and switch tab
            self.update_downloads_lists()
            self.downloads_tab_widget.setCurrentIndex(0)
            self.status_bar.showMessage("Download resumed", 2000)

    def cancel_selected_download(self):
        """Cancel the selected download (active or paused)."""
        current_tab = self.downloads_tab_widget.currentIndex()
        
        if current_tab == 0:  # Active downloads
            selected = self.active_downloads_list.selectedItems()
            if selected:
                download_id = selected[0].data(Qt.UserRole)
                self.download_manager.cancel_download(download_id)
        
        elif current_tab == 1:  # Paused downloads
            selected = self.paused_downloads_list.selectedItems()
            if selected:
                download_id = selected[0].data(Qt.UserRole)
                if download_id in self.download_manager.paused_downloads:
                    del self.download_manager.paused_downloads[download_id]
                    self.download_manager.download_list_updated.emit()
        
        self.status_bar.showMessage("Download canceled", 2000)



    def _create_download_item(self, download_id, download, state="active"):
        """Create a QListWidgetItem for a download based on its state."""
        received = download.get('received', 0)
        total = download.get('total', 1)
        percent = (received / total * 100) if total > 0 else 0

        if state == "active":
            speed = download.get("speed", 0)
            speed_str = f"{speed:.1f} KB/s" if speed > 0 else "Calculating..."
            item_text = f"{download['filename']} - {percent:.1f}% ({format_size(received)} of {format_size(total)}) | {speed_str}"
        elif state == "paused":
            item_text = f"{download['filename']} - {percent:.1f}% (PAUSED)"
        else:  # completed
            success = download.get('success', True)
            icon = "✓" if success else "✗"
            size = format_size(download.get('received', 0))
            item_text = f"{icon} {download['filename']} - {size}"

        item = QListWidgetItem(item_text)
        
        # Store both the download ID and file path in the item's data
        if state in ["active", "paused"]:
            item.setData(Qt.UserRole, download_id)
        else:  # completed
            item.setData(Qt.UserRole, download.get('path'))  # Store the full file path
        
        return item


    def delete_selected_download_file(self):
        """Delete the selected downloaded file from disk."""
        if self.completed_downloads_list.currentItem():
            path = self.completed_downloads_list.currentItem().data(Qt.UserRole)

            # Confirm deletion with user
            reply = QMessageBox.question(
                self,
                "Confirm Deletion",
                f"Are you sure you want to delete '{os.path.basename(path)}'?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )

            if reply == QMessageBox.Yes:
                try:
                    os.remove(path)
                    self.notification_manager.show_notification(
                        "File Deleted",
                        f"'{os.path.basename(path)}' was deleted successfully.",
                        5000
                    )
                    # Remove from list and update storage
                    row = self.completed_downloads_list.currentRow()
                    self.completed_downloads_list.takeItem(row)
                    self.download_manager.remove_completed_download(row)
                except Exception as e:
                    QMessageBox.critical(
                        self,
                        "Error",
                        f"Could not delete file: {str(e)}"
                    )


    def open_selected_download(self):
        """Open selected downloaded file."""
        current_tab = self.downloads_tab_widget.currentIndex()
        
        if current_tab == 2:  # Completed downloads tab
            selected_items = self.completed_downloads_list.selectedItems()
            if selected_items:
                file_path = selected_items[0].data(Qt.UserRole)
                if file_path and os.path.exists(file_path):
                    QDesktopServices.openUrl(QUrl.fromLocalFile(file_path))
                else:
                    QMessageBox.warning(
                        self, 
                        "File Not Found",
                        f"The file could not be found:\n{file_path}"
                    )

    def open_download_folder(self):
        """Open downloads folder."""
        QDesktopServices.openUrl(QUrl.fromLocalFile(DOWNLOAD_DIR))

    def cancel_selected_download(self):
        """Cancel selected active download."""
        if self.active_downloads_list.currentItem():
            download_id = self.active_downloads_list.currentItem().data(Qt.UserRole)
            if download_id in self.download_manager.active_downloads:
                download = self.download_manager.active_downloads[download_id]
                if 'item' in download:
                    download['item'].cancel()
                if download_id in self.download_manager.active_downloads:
                    del self.download_manager.active_downloads[download_id]
                self.update_downloads_lists()


    def update_downloads_lists(self):
        """Update all download lists while preserving selections."""
        try:
            # Store current selections
            active_selection = self.active_downloads_list.currentRow()
            paused_selection = self.paused_downloads_list.currentRow()
            completed_selection = self.completed_downloads_list.currentRow()

            # Clear all lists
            self.active_downloads_list.clear()
            self.paused_downloads_list.clear()
            self.completed_downloads_list.clear()

            # Debug prints to verify state
            print(f"[DEBUG] Active downloads: {len(self.download_manager.active_downloads)}")
            print(f"[DEBUG] Paused downloads: {len(self.download_manager.paused_downloads)}")
            print(f"[DEBUG] Completed downloads: {len(self.download_manager.completed_downloads)}")

            # Populate active downloads
            for download_id, download in self.download_manager.active_downloads.items():
                item = self._create_download_item(download_id, download, "active")
                self.active_downloads_list.addItem(item)

            # Populate paused downloads
            for download_id, download in self.download_manager.paused_downloads.items():
                item = self._create_download_item(download_id, download, "paused")
                self.paused_downloads_list.addItem(item)
                print(f"[DEBUG] Added paused download: {download_id} - {download['filename']}")

            # Populate completed downloads
            for download in self.download_manager.completed_downloads:
                item = self._create_download_item(None, download, "completed")
                self.completed_downloads_list.addItem(item)

            # Restore selections
            if 0 <= active_selection < self.active_downloads_list.count():
                self.active_downloads_list.setCurrentRow(active_selection)
            if 0 <= paused_selection < self.paused_downloads_list.count():
                self.paused_downloads_list.setCurrentRow(paused_selection)
            if 0 <= completed_selection < self.completed_downloads_list.count():
                self.completed_downloads_list.setCurrentRow(completed_selection)

        except Exception as e:
            print(f"[ERROR] Failed to update download lists: {e}")


    def on_active_download_selected(self):
        """Enable/disable cancel button based on selection and connect it."""
        selected = self.active_downloads_list.selectedItems()
        self.cancel_btn.setEnabled(len(selected) > 0)
        
        if selected:
            # Disconnect any existing connection to avoid multiple signals
            try:
                self.cancel_btn.clicked.disconnect()
            except TypeError:
                pass
                
            # Connect to cancel the currently selected download
            download_id = selected[0].data(Qt.UserRole)
            self.cancel_btn.clicked.connect(
                lambda: self.cancel_selected_download(download_id))

            

    # ====================== HISTORY ======================
    def show_history(self):
        """Show history dialog with search."""
        dialog = QDialog(self)
        dialog.setWindowTitle("History")
        dialog.setMinimumSize(800, 600)

        layout = QVBoxLayout()
        
        # Search bar
        search_layout = QHBoxLayout()
        self.history_search = QLineEdit()
        self.history_search.setPlaceholderText("Search history...")
        search_btn = QPushButton("Search")
        clear_btn = QPushButton("Clear History")
        search_layout.addWidget(self.history_search)
        search_layout.addWidget(search_btn)
        search_layout.addWidget(clear_btn)
        layout.addLayout(search_layout)
        
        # History list
        self.history_list = QTreeWidget()
        self.history_list.setHeaderLabels(["Title", "URL", "Last Visited"])
        self.history_list.setColumnWidth(0, 250)
        self.history_list.setColumnWidth(1, 350)
        self.history_list.itemDoubleClicked.connect(self.open_history_item)
        self.refresh_history_list()
        layout.addWidget(self.history_list)
        
        # Connect signals
        search_btn.clicked.connect(self.refresh_history_list)
        clear_btn.clicked.connect(self.clear_history)
        self.history_search.textChanged.connect(self.refresh_history_list)
        
        dialog.setLayout(layout)
        dialog.exec_()

    def refresh_history_list(self):
        """Refresh history list with optional search."""
        search_query = self.history_search.text()
        history = self.history_manager.get_history(search_query=search_query)
        
        self.history_list.clear()
        
        # Group by date
        date_groups = {}
        for entry in history:
            visit_date = datetime.fromisoformat(entry["date"]).strftime("%Y-%m-%d")
            if visit_date not in date_groups:
                date_groups[visit_date] = []
            date_groups[visit_date].append(entry)
        
        # Add to tree
        for date, entries in sorted(date_groups.items(), reverse=True):
            date_item = QTreeWidgetItem(self.history_list, [date, "", ""])
            for entry in entries:
                QTreeWidgetItem(date_item, [
                    entry["title"],
                    entry["url"],
                    datetime.fromisoformat(entry["date"]).strftime("%H:%M:%S")
                ])
            date_item.setExpanded(True)

    def clear_history(self):
        """Clear browsing history."""
        reply = QMessageBox.question(
            self, "Clear History",
            "Are you sure you want to clear all browsing history?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.history_manager.clear_history()
            self.refresh_history_list()

    def open_history_item(self, item, column):
        """Open history item in current tab."""
        if item.childCount() == 0:  # Not a date group
            url = item.text(1)
            self.current_browser().setUrl(QUrl(url))

    def show_settings(self):
        """Display comprehensive settings dialog with organized configuration options."""
        # Create the dialog with proper parent handling
        dialog = QDialog(self) if isinstance(self, QWidget) else QDialog()
        dialog.setWindowTitle("Browser Settings")
        dialog.setMinimumSize(900, 700)
        dialog.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        tab_widget = QTabWidget()
        tab_widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        # ==================== GENERAL TAB ====================
        general_tab = QWidget()
        general_layout = QFormLayout()
        general_layout.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)

        # Home Page
        self.home_page_edit = QLineEdit(self.settings_manager.get("home_page", "https://www.google.com"))
        general_layout.addRow(QLabel("Home Page:"), self.home_page_edit)

        # Search Engine
        self.search_engine_edit = QLineEdit(self.settings_manager.get("search_engine", "https://www.google.com/search?q="))
        general_layout.addRow(QLabel("Search Engine:"), self.search_engine_edit)

        # Download Directory
        download_layout = QHBoxLayout()
        self.download_dir_edit = QLineEdit(self.settings_manager.get("download_dir", ""))
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(lambda: self.browse_download_dir(dialog))
        download_layout.addWidget(self.download_dir_edit)
        download_layout.addWidget(browse_btn)
        general_layout.addRow(QLabel("Download Directory:"), download_layout)

        # Media Settings
        media_group = QGroupBox("Media Playback")
        media_layout = QVBoxLayout()
        self.hls_check = QCheckBox("Enable HLS Streaming Support")
        self.hls_check.setChecked(self.settings_manager.get("hls_enabled", True))
        media_layout.addWidget(self.hls_check)

        self.drm_check = QCheckBox("Enable DRM Content (Widevine)")
        self.drm_check.setChecked(self.settings_manager.get("drm_enabled", False))
        media_layout.addWidget(self.drm_check)
        media_group.setLayout(media_layout)
        general_layout.addRow(media_group)

        # Performance Settings
        perf_group = QGroupBox("Performance")
        perf_layout = QVBoxLayout()
        self.hardware_accel_check = QCheckBox("Enable Hardware Acceleration")
        self.hardware_accel_check.setChecked(self.settings_manager.get("hardware_acceleration", True))
        perf_layout.addWidget(self.hardware_accel_check)
        perf_group.setLayout(perf_layout)
        general_layout.addRow(perf_group)

        # Accessibility Settings
        accessibility_group = QGroupBox("Accessibility")
        accessibility_layout = QFormLayout()
        
        self.zoom_factor_spin = QDoubleSpinBox()
        self.zoom_factor_spin.setRange(0.5, 3.0)
        self.zoom_factor_spin.setSingleStep(0.1)
        self.zoom_factor_spin.setValue(self.settings_manager.get("default_zoom", 1.0))
        accessibility_layout.addRow(QLabel("Default Zoom Factor:"), self.zoom_factor_spin)
        
        self.font_size_spin = QSpinBox()
        self.font_size_spin.setRange(8, 24)
        self.font_size_spin.setValue(self.settings_manager.get("font_size", 12))
        accessibility_layout.addRow(QLabel("Font Size:"), self.font_size_spin)
        
        accessibility_group.setLayout(accessibility_layout)
        general_layout.addRow(accessibility_group)

        general_tab.setLayout(general_layout)

        # ==================== THEMES TAB ====================
        themes_tab = QWidget()
        themes_layout = QVBoxLayout()
        
        # Theme Mode Selection
        theme_mode_group = QGroupBox("Theme Mode")
        theme_mode_layout = QVBoxLayout()
        
        self.system_theme_radio = QRadioButton("Follow System Theme")
        self.light_theme_radio = QRadioButton("Force Light Theme")
        self.dark_theme_radio = QRadioButton("Force Dark Theme")
        
        # Set current selection
        theme_mode = self.settings_manager.get("theme_mode", "system")
        if theme_mode == "system":
            self.system_theme_radio.setChecked(True)
        elif theme_mode == "light":
            self.light_theme_radio.setChecked(True)
        else:
            self.dark_theme_radio.setChecked(True)
        
        theme_mode_layout.addWidget(self.system_theme_radio)
        theme_mode_layout.addWidget(self.light_theme_radio)
        theme_mode_layout.addWidget(self.dark_theme_radio)
        theme_mode_group.setLayout(theme_mode_layout)
        themes_layout.addWidget(theme_mode_group)
        
        # Accent Color Selection
        color_group = QGroupBox("Accent Color")
        color_layout = QGridLayout()
        
        accent_colors = self.settings_manager.get("theme", {}).get("available_colors", [
            {"name": "Blue", "color": "#3daee9"},
            {"name": "Red", "color": "#e74c3c"},
            {"name": "Green", "color": "#2ecc71"},
            {"name": "Purple", "color": "#9b59b6"},
            {"name": "Orange", "color": "#e67e22"},
            {"name": "Pink", "color": "#e91e63"},
            {"name": "Teal", "color": "#1abc9c"},
            {"name": "Yellow", "color": "#f1c40f"}
        ])
        
        current_color = self.settings_manager.get("theme", {}).get("accent_color", "#3daee9")
        self.color_buttons = []
        
        for i, color_info in enumerate(accent_colors):
            btn = QPushButton()
            btn.setFixedSize(40, 40)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {color_info["color"]};
                    border: none;
                    border-radius: 20px;
                }}
                QPushButton:hover {{
                    border: 2px solid white;
                }}
                QPushButton:checked {{
                    border: 3px solid white;
                }}
            """)
            btn.setCheckable(True)
            btn.setChecked(color_info["color"] == current_color)
            btn.clicked.connect(lambda _, c=color_info["color"]: self.settings_manager.apply_accent_color(c))
            self.color_buttons.append(btn)
            color_layout.addWidget(btn, i // 4, i % 4)
        
        color_group.setLayout(color_layout)
        themes_layout.addWidget(color_group)
        
        # Custom CSS
        css_group = QGroupBox("Custom Styling")
        css_layout = QVBoxLayout()
        
        self.css_edit = QPlainTextEdit()
        self.css_edit.setPlaceholderText("Enter custom CSS rules here...")
        self.css_edit.setPlainText(self.settings_manager.get("custom_css", ""))
        css_layout.addWidget(self.css_edit)
        
        btn_layout = QHBoxLayout()
        preview_btn = QPushButton("Preview Theme")
        preview_btn.clicked.connect(lambda: self.preview_theme_changes(dialog))
        reset_btn = QPushButton("Reset to Default")
        reset_btn.clicked.connect(self.reset_theme_settings)
        btn_layout.addWidget(preview_btn)
        btn_layout.addWidget(reset_btn)
        css_layout.addLayout(btn_layout)
        
        css_group.setLayout(css_layout)
        themes_layout.addWidget(css_group)
        
        themes_layout.addStretch()
        themes_tab.setLayout(themes_layout)

        # ==================== PRIVACY TAB ====================
        privacy_tab = QWidget()
        privacy_layout = QFormLayout()

        # Content Settings
        content_group = QGroupBox("Content Settings")
        content_layout = QVBoxLayout()
        self.ad_blocker_check = QCheckBox("Enable Ad Blocker")
        self.ad_blocker_check.setChecked(self.settings_manager.get("ad_blocker", True))
        
        self.tracking_protection_check = QCheckBox("Enable Tracking Protection")
        self.tracking_protection_check.setChecked(self.settings_manager.get("tracking_protection", True))
        
        self.js_check = QCheckBox("Enable JavaScript")
        self.js_check.setChecked(self.settings_manager.get("javascript_enabled", True))

        self.images_check = QCheckBox("Load Images Automatically")
        self.images_check.setChecked(self.settings_manager.get("auto_load_images", True))
        
        content_layout.addWidget(self.ad_blocker_check)
        content_layout.addWidget(self.tracking_protection_check)
        content_layout.addWidget(self.js_check)
        content_layout.addWidget(self.images_check)
        content_group.setLayout(content_layout)
        privacy_layout.addRow(content_group)

        # Cookie Settings
        cookie_group = QGroupBox("Cookie Management")
        cookie_layout = QVBoxLayout()

        # Cookie acceptance
        self.accept_cookies_check = QCheckBox("Accept cookies")
        self.accept_cookies_check.setChecked(self.settings_manager.get("cookies", {}).get("accept_cookies", True))
        cookie_layout.addWidget(self.accept_cookies_check)

        # Third-party cookies
        self.third_party_check = QCheckBox("Accept third-party cookies")
        self.third_party_check.setChecked(self.settings_manager.get("cookies", {}).get("accept_third_party", False))
        cookie_layout.addWidget(self.third_party_check)

        # Cookie lifetime
        lifetime_layout = QHBoxLayout()
        lifetime_layout.addWidget(QLabel("Cookie lifetime:"))
        self.cookie_lifetime_combo = QComboBox()
        self.cookie_lifetime_combo.addItems([
            "Until browser closes",
            "1 day",
            "1 week",
            "1 month",
            "Keep until expired"
        ])
        current_lifetime = self.settings_manager.get("cookies", {}).get("keep_cookies_until", "session_end")
        lifetime_map = {
            "session_end": 0,
            "one_day": 1,
            "one_week": 2,
            "one_month": 3,
            "forever": 4
        }
        self.cookie_lifetime_combo.setCurrentIndex(lifetime_map.get(current_lifetime, 0))
        lifetime_layout.addWidget(self.cookie_lifetime_combo)
        cookie_layout.addLayout(lifetime_layout)

        # Cookie management button
        manage_cookies_btn = QPushButton("Manage Cookies...")
        manage_cookies_btn.clicked.connect(self.show_cookie_manager)
        cookie_layout.addWidget(manage_cookies_btn)

        cookie_group.setLayout(cookie_layout)
        privacy_layout.addRow(cookie_group)

        # User Agent Settings
        ua_group = QGroupBox("User Agent")
        ua_layout = QVBoxLayout()
        self.user_agent_edit = QLineEdit(self.settings_manager.get("user_agent", USER_AGENT))
        ua_layout.addWidget(self.user_agent_edit)

        preset_ua_layout = QHBoxLayout()
        desktop_ua_btn = QPushButton("Desktop")
        mobile_ua_btn = QPushButton("Mobile")
        custom_ua_btn = QPushButton("Custom")

        desktop_ua_btn.clicked.connect(lambda: self.user_agent_edit.setText(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.6778.85 Safari/537.36"
        ))
        mobile_ua_btn.clicked.connect(lambda: self.user_agent_edit.setText(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.6778.85 Safari/537.36"
        ))
        custom_ua_btn.clicked.connect(lambda: self.user_agent_edit.setText("Custom"))

        preset_ua_layout.addWidget(desktop_ua_btn)
        preset_ua_layout.addWidget(mobile_ua_btn)
        preset_ua_layout.addWidget(custom_ua_btn)
        ua_layout.addLayout(preset_ua_layout)
        ua_group.setLayout(ua_layout)
        privacy_layout.addRow(ua_group)

        privacy_tab.setLayout(privacy_layout)

        # ==================== SHORTCUTS TAB ====================
        shortcuts_tab = QWidget()
        shortcuts_layout = QVBoxLayout(shortcuts_tab)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)

        # Shortcut Categories
        categories = {
            "Navigation": [
                ("Back", "back", "Alt+Left"),
                ("Forward", "forward", "Alt+Right"),
                ("Reload", "reload", "F5"),
                ("Hard Reload", "reload_ignore_cache", "Shift+F5"),
                ("Stop Loading", "stop", "Esc"),
                ("Go to Home", "home", "Alt+Home"),
                ("Url Launcher", "launch_url_prompt", "Ctrl+L"),
            ],
            "Tab Management": [
                ("New Tab", "new_tab", "Ctrl+T"),
                ("Close Tab", "close_tab", "Ctrl+W"),
                ("Next Tab", "next_tab", "Ctrl+Tab"),
                ("Previous Tab", "prev_tab", "Ctrl+Shift+Tab"),
                ("Restore Closed Tab", "restore_tab", "Ctrl+Shift+T"),
                ("New Incognito Tab", "incognito_tab", "Ctrl+Shift+N"),
            ],
            "Focus & Search": [
                ("Focus URL Bar", "focus_url", "Ctrl+Shift+L"),
                ("Focus Search Bar", "focus_search", "Ctrl+K"),
                ("Search Selected Text", "search_selected", "Ctrl+E"),
                ("Autocomplete URL", "autocomplete_url", "Ctrl+Return"),
            ],
            "Bookmarks": [
                ("Bookmark Search", "bookmark_search", "Ctrl+B"),
                ("Bookmark Current Page", "bookmark_page", "Ctrl+D"),
            ],
            "Tools": [
                ("Downloads", "downloads", "Ctrl+J"),
                ("History", "history", "Ctrl+H"),
                ("Settings", "settings", "Ctrl+,"),
                ("Print", "print", "Ctrl+P"),
                ("Save as PDF", "print_pdf", "Ctrl+Shift+P"),
                ("Calendar", "calendar", "Ctrl+Shift+C"),
            ],
            "Search": [
                ("Multi-Site Search", "multi_site_search", "Ctrl+K"),
            ],
            "Screenshots": [
                ("Capture Screenshot", "screenshot", "Ctrl+Shift+S"),
                ("Full Page Screenshot", "full_screenshot", "Ctrl+Alt+Shift+S"),
                ("Region Screenshot", "region_screenshot", "Ctrl+Shift+R"),
            ],
            "Developer Tools": [
                ("Toggle DevTools", "dev_tools", "F12"),
                ("View Page Source", "view_source", "Ctrl+U"),
            ],
            "Zoom": [
                ("Zoom In", "zoom_in", "Ctrl++"),
                ("Zoom Out", "zoom_out", "Ctrl+-"),
                ("Reset Zoom", "zoom_reset", "Ctrl+0"),
            ]
        }

        self.shortcut_editors = {}

        for category_name, items in categories.items():
            group = QGroupBox(category_name)
            group_layout = QFormLayout()
            for label, name, default in items:
                editor = QKeySequenceEdit(QKeySequence(self.settings_manager.get_shortcut(name) or default))
                self.shortcut_editors[name] = editor
                group_layout.addRow(label + ":", editor)
            group.setLayout(group_layout)
            scroll_layout.addWidget(group)

        scroll_layout.addStretch()
        scroll.setWidget(scroll_content)
        shortcuts_layout.addWidget(scroll)

        btn_layout = QHBoxLayout()
        reset_btn = QPushButton("Reset All Shortcuts to Defaults")
        reset_btn.clicked.connect(self.reset_shortcuts_to_defaults)
        btn_layout.addStretch()
        btn_layout.addWidget(reset_btn)
        shortcuts_layout.addLayout(btn_layout)

        # ==================== ABOUT TAB ====================
# ==================== ABOUT TAB ====================
        about_tab = QWidget()
        about_layout = QVBoxLayout()
        about_layout.setAlignment(Qt.AlignTop)
        about_layout.setContentsMargins(20, 20, 20, 20)
        about_layout.setSpacing(15)

        # App logo/icon
        self.logo_label = QLabel()
        pixmap = QPixmap(":/icons/app_icon.png").scaled(64, 64, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        self.logo_label.setPixmap(pixmap)
        self.logo_label.setAlignment(Qt.AlignCenter)
        about_layout.addWidget(self.logo_label)

        # App name and version
        self.title_label = QLabel("Icarus Browser")
        self.title_label.setAlignment(Qt.AlignCenter)
        title_font = self.title_label.font()
        title_font.setPointSize(20)
        title_font.setBold(True)
        self.title_label.setFont(title_font)
        about_layout.addWidget(self.title_label)

        self.version_label = QLabel(f"Version: {self.get_version()}")
        self.version_label.setAlignment(Qt.AlignCenter)
        about_layout.addWidget(self.version_label)

        # Separator
        about_layout.addWidget(QLabel())  # Spacer
        about_layout.addWidget(QFrame(frameShape=QFrame.HLine, frameShadow=QFrame.Sunken))

        # Description
        desc_label = QLabel("""
        <p><b>Storm Browser</b> is a modern, privacy-focused web browser built with Python and Qt.</p>
        <p>It offers a fast, secure, and customizable browsing experience with a wide range of features designed to enhance your productivity and privacy.</p>
        """)
        desc_label.setWordWrap(True)
        desc_label.setAlignment(Qt.AlignCenter)
        about_layout.addWidget(desc_label)

        # Features
        features_label = QLabel("""
        <h3>Key Features</h3>
        <ul>
            <li><b>Modern Web Engine:</b> Powered by QtWebEngine (Chromium-based) with full HTML5, WebRTC, WebGL, and WebAssembly support.</li>
            <li><b>Privacy Protection:</b> Built-in ad blocker, tracking protection, cookie controls, and incognito mode with isolated sessions.</li>
            <li><b>Customizable UI:</b> Light, dark, and system theme modes with accent color selection, custom CSS injection, and live preview.</li>
            <li><b>Tab Management:</b> Movable, closable tabs with + button, background tab opening, pinning, and session restore.</li>
            <li><b>Smart Navigation:</b> Unified search & URL bar with auto-completion, bookmark/URL/description search, and home button.</li>
            <li><b>Productivity Tools:</b> Integrated rich-text Notes and calendar with event scheduling and desktop reminders.</li>
            <li><b>Download Manager:</b> Organized view with active, paused, and completed downloads; supports pause/resume and file opening.</li>
            <li><b>Security:</b> Fine-grained content settings (JavaScript, images, popups), user agent switching, and secure password storage.</li>
            <li><b>Cross-Platform:</b> Native support for Windows, Linux, and macOS with consistent UI and behavior.</li>
        </ul>
        <h3>Advanced Features</h3>
        <ul>
            <li><b>Screen Recording:</b> Record full screen, application window, or custom region with system + microphone audio, countdown timer, and quality settings.</li>
            <li><b>Screenshot Tool:</b> Capture full page, visible area, or selected region with copy-to-clipboard and save options.</li>
            <li><b>Fullscreen Mode:</b> True fullscreen browsing with custom event handling and immersive experience.</li>
            <li><b>Bookmark Manager:</b> Hierarchical tree view with search, multi-select, drag-and-drop, and import from Chrome/Firefox.</li>
            <li><b>Settings Framework:</b> Persistent settings with form-based UI, reset options, and real-time theme preview.</li>
            <li><b>Developer Tools:</b> Toggleable web inspector for debugging pages, network analysis, and DOM inspection.</li>
            <li><b>Custom Shortcuts:</b> Fully configurable keyboard shortcuts for navigation, tabs, tools, and media controls.</li>
            <li><b>Favicon Management:</b> Automatic favicon fetching and display on tabs, bookmarks, and history.</li>
            <li><b>Blue Light Filter:</b> Reduce eye strain with a warm screen filter during night-time browsing.</li>
            <li><b>Find-in-Page:</b> Dedicated search bar with case-sensitive and whole-word options.</li>
            <li><b>Event & Reminder System:</b> Calendar-integrated event management with optional pop-up and audio reminders.</li>
        </ul>
        """)
        features_label.setWordWrap(True)
        features_label.setTextFormat(Qt.RichText)
        features_label.setOpenExternalLinks(False)
        about_layout.addWidget(features_label)

        # Credits
        credits_label = QLabel("""
        <h3>Credits</h3>
        <p><b>Developed by:</b> Your Name</p>
        <p><b>Qt Framework:</b> <a href="https://www.qt.io">Qt Framework</a> by The Qt Company</p>
        <p><b>Python Bindings:</b> PyQt5</p>
        <p><b>Web Engine:</b> Chromium via QtWebEngine</p>
        <p><b>Icons:</b> Material Design Icons and system theme icons</p>
        <p><b>Special Thanks:</b> Open-source community and contributors</p>
        """)
        credits_label.setWordWrap(True)
        credits_label.setTextFormat(Qt.RichText)
        credits_label.setOpenExternalLinks(True)
        about_layout.addWidget(credits_label)

        # Links
        links_layout = QHBoxLayout()
        github_btn = QPushButton("GitHub Repository")
        github_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://github.com/yourusername/Icarus-browser")))
        website_btn = QPushButton("Official Website")
        website_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://yourwebsite.com")))

        links_layout.addWidget(github_btn)
        links_layout.addWidget(website_btn)
        about_layout.addLayout(links_layout)

        # License
        license_label = QLabel("""
        <small>Licensed under the <a href="https://www.gnu.org/licenses/gpl-3.0.html">GNU General Public License v3.0</a></small>
        """)
        license_label.setAlignment(Qt.AlignCenter)
        license_label.setTextFormat(Qt.RichText)
        license_label.setOpenExternalLinks(True)
        about_layout.addWidget(license_label)

        about_tab.setLayout(about_layout)


        # Add all tabs to the tab widget
        tab_widget.addTab(general_tab, "General")
        tab_widget.addTab(themes_tab, "Themes")
        tab_widget.addTab(privacy_tab, "Privacy")
        tab_widget.addTab(shortcuts_tab, "Shortcuts")
        tab_widget.addTab(about_tab, "About")

        # Dialog buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel,
            Qt.Horizontal, dialog
        )
        button_box.accepted.connect(lambda: self.save_settings(dialog))
        button_box.rejected.connect(dialog.reject)

        main_layout = QVBoxLayout(dialog)
        main_layout.addWidget(tab_widget)
        main_layout.addWidget(button_box)

        if self.settings_manager.get("dark_mode"):
            self._apply_dark_mode_to_dialog(dialog)

        dialog.exec_()

    def get_version(self):
        """Get current version from package or constant"""
        try:
            from . import __version__
            return __version__
        except ImportError:
            return "1.0.0"  # Fallback version

        
    def preview_theme_changes(self, dialog=None):
        """Show a preview of theme changes before applying."""
        preview = QDialog(dialog) if dialog else QDialog()
        preview.setWindowTitle("Theme Preview")
        preview.setMinimumSize(400, 500)
        
        layout = QVBoxLayout()
        
        # Sample widgets to demonstrate theme
        sample_label = QLabel("This is a sample label showing text styling")
        sample_button = QPushButton("Sample Button")
        sample_checkbox = QCheckBox("Checkbox Example")
        sample_lineedit = QLineEdit("Sample text input")
        sample_combobox = QComboBox()
        sample_combobox.addItems(["Option 1", "Option 2", "Option 3"])
        sample_slider = QSlider(Qt.Horizontal)
        sample_slider.setRange(0, 100)
        sample_slider.setValue(50)
        
        # Add widgets to layout
        layout.addWidget(sample_label)
        layout.addWidget(sample_button)
        layout.addWidget(sample_checkbox)
        layout.addWidget(sample_lineedit)
        layout.addWidget(sample_combobox)
        layout.addWidget(sample_slider)
        
        # Apply current theme settings to preview
        theme_mode = "dark" if self.dark_theme_radio.isChecked() else "light"
        accent_color = None
        for btn in self.color_buttons:
            if btn.isChecked():
                accent_color = btn.palette().button().color().name()
                break
        
        # Create temporary settings for preview
        temp_settings = {
            "theme_mode": theme_mode,
            "theme": {
                "accent_color": accent_color or "#3daee9",
                "available_colors": self.settings_manager.get("theme", {}).get("available_colors", [])
            },
            "custom_css": self.css_edit.toPlainText(),
            "font_size": self.font_size_spin.value()
        }
        
        # Apply to preview window
        self._apply_theme_to_widget(preview, temp_settings)
        
        preview.setLayout(layout)
        preview.exec_()

    def reset_theme_settings(self):
        """Reset theme settings to defaults."""
        self.system_theme_radio.setChecked(True)
        for btn in self.color_buttons:
            if btn.palette().button().color().name() == "#3daee9":
                btn.setChecked(True)
                break
        self.css_edit.setPlainText("")
        self.notification_manager.show_notification("Theme Reset", "Theme settings restored to defaults", 2000)

    def reset_shortcuts_to_defaults(self):
        """Reset all shortcuts to their default values."""
        defaults = {
            "back": "Alt+Left",
            "forward": "Alt+Right",
            "reload": "F5",
            "reload_ignore_cache": "Shift+F5",
            "stop": "Esc",
            "home": "Alt+Home",
            "new_tab": "Ctrl+T",
            "close_tab": "Ctrl+W",
            "next_tab": "Ctrl+Tab",
            "prev_tab": "Ctrl+Shift+Tab",
            "restore_tab": "Ctrl+Shift+T",
            "incognito_tab": "Ctrl+Shift+N",
            "focus_url": "Ctrl+L",
            "focus_search": "Ctrl+K",
            "search_selected": "Ctrl+E",
            "autocomplete_url": "Ctrl+Return",
            "bookmark_search": "Ctrl+B",
            "bookmark_page": "Ctrl+D",
            "downloads": "Ctrl+J",
            "history": "Ctrl+H",
            "settings": "Ctrl+,",
            "print": "Ctrl+P",
            "print_pdf": "Ctrl+Shift+P",
            "calendar": "Ctrl+Shift+C",
            "multi_site_search": "Ctrl+K",
            "screenshot": "Ctrl+Shift+S",
            "full_screenshot": "Ctrl+Alt+Shift+S",
            "region_screenshot": "Ctrl+Shift+R",
            "dev_tools": "F12",
            "view_source": "Ctrl+U",
            "zoom_in": "Ctrl++",
            "zoom_out": "Ctrl+-",
            "zoom_reset": "Ctrl+0"
        }
        
        for name, editor in self.shortcut_editors.items():
            editor.setKeySequence(QKeySequence(defaults.get(name, "")))
        
        self.notification_manager.show_notification("Shortcuts Reset", "All shortcuts restored to defaults", 2000)

    def browse_download_dir(self):
        """Open directory dialog to select download location."""
        dir_path = QFileDialog.getExistingDirectory(self.parent, "Select Download Directory")
        if dir_path:
            self.download_dir_edit.setText(dir_path)

    def show_cookie_manager(self):
        """Display cookie management dialog."""
        # Implementation would go here
        QMessageBox.information(self.parent, "Cookie Manager", "Cookie management functionality would be implemented here")

    def _apply_theme_to_widget(self, widget, settings):
        """Apply theme settings to a specific widget."""
        is_dark = settings["theme_mode"] == "dark"
        accent_color = settings["theme"]["accent_color"]
        custom_css = settings.get("custom_css", "")
        
        # Base colors
        if is_dark:
            base_color = "#2d2d2d"
            text_color = "#f0f0f0"
            button_color = "#3a3a3a"
            highlight_color = accent_color
            window_color = "#252525"
        else:
            base_color = "#f0f0f0"
            text_color = "#000000"
            button_color = "#e0e0e0"
            highlight_color = accent_color
            window_color = "#ffffff"
        
        # Build stylesheet
        stylesheet = f"""
            QWidget {{
                background-color: {base_color};
                color: {text_color};
                font-size: {self.settings_manager.get("font_size", 12)}px;
            }}
            QPushButton {{
                background-color: {button_color};
                color: {text_color};
                border: 1px solid {highlight_color};
                padding: 5px;
                border-radius: 3px;
            }}
            QPushButton:hover {{
                background-color: {highlight_color};
            }}
            QLineEdit, QComboBox, QPlainTextEdit {{
                background-color: {window_color};
                color: {text_color};
                border: 1px solid {button_color};
                padding: 3px;
            }}
            QCheckBox, QRadioButton {{
                spacing: 5px;
            }}
            QGroupBox {{
                border: 1px solid {button_color};
                border-radius: 3px;
                margin-top: 10px;
                padding-top: 15px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 10px;
                color: {highlight_color};
            }}
            QSlider::groove:horizontal {{
                height: 8px;
                background: {button_color};
                margin: 2px 0;
                border-radius: 4px;
            }}
            QSlider::handle:horizontal {{
                background: {highlight_color};
                border: 1px solid {button_color};
                width: 18px;
                margin: -4px 0;
                border-radius: 9px;
            }}
        """
        
        # Add custom CSS if provided
        if custom_css:
            stylesheet += "\n" + custom_css
        
        widget.setStyleSheet(stylesheet)

    def _apply_dark_mode_to_dialog(self, dialog):
        """Apply dark theme to any dialog."""
        theme = self.settings_manager.get("dark_theme", {
            "base_color": "#2d2d2d",
            "text_color": "#f0f0f0",
            "button_color": "#3a3a3a",
            "highlight_color": "#3daee9",
            "window_color": "#252525"
        })
        
        dialog.setStyleSheet(f"""
            QDialog {{
                background-color: {theme["base_color"]};
                color: {theme["text_color"]};
                font-size: {self.settings_manager.get("font_size", 12)}px;
            }}
            QGroupBox {{
                border: 1px solid {theme["button_color"]};
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 15px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 10px;
                color: {theme["highlight_color"]};
                padding: 0 3px;
            }}
            QLineEdit, QComboBox, QTreeWidget, QPlainTextEdit, QSpinBox, QDoubleSpinBox {{
                background-color: {theme["window_color"]};
                color: {theme["text_color"]};
                border: 1px solid {theme["button_color"]};
                padding: 5px;
            }}
            QPushButton {{
                background-color: {theme["button_color"]};
                color: {theme["text_color"]};
                border: 1px solid {theme["highlight_color"]};
                padding: 5px 10px;
                min-width: 80px;
                border-radius: 3px;
            }}
            QPushButton:hover {{
                background-color: {theme["highlight_color"]};
            }}
            QTreeWidget::item:hover {{
                background-color: {theme["highlight_color"]};
                color: black;
            }}
            QTreeWidget::item:selected {{
                background-color: {theme["highlight_color"]};
                color: black;
            }}
            QCheckBox, QRadioButton {{
                spacing: 5px;
            }}
            QTabWidget::pane {{
                border: 1px solid {theme["button_color"]};
            }}
            QTabBar::tab {{
                background: {theme["button_color"]};
                color: {theme["text_color"]};
                padding: 5px 10px;
                border: 1px solid {theme["button_color"]};
                border-bottom: none;
                border-top-left-radius: 3px;
                border-top-right-radius: 3px;
            }}
            QTabBar::tab:selected {{
                background: {theme["base_color"]};
                border-color: {theme["highlight_color"]};
            }}
        """)

    def save_settings(self, dialog):
        """Save all settings to configuration file."""
        try:
            # General settings
            self.settings_manager.set("home_page", self.home_page_edit.text())
            self.settings_manager.set("search_engine", self.search_engine_edit.text())
            self.settings_manager.set("download_dir", self.download_dir_edit.text())
            self.settings_manager.set("hardware_acceleration", self.hardware_accel_check.isChecked())
            self.settings_manager.set("default_zoom", self.zoom_factor_spin.value())
            self.settings_manager.set("font_size", self.font_size_spin.value())
            
            # Theme settings
            if self.system_theme_radio.isChecked():
                self.settings_manager.set("theme_mode", "system")
            elif self.light_theme_radio.isChecked():
                self.settings_manager.set("theme_mode", "light")
            else:
                self.settings_manager.set("theme_mode", "dark")
            
            # Save accent color
            for btn in self.color_buttons:
                if btn.isChecked():
                    color = btn.palette().button().color().name()
                    self.settings_manager.apply_accent_color(color)
                    break
            
            # Save custom CSS
            self.settings_manager.set("custom_css", self.css_edit.toPlainText())
            
            # Media
            self.settings_manager.set("hls_enabled", self.hls_check.isChecked())
            self.settings_manager.set("drm_enabled", self.drm_check.isChecked())
            
            # Privacy
            self.settings_manager.set("ad_blocker", self.ad_blocker_check.isChecked())
            self.settings_manager.set("tracking_protection", self.tracking_protection_check.isChecked())
            self.settings_manager.set("javascript_enabled", self.js_check.isChecked())
            self.settings_manager.set("auto_load_images", self.images_check.isChecked())
            self.settings_manager.set("user_agent", self.user_agent_edit.text())
            
            # Cookie settings
            cookie_settings = {
                "accept_cookies": self.accept_cookies_check.isChecked(),
                "accept_third_party": self.third_party_check.isChecked(),
                "keep_cookies_until": ["session_end", "one_day", "one_week", "one_month", "forever"][self.cookie_lifetime_combo.currentIndex()]
            }
            self.settings_manager.set("cookies", cookie_settings)
            
            # Apply theme changes immediately
            self.settings_manager.apply_theme(QApplication.instance())
            
            # Save shortcuts
            shortcuts = {
                name: editor.keySequence().toString()
                for name, editor in self.shortcut_editors.items()
            }
            self.settings_manager.set("shortcuts", shortcuts)
            
            # Reconfigure browser with new settings
            if hasattr(self.parent, 'configure_webengine'):
                self.parent.configure_webengine()
            if hasattr(self.parent, 'setup_shortcuts'):
                self.parent.setup_shortcuts()
            
            dialog.accept()
            self.notification_manager.show_notification(
                "Settings Saved", 
                "Your preferences have been updated",
                3000
            )
            
        except Exception as e:
            logging.error(f"Error saving settings: {str(e)}")
            QMessageBox.warning(
                self.parent,
                "Save Error",
                f"Failed to save settings: {str(e)}"
            )

    def apply_theme(self, app):
        """Apply theme to the entire application, including the URL bar."""
        theme_mode = self.settings_manager.get("theme_mode", "system")
        use_dark = False
        
        if theme_mode == "system":
            use_dark = self.should_use_dark_mode()
        elif theme_mode == "dark":
            use_dark = True
        
        if use_dark:
            # Dark theme
            palette = QPalette()
            palette.setColor(QPalette.Window, QColor(53, 53, 53))
            palette.setColor(QPalette.WindowText, Qt.white)
            palette.setColor(QPalette.Base, QColor(25, 25, 25))
            palette.setColor(QPalette.Text, Qt.white)
            palette.setColor(QPalette.Button, QColor(53, 53, 53))
            palette.setColor(QPalette.ButtonText, Qt.white)
            palette.setColor(QPalette.Highlight, QColor(self.settings_manager.get("theme", {}).get("accent_color", "#3daee9")))
            palette.setColor(QPalette.HighlightedText, Qt.black)
            app.setPalette(palette)

            # Explicitly style the URL bar
            app.setStyleSheet(f"""
                QLineEdit {{
                    background-color: #2d2d2d;
                    color: #ffffff;
                    border: 1px solid #444;
                    padding: 5px;
                    font-size: {self.settings_manager.get("font_size", 12)}px;
                }}
                QLineEdit:hover {{
                    border: 1px solid #555;
                }}
                QTabBar::tab {{
                    background: #3a3a3a;
                    color: #f0f0f0;
                    padding: 5px 10px;
                    border: 1px solid #444;
                    border-bottom: none;
                    border-top-left-radius: 3px;
                    border-top-right-radius: 3px;
                }}
                QTabBar::tab:selected {{
                    background: #2d2d2d;
                    border-color: {self.settings_manager.get("theme", {}).get("accent_color", "#3daee9")};
                }}
            """)
        else:
            # Light theme
            app.setPalette(QStyleFactory.create("Fusion").standardPalette())
            app.setStyleSheet(f"""
                QLineEdit {{
                    background-color: white;
                    color: black;
                    border: 1px solid #ccc;
                    padding: 5px;
                    font-size: {self.settings_manager.get("font_size", 12)}px;
                }}
                QLineEdit:hover {{
                    border: 1px solid #aaa;
                }}
                QTabBar::tab {{
                    background: #e0e0e0;
                    color: #000000;
                    padding: 5px 10px;
                    border: 1px solid #ccc;
                    border-bottom: none;
                    border-top-left-radius: 3px;
                    border-top-right-radius: 3px;
                }}
                QTabBar::tab:selected {{
                    background: #ffffff;
                    border-color: {self.settings_manager.get("theme", {}).get("accent_color", "#3daee9")};
                }}
            """)

    def should_use_dark_mode(self):
        """Check if system is in dark mode"""
        palette = QApplication.palette()
        return palette.window().color().lightness() < 128

    def apply_accent_color(self, color_hex):
        """Apply the selected accent color to the theme"""
        if "theme" not in self.settings_manager.settings:
            self.settings_manager.settings["theme"] = {}
        
        self.settings_manager.settings["theme"]["accent_color"] = color_hex
        self.settings_manager.save_settings()
        
        # Update the dark theme highlight color
        if "dark_theme" in self.settings_manager.settings:
            self.settings_manager.settings["dark_theme"]["highlight_color"] = color_hex
            self.settings_manager.save_settings()
        
        # Re-apply the theme
        self.apply_theme(QApplication.instance())
def main():
    # Enable High DPI scaling if available
    if hasattr(Qt, 'AA_EnableHighDpiScaling'):
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    if hasattr(Qt, 'AA_UseHighDpiPixmaps'):
        QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("Storm Browser")
    app.setApplicationVersion("12.0")
    
    # Use our dark theme browser class
    window = StormBrowserDark()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
