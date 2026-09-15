#!/usr/bin/env python3

import os
import sys
import subprocess
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, 
                            QVBoxLayout, QPushButton, QGridLayout, QLabel, QStyleFactory)
from PyQt5.QtGui import QIcon, QPalette, QColor
from PyQt5.QtCore import QSize, Qt

# ---------------------------------------------------------------------------
# Defensive helpers for installer utilities
# ---------------------------------------------------------------------------
# The welcome app is auto-started by the desktop environment via:
#   /etc/xdg/autostart/stormos-welcome.desktop
# and for liveuser via:
#   /etc/skel/.config/autostart/stormos-welcome.desktop
#
# Installer utilities must not delete or overwrite these files.
# This module provides a tiny guard that can be called by any future
# installer/edit logic that touches autostart entries.
WELCOME_DESKTOP_FILES = (
    "/etc/xdg/autostart/stormos-welcome.desktop",
    "/etc/skel/.config/autostart/stormos-welcome.desktop",
)

def file_read_text(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except OSError:
        return None

def is_welcome_autostart_file(path):
    if not path:
        return False
    return any(path == expected for expected in WELCOME_DESKTOP_FILES)

def ensure_welcome_autostart_file(path):
    """Ensure the expected welcome autostart desktop file exists and is sane.
    Returns True if the file already exists and looks correct, or if we created
    a missing/skeletal copy. Returns False on hard errors."""
    if is_welcome_autostart_file(path) and os.path.exists(path):
        content = file_read_text(path)
        if content is not None and "[Desktop Entry]" in content and "Exec=" in content:
            return True
    # If the file is missing or broken, restore a minimal sane copy.
    if path in WELCOME_DESKTOP_FILES:
        try:
            parent = os.path.dirname(path)
            os.makedirs(parent, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(
                    "[Desktop Entry]\n"
                    "Type=Application\n"
                    "Name=StormOS Welcome\n"
                    "Comment=StormOS welcome screen (first boot helper)\n"
                    "Exec=/usr/local/bin/stormos-welcome\n"
                    "Icon=stormos-welcome\n"
                    "Terminal=false\n"
                    "Categories=System;\n"
                    "X-GNOME-Autostart-enabled=true\n"
                    "X-GNOME-Autostart-Phase=Application\n"
                    "Hidden=false\n"
                    "NoDisplay=false\n"
                    "StartupNotify=false\n"
                )
            return True
        except OSError:
            return False
    return False

def safe_run_command(command):
    """Run a command but refuse to delete/overwrite welcome autostart files.
    This is defensive; normal UI actions should not generate these paths."""
    if not isinstance(command, str):
        return False
    for forbidden in WELCOME_DESKTOP_FILES:
        if command.strip().startswith("rm ") and forbidden in command:
            return False
        if command.strip().startswith("rm -f ") and forbidden in command:
            return False
        if command.strip().startswith("rm -rf ") and forbidden in command:
            return False
        if command.strip().startswith("> " + forbidden) or command.strip().startswith(">> " + forbidden):
            return False
        if f">{forbidden}" in command or f">>{forbidden}" in command:
            return False
    return True

# ---------------------------------------------------------------------------
# Installer shortcut control surface
# ---------------------------------------------------------------------------
# This module provides a documented control path for the GUI utilities to
# request installer-shortcut cleanup/removal on the installed system without
# manually editing environment variables such as
# CALAMARES_REMOVE_INSTALLER_DESKTOP=1.
#
# The intended behavior is:
#   * The live image keeps installer autostart entries disabled by default.
#   * The installed system can be configured through this UI to remove the
#     installer desktop shortcuts from /usr/share/applications/.
#   * The UI may also let the user pick which installer entries are enabled
#     in autostart, rather than relying on desktop shortcuts to launch them.
#
# Note: The actual removal on the installed system is performed by the
# postinstall flow when CALAMARES_REMOVE_INSTALLER_DESKTOP=1. This helper
# writes that flag into a small state file and/or sets the environment for
# the postinstall runner so the GUI can request the same result.
INSTALLER_STATE_FILE = "/var/lib/stormos/installer-shortcut-state.conf"

INSTALLER_SHORTCUT_DESKTOP_NAMES = [
    "stormos-installer-cli.desktop",
    "abif.desktop",
    "install-stormos-cli.desktop",
    "install-stormos-desktop.desktop",
    "install-stormos.desktop",
    "install-stormos-cli-installer.desktop",
    "install-stormos-installer.desktop",
    "stormos-installer.desktop",
]

def installer_state_dir():
    parent = os.path.dirname(INSTALLER_STATE_FILE)
    try:
        os.makedirs(parent, exist_ok=True)
    except OSError:
        return None
    return parent

def write_installer_remove_request():
    """Request installer-shortcut removal on the installed system.
    This writes a small state file that the postinstall/runner can honor.
    Returns True on success, False on failure."""
    d = installer_state_dir()
    if d is None:
        return False
    try:
        with open(INSTALLER_STATE_FILE, "w", encoding="utf-8") as f:
            f.write("REMOVE_INSTALLER_DESKTOP=1\n")
        return True
    except OSError:
        return False

def installer_remove_requested():
    """Check whether the installer-shortcut removal has been requested."""
    try:
        with open(INSTALLER_STATE_FILE, "r", encoding="utf-8") as f:
            return any(
                line.strip().lower().startswith("remove_installer_desktop")
                for line in f
            )
    except OSError:
        return False

def installer_autostart_entries_on_system(root="/"):
    """Return a list of installer-related autostart desktop entries found
    on the installed system. This can be used by a GUI picker to let the
    user choose which installer entries are enabled in autostart."""
    entries = []
    for subdir in (
        os.path.join(root, "etc", "xdg", "autostart"),
        os.path.join(root, "etc", "skel", ".config", "autostart"),
    ):
        if not os.path.isdir(subdir):
            continue
        for name in sorted(os.listdir(subdir)):
            if not name.endswith(".desktop"):
                continue
            path = os.path.join(subdir, name)
            if not os.path.isfile(path):
                continue
            try:
                content = open(path, "r", encoding="utf-8").read()
            except OSError:
                continue
            if not content:
                continue
            if not (
                "Install StormOS" in content
                or "abif" in content
                or "stormos-installer" in content
                or "install-stormos" in content
            ):
                continue
            hidden = False
            for line in content.splitlines():
                if line.startswith("Hidden="):
                    hidden = line.split("=", 1)[1].strip().lower() == "true"
                    break
            entries.append({
                "path": path,
                "name": name,
                "hidden": hidden,
            })
    return entries

def _installer_menu_entry_name_for_autostart_name(autostart_name):
    """Map an installer autostart filename to the corresponding installer
    menu entry filename in /usr/share/applications.

    This keeps the picker from requiring every possible installer shortcut
    name up front; it only maps the entries this tree actually ships."""
    if autostart_name == "abif.desktop":
        return "stormos-installer-cli.desktop"
    if autostart_name == "stormos-installer-cli.desktop":
        return "stormos-installer-cli.desktop"
    if autostart_name == "install-stormos-cli.desktop":
        return "install-stormos-cli.desktop"
    if autostart_name == "install-stormos-desktop.desktop":
        return "install-stormos-desktop.desktop"
    return None


def _installer_menu_entries_on_system(root="/"):
    """Return installer menu entries from /usr/share/applications.

    These are installer-themed desktop files that live in the system
    applications directory rather than in an autostart directory.
    """
    appdir = os.path.join(root, "usr", "share", "applications")
    if not os.path.isdir(appdir):
        return []
    entries = []
    try:
        names = sorted(os.listdir(appdir))
    except OSError:
        return []
    for name in names:
        if not name.endswith(".desktop"):
            continue
        path = os.path.join(appdir, name)
        if not os.path.isfile(path):
            continue
        try:
            content = open(path, "r", encoding="utf-8").read()
        except OSError:
            continue
        if not content:
            continue
        if not (
            "Install StormOS" in content
            or "abif" in content
            or "stormos-installer" in content
            or "install-stormos" in content
        ):
            continue
        hidden = False
        for line in content.splitlines():
            if line.startswith("Hidden="):
                hidden = line.split("=", 1)[1].strip().lower() == "true"
                break
        entries.append({
            "path": path,
            "name": name,
            "hidden": hidden,
        })
    return entries


def _installer_menu_entries_hidden(menu_entries):
    """Return a mapping from installer menu entry name to whether it is
    currently hidden."""
    out = {}
    for entry in menu_entries:
        out[entry["name"]] = entry["hidden"]
    return out


def set_installer_menu_hidden(root="/", name, hidden=True):
    """Set Hidden on an installer menu entry in /usr/share/applications.

    This is intended for the side-by-side installer picker so the user can
    hide or show the installer menu entry directly from the same place where
    they control autostart.
    """
    appdir = os.path.join(root, "usr", "share", "applications")
    path = os.path.join(appdir, name)
    if not os.path.isfile(path):
        return False
    try:
        lines = open(path, "r", encoding="utf-8").read().splitlines()
    except OSError:
        return False
    out = []
    seen_hidden = False
    changed = False
    for line in lines:
        if line.startswith("Hidden="):
            out.append(f"Hidden={'true' if hidden else 'false'}")
            seen_hidden = True
            changed = True
        else:
            out.append(line)
    if not seen_hidden:
        out.append(f"Hidden={'true' if hidden else 'false'}")
        changed = True
    if changed:
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(out) + "\n")
            return True
        except OSError:
            return False
    return False


def set_installer_autostart_hidden(root="/", name, hidden=True):
    """Set Hidden on an installer-related autostart entry.
    This is intended for a GUI picker that lets the user choose which
    installer entry should be honored in autostart."""
    subdirs = [
        os.path.join(root, "etc", "xdg", "autostart"),
        os.path.join(root, "etc", "skel", ".config", "autostart"),
        os.path.expanduser(os.path.join("~/.config", "autostart")),
    ]
    for subdir in subdirs:
        path = os.path.join(subdir, name)
        if not os.path.isfile(path):
            continue
        try:
            lines = open(path, "r", encoding="utf-8").read().splitlines()
        except OSError:
            continue
        out = []
        changed = False
        seen_hidden = False
        for line in lines:
            if line.startswith("Hidden="):
                out.append(f"Hidden={'true' if hidden else 'false'}")
                seen_hidden = True
                changed = True
            else:
                out.append(line)
        if not seen_hidden:
            out.append(f"Hidden={'true' if hidden else 'false'}")
            changed = True
        if changed:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write("\n".join(out) + "\n")
                return True
            except OSError:
                return False
    return False

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("StormOS Utilities v6.2")
        self.setGeometry(100, 100, 700, 500)
        
        # Apply Fusion style
        self.setStyle(QStyleFactory.create('Fusion'))
        
        self.create_installer_shortcuts_tab()
        
        # Apply dark mode with Fusion styling
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #2D2D30;
                color: #E0E0E0;
                font-size: 11px;
            }
            QTabWidget::pane {
                border: 1px solid #3F3F46;
                background-color: #252526;
            }
            QTabBar::tab {
                background-color: #3F3F46;
                color: #E0E0E0;
                padding: 4px 12px;
                border: 1px solid #555555;
                border-bottom: none;
                margin-right: 1px;
                min-width: 80px;
            }
            QTabBar::tab:selected {
                background-color: #007ACC;
                border-color: #007ACC;
            }
            QPushButton {
                background-color: #3F3F46;
                border: 1px solid #555555;
                color: #E0E0E0;
                padding: 4px 8px;
                border-radius: 3px;
                text-align: left;
                min-height: 24px;
            }
            QPushButton:hover {
                background-color: #505050;
                border-color: #007ACC;
            }
            QPushButton:pressed {
                background-color: #007ACC;
            }
            QGridLayout {
                spacing: 5px;
            }
            QToolTip {
                background-color: #3F3F46;
                color: #E0E0E0;
                border: 1px solid #555555;
            }
        """)
        
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(5, 5, 5, 5)
        
        # Create tab widget with tabs on top
        self.notebook = QTabWidget()
        self.notebook.setTabPosition(QTabWidget.North)
        main_layout.addWidget(self.notebook)
        
        # Create all tabs
        self.create_maintenance_tab()
        self.create_game_utilities_tab()
        self.create_printer_tab()
        self.create_arch_university_tab()
        self.create_about_us_tab()
    
    def create_button_with_icon(self, label, command, icon_name=None):
        button = QPushButton(label)
        if icon_name:
            try:
                button.setIcon(QIcon.fromTheme(icon_name))
            except:
                pass
            button.setIconSize(QSize(16, 16))
        button.clicked.connect(lambda checked, cmd=command: self.run_command(cmd))
        
        # Add tooltips for better usability
        button.setToolTip(f"Execute: {command}")
        
        return button
    
    def run_command(self, command):
        if not safe_run_command(command):
            return
        if command.startswith('xdg-open') or command.startswith('https://'):
            subprocess.Popen(command, shell=True)
        else:
            if not command.startswith('konsole') and not command.startswith('/'):
                command = f"konsole -e '{command}'"
            subprocess.Popen(command, shell=True)
    
    def create_maintenance_tab(self):
        tab = QWidget()
        layout = QGridLayout(tab)
        layout.setContentsMargins(5, 5, 5, 5)
        
        commands = [
            ("Refresh Mirrors", "sudo reflector --verbose -l 20 --sort rate --save /etc/pacman.d/mirrorlist", "view-refresh"),
            ("System Updates", "sudo pacman -Syyu --noconfirm", "system-software-update"),
            ("Aur Updates", "yay -Syyu --noconfirm", "system-software-update"),
            ("Keyring Updater", "upkeyring", "system-lock-screen"),
            ("Renew Keyring", "upsystem", "system-lock-screen"),
            ("Install Teamviewer", "tinstall", "applications-internet"),
            ("Install Lshw", "sudo pacman -S lshw --noconfirm", "applications-system"),
            ("Install i2c-tools", "sudo pacman -S i2c-tools --noconfirm", "applications-system"),
            ("Nvidia Drivers", "sudo pacman -S nvidia-dkms lib32-nvidia-utils lib32-opencl-nvidia lib32-primus_vk lib32-libvdpau cuda-tools cuda opencl-nvidia primus_vk --noconfirm", "video-display"),
            ("Nvidia-390xx", "sudo pacman -S nvidia-390xx-dkms nvidia-390xx-utils opencl-nvidia-390xx --noconfirm", "video-display")
        ]
        
        for i, (label, command, icon_name) in enumerate(commands):
            button = self.create_button_with_icon(label, command, icon_name)
            layout.addWidget(button, i, 0)
        
        self.notebook.addTab(tab, "Maintenance")
    
    def create_game_utilities_tab(self):
        tab = QWidget()
        layout = QGridLayout(tab)
        layout.setContentsMargins(5, 5, 5, 5)
        
        commands = [
            ("Steam Native", "sudo pacman -S --noconfirm steam-native-runtime gamemode", "applications-games"),
            ("Heroic Launcher", "yay -S --noconfirm heroic-games-launcher-bin gamemode", "applications-games"),
            ("Lutris Launcher", "sudo pacman -S --noconfirm lutris gamemode", "applications-games"),
            ("ProtonGE Updater", "yay -S --noconfirm proton-community-updater", "applications-games"),
            ("Mangohud/Goverlay", "yay -S --noconfirm mangohud goverlay-bin", "applications-games"),
            ("Bottles Launcher", "yay -S --noconfirm bottles", "applications-games"),
            ("Warpinator", "sudo pacman -S warpinator --noconfirm", "applications-internet"),
            ("Calculator", "sudo pacman -S gnome-calculator --noconfirm", "accessories-calculator"),
            ("Flameshot", "sudo pacman -S flameshot --noconfirm", "accessories-screenshot"),
            ("Transmission", "sudo pacman -S transmission-gtk --noconfirm", "network-workgroup"),
            ("Thunderbird", "sudo pacman -S thunderbird --noconfirm", "internet-mail"),
            ("Xed Editor", "sudo pacman -S xed --noconfirm", "accessories-text-editor"),
            ("OnlyOffice", "yay -S onlyoffice-bin --noconfirm", "applications-office"),
            ("Media Stream", "minstaller", "multimedia-video-player"),
            ("Minimize Tray", "trayinjector", "system-run")
        ]
        
        for i, (label, command, icon_name) in enumerate(commands):
            button = self.create_button_with_icon(label, command, icon_name)
            layout.addWidget(button, i, 0)
        
        self.notebook.addTab(tab, "Games/Utils")
    
    def create_printer_tab(self):
        tab = QWidget()
        layout = QGridLayout(tab)
        layout.setContentsMargins(5, 5, 5, 5)
        
        commands = [
            ("Enable Cups", "systemctl enable --now cups", "printer"),
            ("Cups Web", "xdg-open http://localhost:631", "applications-internet"),
            ("Epson Drivers", "epsoninstaller", "printer"),
            ("HP Drivers", "eom", "printer")
        ]
        
        for i, (label, command, icon_name) in enumerate(commands):
            button = self.create_button_with_icon(label, command, icon_name)
            layout.addWidget(button, i, 0)
        
        self.notebook.addTab(tab, "Printers")
    
    def create_arch_university_tab(self):
        tab = QWidget()
        layout = QGridLayout(tab)
        layout.setContentsMargins(5, 5, 5, 5)
        
        commands = [
            ("Arch Commands", '/usr/local/bin/data/commands', "utilities-terminal"),
            ("Arch Wiki", "xdg-open https://wiki.archlinux.org/", "internet-web-browser"),
            ("Arch Website", "xdg-open https://archlinux.org/", "internet-web-browser"),
            ("Pacman Guide", "xdg-open https://wiki.archlinux.org/title/Pacman", "internet-web-browser"),
            ("AUR Website", "xdg-open https://aur.archlinux.org/", "internet-web-browser"),
            ("Pacman Tutorial", "xdg-open https://www.youtube.com/watch?v=TQaHfQrwnXo", "applications-multimedia"),
            ("Advanced Pacman", "xdg-open https://www.youtube.com/watch?v=-dEuXTMzRKs", "applications-multimedia")
        ]
        
        for i, (label, command, icon_name) in enumerate(commands):
            button = self.create_button_with_icon(label, command, icon_name)
            layout.addWidget(button, i, 0)
        
        self.add_left_buttons(layout, len(commands))
        
        self.notebook.addTab(tab, "Arch University")
    
    def create_about_us_tab(self):
        tab = QWidget()
        layout = QGridLayout(tab)
        layout.setContentsMargins(5, 5, 5, 5)
        
        commands = [
            ("Discord", "sudo pacman -S discord --noconfirm", "internet-chat"),
            ("Join Us", "xdg-open https://discord.gg/stormos", "internet-web-browser"),
            ("Distrowatch", "xdg-open https://distrowatch.com/stormos", "internet-web-browser"),
            ("Gofundme", "xdg-open https://gofund.me/stormos", "internet-web-browser"),
            ("Patreon", "xdg-open https://patreon.com/stormos", "internet-web-browser"),
            ("StormOS Site", "https://stormos.org", "internet-web-browser"),
            ("ReadMe", '/usr/local/bin/data/about', "text-x-generic")
        ]
        
        for i, (label, command, icon_name) in enumerate(commands):
            button = self.create_button_with_icon(label, command, icon_name)
            layout.addWidget(button, i, 0)
        
        self.notebook.addTab(tab, "About")
        self.notebook.addTab(self.create_installer_shortcuts_tab(), "Installer Shortcuts")
    
    def create_installer_shortcuts_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(5, 5, 5, 5)
        
        intro = QLabel(
            "This tab controls installer desktop shortcuts on the installed "
            "system. It does not launch the installer directly from the desktop."
        )
        layout.addWidget(intro)
        layout.addSpacing(8)
        
        self.installer_remove_btn = QPushButton("Remove installer shortcuts from installed system")
        self.installer_remove_btn.setToolTip(
            "Requests removal of installer desktop shortcuts from /usr/share/applications/ "
            "on the installed system. This is the same request the postinstall flow honors "
            "when CALAMARES_REMOVE_INSTALLER_DESKTOP=1."
        )
        self.installer_remove_btn.clicked.connect(self.request_installer_shortcut_removal)
        layout.addWidget(self.installer_remove_btn)
        layout.addSpacing(12)
        
        picker_label = QLabel("Installer autostart picker")
        layout.addWidget(picker_label)
        layout.addSpacing(4)
        picker_note = QLabel(
            "Use this to choose which installer entry is enabled in autostart, "
            "and to show or hide the matching installer menu entry. The two sides "
            "are shown together so you can pick the installer experience from one place."
        )
        picker_note.setWordWrap(True)
        layout.addWidget(picker_note)
        layout.addSpacing(8)
        
        self.installer_picker = QGridLayout()
        layout.addLayout(self.installer_picker)
        layout.addStretch(1)
        
        self.refresh_installer_picker()
        return tab
    
    def refresh_installer_picker(self):
        while self.installer_picker.count():
            item = self.installer_picker.takeAt(0)
            if item and item.widget():
                item.widget().deleteLater()
        entries = installer_autostart_entries_on_system()
        menu_entries = self._installer_menu_entries_on_system()
        hidden_menu = self._installer_menu_entries_hidden(menu_entries)
        if not entries and not menu_entries:
            empty = QLabel("No installer desktop entries found on the system.")
            empty.setWordWrap(True)
            self.installer_picker.addWidget(empty, 0, 0)
            return
        row = 0
        # Side-by-side columns: autostart entries on the left, matching menu
        # entries on the right. Each row corresponds to one installer entry,
        # with its autostart state and its menu state shown together.
        max_rows = max(len(entries), len(menu_entries))
        for i in range(max_rows):
            if i < len(entries):
                entry = entries[i]
                name_label = QLabel(entry["name"])
                autostatus_label = QLabel("enabled in autostart" if not entry["hidden"] else "disabled in autostart")
                enable_btn = QPushButton("Enable in autostart")
                disable_btn = QPushButton("Disable in autostart")
                enable_btn.setToolTip(
                    "Set Hidden=false in %s so this installer entry launches on login."
                    % entry["path"]
                )
                disable_btn.setToolTip(
                    "Set Hidden=true in %s so this installer entry does not launch on login."
                    % entry["path"]
                )
                enable_btn.clicked.connect(
                    lambda checked, name=entry["name"]: set_installer_autostart_hidden(name=name, hidden=False)
                )
                disable_btn.clicked.connect(
                    lambda checked, name=entry["name"]: set_installer_autostart_hidden(name=name, hidden=True)
                )            self.installer_picker.addWidget(name_label, row, 0)
            self.installer_picker.addWidget(autostatus_label, row, 1)
            self.installer_picker.addWidget(enable_btn, row, 2)
            self.installer_picker.addWidget(disable_btn, row, 3)
            # If the user disabled this installer entry, also hide the matching
            # menu entry so the picker's autostart and menu sides stay aligned
            # without requiring a separate action for each.
            menu_name = _installer_menu_entry_name_for_autostart_name(entry["name"])
            if menu_name and entry["hidden"]:
                if not hidden_menu.get(menu_name, False):
                    set_installer_menu_hidden(name=menu_name, hidden=True)
                    hidden_menu[menu_name] = True
            if i < len(menu_entries):
                menu = menu_entries[i]
                menu_name_label = QLabel(menu["name"])
                menu_path_label = QLabel(menu["path"])
                menu_path_label.setToolTip(
                    "This is the matching menu entry for the installer. Enabling autostart does not remove it."
                )
                if i < len(entries):
                    menu_status_label = QLabel(
                        "menu-visible" if not hidden_menu.get(menu["name"], False) else "menu-hidden"
                    )
                    hide_menu_btn = QPushButton("Hide in menu")
                    unhide_menu_btn = QPushButton("Show in menu")
                    hide_menu_btn.clicked.connect(
                        lambda checked, name=menu["name"]: set_installer_menu_hidden(name=name, hidden=True)
                    )
                    unhide_menu_btn.clicked.connect(
                        lambda checked, name=menu["name"]: set_installer_menu_hidden(name=name, hidden=False)
                    )
                    self.installer_picker.addWidget(menu_name_label, row, 4)
                    self.installer_picker.addWidget(menu_path_label, row, 5)
                    self.installer_picker.addWidget(menu_status_label, row, 6)
                    self.installer_picker.addWidget(hide_menu_btn, row, 7)
                    self.installer_picker.addWidget(unhide_menu_btn, row, 8)
                else:
                    self.installer_picker.addWidget(menu_name_label, row, 4)
                    self.installer_picker.addWidget(menu_path_label, row, 5)
            row += 1
        # After the user disables all installer autostart entries, also hide the
        # matching menu-only installer entry so the autostart pane and the menu
        # pane stay consistent without a separate action.
        installer_names = [e["name"] for e in entries]
        if installer_names and all(
            e["hidden"] for e in entries if e["name"] in installer_names
        ):
            for entry in entries:
                menu_name = _installer_menu_entry_name_for_autostart_name(entry["name"])
                if menu_name and not hidden_menu.get(menu_name, False):
                    set_installer_menu_hidden(name=menu_name, hidden=True)
                    hidden_menu[menu_name] = True
        # Separator + note so the user understands the relationship between the
        # two sides.
        sep = QLabel("")
        sep.setFixedHeight(8)
        self.installer_picker.addWidget(sep, row, 0, 1, 9)
        row += 1
        side_by_side_note = QLabel(
            "Left side: installer autostart entries (launch on login when enabled). "
            "Right side: matching installer menu entries (appear in the app menu). "
            "Disabling all installer autostart entries also hides the matching menu "
            "entry so the two stay consistent."
        )
        side_by_side_note.setWordWrap(True)
        row += 1
        self.installer_picker.addWidget(side_by_side_note, row, 0, 1, 9)
        row += 1
        entries_uniform = (
            not entries
            or all(not e["hidden"] for e in entries)
            or all(e["hidden"] for e in entries)
        )
        if entries_uniform and menu_entries:
            self.installer_picker.addWidget(
                QLabel(
                    "Current state: installer autostart is uniformly %s. "
                    "The menu-only installer entry %s."
                    % (
                        "enabled" if (not entries or all(not e["hidden"] for e in entries)) else "disabled",
                        "is hidden to match" if all(e["hidden"] for e in entries) else "is visible to match",
                    )
                ),
                row,
                0,
                1,
                9,
            )
            row += 1
        layout = self.installer_picker.parent()
        if layout is not None:
            layout.addStretch(1)
    
    def request_installer_shortcut_removal(self):
        if write_installer_remove_request():
            self.installer_remove_btn.setEnabled(False)
            QMessageBox.information(
                self,
                "Installer shortcuts",
                "Installer shortcut removal requested. The next postinstall run "
                "will remove the installer desktop shortcuts from /usr/share/applications/."
            )
        else:
            QMessageBox.warning(
                self,
                "Installer shortcuts",
                "Could not write the installer shortcut removal request."
            )
    
    def add_left_buttons(self, layout, start_index):
        buttons = [
            ("Logout", "qdbus6 org.kde.LogoutPrompt /LogoutPrompt promptLogout", "system-log-out"),
            ("System Info", "konsole --hold -e sudo lshw -short", "system-help"),
            ("System Resources", "konsole --hold -e top", "utilities-system-monitor"),
            ("Update Utility", "utilityup", "view-refresh"),
            ("Add/Remove Software", "/usr/bin/octopi %U", "system-software-install"),
            ("Add to Tray", "alltray -H sysconfig", "utilities-terminal")
        ]
        
        for i, (label, command, icon_name) in enumerate(buttons):
            button = self.create_button_with_icon(label, command, icon_name)
            layout.addWidget(button, start_index + i, 0)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Set Fusion style
    app.setStyle(QStyleFactory.create('Fusion'))
    
    # Set dark palette for Fusion style
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(45, 45, 48))
    palette.setColor(QPalette.WindowText, QColor(224, 224, 224))
    palette.setColor(QPalette.Base, QColor(37, 37, 38))
    palette.setColor(QPalette.AlternateBase, QColor(45, 45, 48))
    palette.setColor(QPalette.ToolTipBase, QColor(0, 0, 0))
    palette.setColor(QPalette.ToolTipText, QColor(224, 224, 224))
    palette.setColor(QPalette.Text, QColor(224, 224, 224))
    palette.setColor(QPalette.Button, QColor(63, 63, 70))
    palette.setColor(QPalette.ButtonText, QColor(224, 224, 224))
    palette.setColor(QPalette.BrightText, QColor(255, 0, 0))
    palette.setColor(QPalette.Link, QColor(0, 122, 204))
    palette.setColor(QPalette.Highlight, QColor(0, 122, 204))
    palette.setColor(QPalette.HighlightedText, QColor(0, 0, 0))
    app.setPalette(palette)
    
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())