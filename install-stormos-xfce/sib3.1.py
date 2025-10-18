#!/usr/bin/env python3

import os
import sys
import subprocess
import time
import shutil
import traceback
import multiprocessing
from datetime import datetime

from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QPushButton, QCheckBox, QLabel, QSpinBox, QProgressBar, 
                            QTextEdit, QMessageBox, QGroupBox, QGridLayout, QMenu)
from PyQt5.QtCore import Qt, QProcess, pyqtSignal, QObject, QTimer, QPoint
from PyQt5.QtGui import QFont, QTextCursor, QClipboard

class TerminalProcess(QObject):
    """Handles terminal operations in a separate thread"""
    output_ready = pyqtSignal(str)
    error_ready = pyqtSignal(str)
    process_finished = pyqtSignal(int)
    
    def __init__(self):
        super().__init__()
        self.process = QProcess()
        self.process.readyReadStandardOutput.connect(self._handle_output)
        self.process.readyReadStandardError.connect(self._handle_error)
        self.process.finished.connect(self._handle_finished)
    
    def run_command(self, command, working_dir=None):
        """Execute a command in the terminal"""
        self.process.setWorkingDirectory(working_dir if working_dir else os.path.expanduser("~"))
        self.output_ready.emit(f"Executing: {command}\n")
        self.process.start("/bin/bash", ["-c", command])
    
    def _handle_output(self):
        """Handle standard output"""
        data = self.process.readAllStandardOutput().data().decode('utf-8')
        self.output_ready.emit(data)
    
    def _handle_error(self):
        """Handle standard error"""
        data = self.process.readAllStandardError().data().decode('utf-8')
        self.error_ready.emit(data)
    
    def _handle_finished(self, exit_code):
        """Handle process completion"""
        self.process_finished.emit(exit_code)
    
    def terminate(self):
        """Terminate the running process"""
        if self.process.state() == QProcess.Running:
            self.process.terminate()

class ArchIsoBuilder(QMainWindow):
    REQUIRED_PACKAGES = [
        'archiso', 'mkinitcpio-archiso',  # Changed from calamares-app to calamares-git
    ]
    GIT_REPO = "https://github.com/bfitzgit23/stormos-build-files"
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("StormOS ISO Builder v3")
        self.setMinimumSize(800, 600)
        
        # Initialize paths
        self.USER_HOME = os.path.expanduser("~")
        self.STORMOS_DIR = os.path.join(self.USER_HOME, "Desktop", "stormos-build-files", "install-stormos-xfce")
        self.OUTPUT_DIR = os.path.join(self.USER_HOME, "Desktop", "StormOS-ISO")
        self.LOCAL_PACKAGE_DIR = os.path.join(self.STORMOS_DIR, "local_packages")  # Directory containing local .zst files
        
        # State variables
        self.root_commands = []
        self.build_in_progress = False
        self.start_time = 0
        self.all_requirements_met = False
        self.build_timer = None
        self.last_output_time = 0
        self.current_progress = 0
        
        # Setup UI
        self.setup_ui()
        
        # Initialize terminal process handler
        self.terminal_process = TerminalProcess()
        self.terminal_process.output_ready.connect(self.append_terminal_text)
        self.terminal_process.error_ready.connect(self.append_terminal_text)
        self.terminal_process.process_finished.connect(self.on_process_finished)
        
        # Initialize directories
        self.ensure_directories_exist()
        
        # Check packages after UI is ready
        self.check_and_install_packages()
        
        # Enable build button only if all requirements are met
        self.update_build_button_state()

    def setup_ui(self):
        """Create and arrange the UI elements"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Terminal output
        terminal_group = QGroupBox("Terminal Output")
        terminal_layout = QVBoxLayout()
        
        self.terminal = QTextEdit()
        self.terminal.setFont(QFont("monospace", 10))
        self.terminal.setReadOnly(True)
        self.terminal.setContextMenuPolicy(Qt.CustomContextMenu)
        self.terminal.customContextMenuRequested.connect(self.show_terminal_context_menu)
        terminal_layout.addWidget(self.terminal)
        
        terminal_group.setLayout(terminal_layout)
        main_layout.addWidget(terminal_group)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        main_layout.addWidget(self.progress_bar)
        
        # Controls section
        controls_group = QGroupBox("Build Controls")
        controls_layout = QGridLayout()
        
        # Git options
        self.use_existing_checkbox = QCheckBox("Use existing git clone")
        self.use_existing_checkbox.setChecked(True)  # Default to using existing clone if available
        controls_layout.addWidget(self.use_existing_checkbox, 0, 0)
        
        self.update_git_button = QPushButton("Update Git Clone")
        self.update_git_button.clicked.connect(self.on_update_git_button_clicked)
        controls_layout.addWidget(self.update_git_button, 0, 1)
        
        # Build button
        self.build_button = QPushButton("Build ISO")
        self.build_button.clicked.connect(self.on_build_button_clicked)
        controls_layout.addWidget(self.build_button, 0, 2)
        
        # Processor selection
        controls_layout.addWidget(QLabel("Processors:"), 1, 0)
        
        cpu_count = multiprocessing.cpu_count()
        self.processor_spinbox = QSpinBox()
        self.processor_spinbox.setRange(1, cpu_count)
        self.processor_spinbox.setValue(cpu_count)
        controls_layout.addWidget(self.processor_spinbox, 1, 1)
        
        controls_group.setLayout(controls_layout)
        main_layout.addWidget(controls_group)
        
        # Status bar
        self.statusBar().showMessage("Ready")

    def show_terminal_context_menu(self, position):
        """Show context menu for terminal with copy/paste options"""
        menu = QMenu()
        copy_action = menu.addAction("Copy")
        paste_action = menu.addAction("Paste")
        
        # Get the current selection
        cursor = self.terminal.textCursor()
        has_selection = cursor.hasSelection()
        
        copy_action.setEnabled(has_selection)
        
        # Show menu and handle actions
        action = menu.exec_(self.terminal.mapToGlobal(position))
        
        if action == copy_action:
            self.terminal.copy()
        elif action == paste_action:
            self.terminal.paste()

    def append_terminal_text(self, text):
        """Append text to the terminal widget and log to a file"""
        self.terminal.moveCursor(QTextCursor.End)
        self.terminal.insertPlainText(text)
        self.terminal.ensureCursorVisible()
        
        # Update status bar with last line
        lines = text.strip().split('\n')
        if lines:
            self.statusBar().showMessage(lines[-1][:50] + "..." if len(lines[-1]) > 50 else lines[-1])
        
        # Update last output time for progress tracking
        if text.strip():
            self.last_output_time = time.time()
        
        # Log to file
        try:
            with open(os.path.join(self.USER_HOME, 'stormos_build.log'), 'a') as log_file:
                log_file.write(text)
        except Exception as e:
            print(f"Error writing to log file: {e}")

    def ensure_directories_exist(self):
        """Ensure that OUTPUT_DIR and STORMOS_DIR exist, create them if necessary"""
        self.append_terminal_text("Checking if necessary directories exist...\n")
        
        # Check and create OUTPUT_DIR if it does not exist
        if not os.path.exists(self.OUTPUT_DIR):
            self.append_terminal_text(f"Output directory {self.OUTPUT_DIR} does not exist. Creating...\n")
            os.makedirs(self.OUTPUT_DIR, exist_ok=True)
            self.append_terminal_text(f"Created output directory: {self.OUTPUT_DIR}\n")
        
        # Check and create STORMOS_DIR if it does not exist
        if not os.path.exists(self.STORMOS_DIR):
            self.append_terminal_text(f"StormOS directory {self.STORMOS_DIR} does not exist. Creating...\n")
            os.makedirs(self.STORMOS_DIR, exist_ok=True)
            self.append_terminal_text(f"Created StormOS directory: {self.STORMOS_DIR}\n")
        
        # Ensure LOCAL_PACKAGE_DIR exists
        if not os.path.exists(self.LOCAL_PACKAGE_DIR):
            self.append_terminal_text(f"Local package directory {self.LOCAL_PACKAGE_DIR} does not exist. Creating...\n")
            os.makedirs(self.LOCAL_PACKAGE_DIR, exist_ok=True)
            self.append_terminal_text(f"Created local package directory: {self.LOCAL_PACKAGE_DIR}\n")

    def check_and_install_packages(self):
        """Check if required packages are installed and collect missing ones to install later"""
        self.append_terminal_text("Checking required packages...\n")
        missing_packages = []
        
        # Check if each required package is installed
        for package in self.REQUIRED_PACKAGES:
            if not self.is_package_installed(package):
                missing_packages.append(package)
        
        # Collect missing packages to install later
        if missing_packages:
            self.install_missing_packages(missing_packages)
            self.all_requirements_met = False
        else:
            self.append_terminal_text("All required packages are already installed.\n")
            self.all_requirements_met = True

    def is_package_installed(self, package_name):
        """Check if a package is installed using pacman"""
        try:
            result = subprocess.run(['pacman', '-Qs', package_name], 
                                   capture_output=True, text=True, timeout=10)
            installed = package_name in result.stdout
            if installed:
                self.append_terminal_text(f"Package '{package_name}' is already installed.\n")
            else:
                self.append_terminal_text(f"Package '{package_name}' is NOT installed.\n")
            return installed
        except subprocess.TimeoutExpired:
            self.append_terminal_text(f"Timeout while checking package: {package_name}\n")
            return False
        except Exception as e:
            self.append_terminal_text(f"Error checking package {package_name}: {str(e)}\n")
            return False

    def install_missing_packages(self, packages):
        """Collect the command to install missing packages"""
        for package in packages:
            if package == 'calamares-git':
                # Path to the local calamares-git.zst file
                local_zst = os.path.join(self.LOCAL_PACKAGE_DIR, f"{package}.zst")
                if os.path.exists(local_zst):
                    # Install from the local .zst file
                    self.append_terminal_text(f"Installing '{package}' from local file: {local_zst}\n")
                    command = f"pacman -U '{local_zst}' --noconfirm"
                else:
                    # Attempt to install from the official repositories
                    self.append_terminal_text(f"Local package file for '{package}' not found. Attempting to install from repository.\n")
                    command = f"pacman -S --needed --noconfirm {package}"
            else:
                # Install other packages from the official repositories
                self.append_terminal_text(f"Installing package from repository: {package}\n")
                command = f"pacman -S --needed --noconfirm {package}"
            
            self.root_commands.append(command)
            self.append_terminal_text(f"Queued command: {command}\n")
        
        # Inform the user that the installation commands have been collected
        self.append_terminal_text("Missing packages have been queued for installation.\n")

    def update_build_button_state(self):
        """Enable or disable the build button based on requirements"""
        self.build_button.setEnabled(self.all_requirements_met)
        if not self.all_requirements_met:
            self.build_button.setToolTip("Build disabled: Missing required components")
            self.append_terminal_text("Build button disabled due to missing requirements.\n")
        else:
            self.build_button.setToolTip("Start building the ISO")
            self.append_terminal_text("All requirements met. Build button enabled.\n")

    def recheck_requirements(self):
        """Re-check if required packages are installed after build"""
        self.append_terminal_text("Re-checking requirements after build...\n")
        missing_packages = []
        
        # Check if each required package is installed
        for package in self.REQUIRED_PACKAGES:
            if not self.is_package_installed(package):
                missing_packages.append(package)
        
        if not missing_packages:
            self.all_requirements_met = True
            self.append_terminal_text("All required packages are now installed.\n")
        else:
            self.all_requirements_met = False
            self.append_terminal_text(f"Still missing packages: {', '.join(missing_packages)}\n")
        
        self.update_build_button_state()

    def on_update_git_button_clicked(self):
        """Handler for the 'Update Git Clone' button"""
        if self.build_in_progress:
            self.show_error_dialog("Operation in Progress", 
                                  "Cannot update Git repository while a build is in progress.")
            return
            
        self.append_terminal_text("Updating Git clone...\n")
        self.clone_or_update_git_repo(force_update=True)

    def clone_or_update_git_repo(self, force_update=False):
        """Clone or update the git repository"""
        use_existing = self.use_existing_checkbox.isChecked()
        
        # Only clone or update the repo when explicitly requested
        if not use_existing or force_update:
            repo_parent_dir = os.path.dirname(self.STORMOS_DIR)
            
            # If "Use existing" is unchecked or force_update is True, delete and re-clone the repo
            if os.path.exists(repo_parent_dir):
                self.append_terminal_text("Deleting existing repository to download a fresh copy...\n")
                try:
                    shutil.rmtree(repo_parent_dir)
                except Exception as e:
                    self.append_terminal_text(f"Error removing existing repository: {str(e)}\n")
                    return
            
            self.append_terminal_text(f"Cloning repository from {self.GIT_REPO}...\n")
            command = f"git clone --progress {self.GIT_REPO} '{repo_parent_dir}'"
            self.terminal_process.run_command(command)
        else:
            self.append_terminal_text("Using existing Git clone. No update needed.\n")

    def scan_stormos_dir(self):
        """Scan the StormOS directory for necessary files and folders"""
        self.append_terminal_text(f"Scanning {self.STORMOS_DIR} for necessary files and folders...\n")
        required_files = ["packages.x86_64", "profiledef.sh", "pacman.conf"]
        required_dirs = ["syslinux", "grub"]
        
        for required_file in required_files:
            file_path = os.path.join(self.STORMOS_DIR, required_file)
            if not os.path.exists(file_path):
                self.append_terminal_text(f"Missing: {required_file}. Creating default...\n")
                self.create_required_file(required_file)
            else:
                self.append_terminal_text(f"Found: {required_file}\n")
        
        for required_dir in required_dirs:
            dir_path = os.path.join(self.STORMOS_DIR, required_dir)
            if not os.path.exists(dir_path):
                self.append_terminal_text(f"Missing: {required_dir} directory. Creating it...\n")
                os.makedirs(dir_path, exist_ok=True)
                self.create_required_file(required_dir)
            else:
                self.append_terminal_text(f"Found: {required_dir} directory\n")

    def create_required_file(self, filename):
        """Create required files with proper directory structure"""
        try:
            if filename == "packages.x86_64":
                with open(os.path.join(self.STORMOS_DIR, "packages.x86_64"), "w") as f:
                    f.write("base\nlinux\nlinux-firmware\nsyslinux\n")
            
            elif filename == "pacman.conf":
                default_pacman_conf = "/etc/pacman.conf"
                if os.path.exists(default_pacman_conf):
                    shutil.copy(default_pacman_conf, os.path.join(self.STORMOS_DIR, "pacman.conf"))
                else:
                    self.append_terminal_text(f"Default pacman.conf not found at {default_pacman_conf}.\n")
            
            elif filename == "syslinux":
                syslinux_dir = os.path.join(self.STORMOS_DIR, "syslinux")
                os.makedirs(syslinux_dir, exist_ok=True)
                with open(os.path.join(syslinux_dir, "syslinux.cfg"), "w") as f:
                    f.write(
                        "DEFAULT linux\n"
                        "LABEL linux\n"
                        "    LINUX /boot/vmlinuz-linux\n"
                        "    INITRD /boot/initramfs-linux.img\n"
                        "    APPEND root=/dev/sda1 rw\n"
                    )
            
            elif filename == "grub":
                grub_dir = os.path.join(self.STORMOS_DIR, "grub")
                os.makedirs(grub_dir, exist_ok=True)
                with open(os.path.join(grub_dir, "grub.cfg"), "w") as f:
                    f.write(
                        "set default=0\n"
                        "set timeout=5\n\n"
                        "menuentry 'Arch Linux' {\n"
                        "    linux /boot/vmlinuz-linux root=/dev/sda1 rw\n"
                        "    initrd /boot/initramfs-linux.img\n"
                        "}\n"
                    )
            
            elif filename == "profiledef.sh":
                profiledef_path = os.path.join(self.STORMOS_DIR, "profiledef.sh")
                with open(profiledef_path, "w") as f:
                    f.write(
                        "#!/bin/bash\n"
                        "iso_name=\"stormos\"\n"
                        "iso_label=\"STORMOS_$(date +%Y%m)\"\n"
                        "iso_version=\"$(date +%Y.%m.%d)\"\n"
                    )
                os.chmod(profiledef_path, 0o755)
            
            self.append_terminal_text(f"Created required file: {filename}\n")
        
        except Exception as e:
            self.append_terminal_text(f"Error creating file {filename}: {str(e)}\n")

    def generate_generic_calamares_config(self):
        """Generate a generic Calamares configuration"""
        self.append_terminal_text("Generating generic Calamares configuration...\n")
        
        generic_config = """
---
# Calamares Generic Config
modules:
  - welcome
  - locale
  - keyboard
  - partition
  - users
  - summary
  - finished
"""
        calamares_dir = os.path.join(self.STORMOS_DIR, 'calamares')
        os.makedirs(calamares_dir, exist_ok=True)
        
        try:
            with open(os.path.join(calamares_dir, 'settings.conf'), 'w') as f:
                f.write(generic_config)
            self.append_terminal_text("Generic Calamares configuration generated successfully.\n")
        except Exception as e:
            self.append_terminal_text(f"Error generating Calamares config: {str(e)}\n")

    def on_build_button_clicked(self):
        """Handler for the 'Build ISO' button"""
        if not self.all_requirements_met:
            self.show_error_dialog("Missing Requirements", 
                                  "Cannot start build. Missing required components. Please check the terminal output for details.")
            return
            
        if self.build_in_progress:
            reply = QMessageBox.question(self, "Build in Progress", 
                                       "A build is already in progress. Do you want to cancel it?",
                                       QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.terminal_process.terminate()
                self.build_in_progress = False
                self.append_terminal_text("Build process cancelled by user.\n")
                self.progress_bar.setValue(0)
                if self.build_timer:
                    self.build_timer.stop()
            return
        
        self.append_terminal_text("Starting ISO build...\n")
        self.build_in_progress = True
        self.start_time = time.time()
        self.last_output_time = time.time()
        self.current_progress = 0
        self.build_iso()
        
        # Start a timer to monitor progress
        self.build_timer = QTimer(self)
        self.build_timer.timeout.connect(self.monitor_build_progress)
        self.build_timer.start(1000)  # Check every second for more responsive updates

    def monitor_build_progress(self):
        """Monitor the build progress and update the progress bar"""
        if not self.build_in_progress:
            if self.build_timer:
                self.build_timer.stop()
            return
            
        # Check if the process is still running
        if self.terminal_process.process.state() == QProcess.Running:
            # Update progress bar based on time elapsed and output activity
            current_time = time.time()
            elapsed = current_time - self.start_time
            
            # Base progress on time (max 30 minutes)
            time_progress = min(90, int((elapsed / 1800) * 100))
            
            # Increase progress if we've had recent output
            if current_time - self.last_output_time < 5:  # Had output in the last 5 seconds
                self.current_progress = min(95, self.current_progress + 1)
            else:
                # If no output for a while, show a pulsing effect to indicate activity
                pulse = int((current_time % 4) * 25)  # Pulse every 4 seconds
                self.current_progress = max(time_progress, pulse)
            
            self.progress_bar.setValue(self.current_progress)
            
            # Check if we haven't received any output in the last 60 seconds
            if current_time - self.last_output_time > 60:
                self.append_terminal_text("Build process seems to be taking longer than expected. This is normal for large builds.\n")
        else:
            # Process has finished
            if self.build_timer:
                self.build_timer.stop()

    def clean_up_previous_build(self):
        """Clean up previous build files"""
        self.append_terminal_text("Cleaning up previous build files...\n")
        
        work_dir = os.path.join(self.OUTPUT_DIR, 'work')
        if os.path.exists(work_dir):
            command = f"rm -rf '{work_dir}'"
            self.root_commands.append(command)
            self.append_terminal_text(f"Queued removal of work directory: {work_dir}\n")
        
        if os.path.exists(self.OUTPUT_DIR):
            for file_name in os.listdir(self.OUTPUT_DIR):
                if file_name.endswith('.iso'):
                    file_path = os.path.join(self.OUTPUT_DIR, file_name)
                    command = f"rm -f '{file_path}'"
                    self.root_commands.append(command)
                    self.append_terminal_text(f"Queued removal of old ISO file: {file_path}\n")

    def build_iso(self):
        """Build the ISO image"""
        try:
            self.progress_bar.setValue(0)
            
            self.clean_up_previous_build()
            self.scan_stormos_dir()
            
            self.append_terminal_text("Starting mkarchiso build process...\n")
            self.append_terminal_text("This may take a while depending on your system performance...\n")
            
            # Ensure work directory exists before starting mkarchiso
            work_dir = os.path.join(self.OUTPUT_DIR, 'work')
            os.makedirs(work_dir, exist_ok=True)  # Create the work directory if it doesn't exist
            
            # Get the number of processors from the spin box
            processors = int(self.processor_spinbox.value())
            self.append_terminal_text(f"Using {processors} processor(s) for the build process.\n")
            
            # Generate the CPU list for taskset
            cpu_list = ",".join(map(str, range(processors)))
            self.append_terminal_text(f"CPU Affinity set to CPUs: {cpu_list}\n")
            
            # Use multi-threading for mksquashfs
            mksquashfs_options = f"-processors {processors}"
            mkarchiso_command = (
                f"export MKSQUASHFS_OPTIONS='{mksquashfs_options}'; "
                f"taskset -c {cpu_list} mkarchiso -v -w '{work_dir}' "
                f"-o '{self.OUTPUT_DIR}' '{self.STORMOS_DIR}'"
            )
            self.root_commands.append(mkarchiso_command)
            self.append_terminal_text(f"Queued build command: {mkarchiso_command}\n")
            
            # Now write all root commands to a script with verification
            script_path = os.path.join(self.USER_HOME, 'build.sh')
            with open(script_path, 'w') as script_file:
                script_file.write('#!/bin/bash\n')
                script_file.write('set -e\n')  # Exit immediately if a command exits with a non-zero status
                script_file.write('set -x\n')  # Print commands as they are executed
                for cmd in self.root_commands:
                    script_file.write(f"{cmd}\n")
                    # Extract the package name for verification
                    if 'pacman -U' in cmd:
                        package_name = cmd.split("'")[1].replace('.zst', '')
                    elif 'pacman -S' in cmd:
                        package_name = cmd.split()[-1]
                    else:
                        package_name = None
                    if package_name:
                        # Add verification step after installation
                        script_file.write(f"pacman -Qs {package_name} > /dev/null || {{ echo \"Error: Package '{package_name}' failed to install.\"; exit 1; }}\n")
            os.chmod(script_path, 0o755)
            self.append_terminal_text(f"Build script created at: {script_path}\n")
            
            # Now run pkexec bash script.sh in the terminal
            command = f"pkexec bash '{script_path}'"
            self.append_terminal_text(f"Executing build script with command: {command}\n")
            self.terminal_process.run_command(command)
            
            # Clear root_commands for next time
            self.root_commands.clear()
        
        except Exception as e:
            error_message = traceback.format_exc()
            self.append_terminal_text(f"An unexpected error occurred: {error_message}\n")
            self.show_error_dialog("Unexpected Error", error_message)
            self.build_in_progress = False
            if self.build_timer:
                self.build_timer.stop()

    def on_process_finished(self, exit_code):
        """Called when a process in the terminal has completed"""
        if not self.build_in_progress:
            return
            
        self.append_terminal_text(f"Process completed with exit code: {exit_code}\n")
        
        # Stop the progress monitoring timer
        if self.build_timer:
            self.build_timer.stop()
        
        # End the timer
        end_time = time.time()
        
        if exit_code == 0:
            self.append_terminal_text("Build process completed successfully.\n")
            iso_files = [f for f in os.listdir(self.OUTPUT_DIR) if f.endswith('.iso')]
            if iso_files:
                iso_path = os.path.join(self.OUTPUT_DIR, iso_files[0])
                self.append_terminal_text(f"ISO build completed successfully. ISO located at: {iso_path}\n")
                self.progress_bar.setValue(100)
            else:
                self.append_terminal_text("Build completed, but no ISO file found.\n")
                self.progress_bar.setValue(0)
            
            # Re-check requirements after successful build
            self.recheck_requirements()
        else:
            self.append_terminal_text("Build process failed due to package installation errors.\n")
            self.append_terminal_text("Please check the terminal output for details.\n")
            self.show_error_dialog("Build Failed", "One or more packages failed to install. Please check the terminal output for details.")
            self.progress_bar.setValue(0)
        
        # Calculate and display the total build time
        total_time = end_time - self.start_time
        minutes, seconds = divmod(total_time, 60)
        self.append_terminal_text(f"Total build time: {int(minutes)} minutes and {int(seconds)} seconds.\n")
        
        self.build_in_progress = False

    def show_error_dialog(self, title, message):
        """Show an error dialog to alert the user of an issue"""
        QMessageBox.critical(self, title, message)

    def closeEvent(self, event):
        """Handle application close event"""
        if self.build_in_progress:
            reply = QMessageBox.question(self, "Build in Progress", 
                                       "A build is in progress. Are you sure you want to quit?",
                                       QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.No:
                event.ignore()
                return
            else:
                self.terminal_process.terminate()
                if self.build_timer:
                    self.build_timer.stop()
        
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Modern look
    
    window = ArchIsoBuilder()
    window.show()
    
    sys.exit(app.exec_())