#!/usr/bin/env python3
import gi
gi.require_version('Gtk', '3.0')
gi.require_version('Gdk', '3.0')
from gi.repository import Gtk, GObject, GLib, Gdk

import os
import sys
import json
import subprocess
import threading
import time

# --- Check for root ---
if os.geteuid() != 0:
    print("This installer must be run as root.")
    sys.exit(1)

class ArchInstaller(Gtk.Window):
    def __init__(self):
        super().__init__(title="Simple Arch Linux Installer")
        self.set_default_size(800, 600)
        self.set_border_width(10)
        self.set_position(Gtk.WindowPosition.CENTER)

        # Main layout
        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.SLIDE_LEFT_RIGHT)
        self.stack.set_transition_duration(300)

        # Pages
        self.create_welcome_page()
        self.create_disk_page()
        self.create_user_page()
        self.create_progress_page()
        self.create_completion_page()

        # Navigation buttons
        self.back_button = Gtk.Button(label="Back")
        self.back_button.connect("clicked", self.on_back_clicked)
        self.next_button = Gtk.Button(label="Next")
        self.next_button.connect("clicked", self.on_next_clicked)
        self.quit_button = Gtk.Button(label="Quit")
        self.quit_button.connect("clicked", self.on_quit_clicked)
        self.quit_button.get_style_context().add_class("destructive-action")

        button_box = Gtk.HBox(spacing=10)
        button_box.pack_start(self.quit_button, False, False, 0)
        button_box.pack_end(self.next_button, False, False, 0)
        button_box.pack_end(self.back_button, False, False, 0)

        main_vbox = Gtk.VBox(spacing=10)
        main_vbox.pack_start(self.stack, True, True, 0)
        main_vbox.pack_end(button_box, False, False, 0)
        self.add(main_vbox)

        # Data store
        self.install_data = {
            "disk": None,
            "hostname": "archlinux",
            "username": "",
            "password": "",
            "locale": "en_US.UTF-8",
            "timezone": "UTC",
            "desktop_env": "none",
            "root_password": ""
        }

        # Initialize UI state
        self.update_button_state()

        # Connect destroy signal
        self.connect("destroy", Gtk.main_quit)

    # --- UI Creation Methods ---
    def create_welcome_page(self):
        vbox = Gtk.VBox(spacing=10)
        vbox.set_halign(Gtk.Align.CENTER)
        vbox.set_valign(Gtk.Align.CENTER)
        label = Gtk.Label(label="<b>Welcome to the Simple Arch Linux Installer!</b>")
        label.set_use_markup(True)
        label.set_line_wrap(True)
        description = Gtk.Label(label=(
            "This wizard will guide you through installing Arch Linux.\n"
            "Please ensure you have read the Arch Linux installation guide and "
            "backed up any important data, as this process will erase the selected disk."
        ))
        description.set_line_wrap(True)
        vbox.pack_start(label, False, False, 0)
        vbox.pack_start(description, False, False, 15)
        self.stack.add_named(vbox, "welcome", "Welcome")

    def create_disk_page(self):
        vbox = Gtk.VBox(spacing=10)
        vbox.set_halign(Gtk.Align.CENTER)
        vbox.set_valign(Gtk.Align.CENTER)
        label = Gtk.Label(label="<b>Disk Selection and Partitioning</b>")
        label.set_use_markup(True)
        self.disk_combo = Gtk.ComboBoxText()
        self.populate_disk_combo()
        self.partition_options_label = Gtk.Label(label="Choose Partitioning Option:")
        self.partition_options_combo = Gtk.ComboBoxText()
        self.partition_options_combo.append_text("auto_efi_root", "Automatic (EFI + Root) - Erases Disk")
        self.partition_options_combo.append_text("manual", "Manual Partitioning (Advanced - Not Implemented)")
        self.partition_options_combo.set_active_id("auto_efi_root")
        vbox.pack_start(label, False, False, 0)
        vbox.pack_start(self.disk_combo, False, False, 0)
        vbox.pack_start(self.partition_options_label, False, False, 0)
        vbox.pack_start(self.partition_options_combo, False, False, 0)
        self.stack.add_named(vbox, "disk_select", "Disk Setup")

    def populate_disk_combo(self):
        self.disk_combo.remove_all()
        try:
            result = subprocess.run(["lsblk", "-J", "-o", "NAME,SIZE,TYPE,MOUNTPOINT"], capture_output=True, text=True, check=True)
            data = json.loads(result.stdout)
            self.disk_combo.append_text("select_disk", "--- Select a Disk ---")
            for dev in data.get("blockdevices", []):
                if dev.get("type") == "disk":
                    name = dev.get("name")
                    size = dev.get("size")
                    display_size = self._format_size(size)
                    self.disk_combo.append_text(f"/dev/{name}", f"/dev/{name} ({display_size})")
            self.disk_combo.set_active_id("select_disk")
        except Exception as e:
            self.disk_combo.append_text("error", "Error loading disks.")
            print(f"Disk load error: {e}")

    def _format_size(self, size_str):
        try:
            bytes_val = int(size_str)
            units = ['B', 'KB', 'MB', 'GB', 'TB']
            index = 0
            while bytes_val >= 1024 and index < len(units) - 1:
                bytes_val /= 1024
                index += 1
            return f"{bytes_val:.1f}{units[index]}"
        except ValueError:
            return size_str

    def create_user_page(self):
        vbox = Gtk.VBox(spacing=10)
        vbox.set_halign(Gtk.Align.CENTER)
        vbox.set_valign(Gtk.Align.CENTER)
        label = Gtk.Label(label="<b>User Account Configuration</b>")
        label.set_use_markup(True)
        grid = Gtk.Grid()
        grid.set_row_spacing(5)
        grid.set_column_spacing(10)
        grid.set_halign(Gtk.Align.CENTER)
        row = 0

        grid.attach(Gtk.Label(label="Hostname:"), 0, row, 1, 1)
        self.hostname_entry = Gtk.Entry()
        self.hostname_entry.set_text(self.install_data["hostname"])
        grid.attach(self.hostname_entry, 1, row, 1, 1)
        row += 1

        grid.attach(Gtk.Label(label="Root Password:"), 0, row, 1, 1)
        self.root_password_entry = Gtk.Entry()
        self.root_password_entry.set_visibility(False)
        grid.attach(self.root_password_entry, 1, row, 1, 1)
        row += 1

        grid.attach(Gtk.Label(label="Confirm Root Password:"), 0, row, 1, 1)
        self.root_password_confirm_entry = Gtk.Entry()
        self.root_password_confirm_entry.set_visibility(False)
        grid.attach(self.root_password_confirm_entry, 1, row, 1, 1)
        row += 1

        grid.attach(Gtk.Label(label="Username:"), 0, row, 1, 1)
        self.username_entry = Gtk.Entry()
        grid.attach(self.username_entry, 1, row, 1, 1)
        row += 1

        grid.attach(Gtk.Label(label="User Password:"), 0, row, 1, 1)
        self.user_password_entry = Gtk.Entry()
        self.user_password_entry.set_visibility(False)
        grid.attach(self.user_password_entry, 1, row, 1, 1)
        row += 1

        grid.attach(Gtk.Label(label="Confirm User Password:"), 0, row, 1, 1)
        self.user_password_confirm_entry = Gtk.Entry()
        self.user_password_confirm_entry.set_visibility(False)
        grid.attach(self.user_password_confirm_entry, 1, row, 1, 1)
        row += 1

        grid.attach(Gtk.Label(label="Desktop Environment:"), 0, row, 1, 1)
        self.de_combo = Gtk.ComboBoxText()
        self.de_combo.append_text("none", "None (CLI only)")
        self.de_combo.append_text("gnome", "GNOME")
        self.de_combo.append_text("kde", "KDE Plasma")
        self.de_combo.append_text("xfce", "XFCE")
        self.de_combo.set_active_id("none")
        grid.attach(self.de_combo, 1, row, 1, 1)
        row += 1

        grid.attach(Gtk.Label(label="Locale:"), 0, row, 1, 1)
        self.locale_entry = Gtk.Entry()
        self.locale_entry.set_text(self.install_data["locale"])
        grid.attach(self.locale_entry, 1, row, 1, 1)
        row += 1

        grid.attach(Gtk.Label(label="Timezone:"), 0, row, 1, 1)
        self.timezone_entry = Gtk.Entry()
        self.timezone_entry.set_text(self.install_data["timezone"])
        grid.attach(self.timezone_entry, 1, row, 1, 1)
        row += 1

        vbox.pack_start(label, False, False, 0)
        vbox.pack_start(grid, False, False, 0)
        self.stack.add_named(vbox, "user_create", "User Setup")

    def create_progress_page(self):
        vbox = Gtk.VBox(spacing=10)
        vbox.set_halign(Gtk.Align.CENTER)
        vbox.set_valign(Gtk.Align.CENTER)
        label = Gtk.Label(label="<b>Installation Progress</b>")
        label.set_use_markup(True)
        self.progress_bar = Gtk.ProgressBar()
        self.progress_bar.set_text("Waiting to start...")
        self.progress_bar.set_show_text(True)
        self.progress_bar.set_fraction(0.0)
        self.log_buffer = Gtk.TextBuffer()
        self.log_view = Gtk.TextView(buffer=self.log_buffer)
        self.log_view.set_editable(False)
        self.log_view.set_wrap_mode(Gtk.WrapMode.WORD)
        scrolled_window = Gtk.ScrolledWindow()
        scrolled_window.set_hexpand(True)
        scrolled_window.set_vexpand(True)
        scrolled_window.add(self.log_view)
        self.start_install_button = Gtk.Button(label="Start Installation")
        self.start_install_button.connect("clicked", self.on_start_install_clicked)
        self.start_install_button.get_style_context().add_class("suggested-action")
        vbox.pack_start(label, False, False, 0)
        vbox.pack_start(self.progress_bar, False, False, 0)
        vbox.pack_start(self.start_install_button, False, False, 0)
        vbox.pack_start(scrolled_window, True, True, 0)
        self.stack.add_named(vbox, "progress", "Install")

    def create_completion_page(self):
        vbox = Gtk.VBox(spacing=10)
        vbox.set_halign(Gtk.Align.CENTER)
        vbox.set_valign(Gtk.Align.CENTER)
        label = Gtk.Label(label="<b>Installation Complete!</b>")
        label.set_use_markup(True)
        message = Gtk.Label(label=(
            "Arch Linux has been successfully installed.\n"
            "You can now reboot your system."
        ))
        message.set_line_wrap(True)
        reboot_button = Gtk.Button(label="Reboot Now")
        reboot_button.connect("clicked", self.on_reboot_clicked)
        reboot_button.get_style_context().add_class("destructive-action")
        vbox.pack_start(label, False, False, 0)
        vbox.pack_start(message, False, False, 15)
        vbox.pack_start(reboot_button, False, False, 0)
        self.stack.add_named(vbox, "completion", "Finished")

    # --- Button Logic ---
    def update_button_state(self):
        current_page_name = self.stack.get_visible_child_name()
        self.back_button.set_sensitive(current_page_name != "welcome")
        self.next_button.set_sensitive(not (current_page_name in ["progress", "completion"]))
        self.start_install_button.set_sensitive(current_page_name == "progress")

    def on_back_clicked(self, widget):
        names = [self.stack.get_child_name(c) for c in self.stack.get_children()]
        current_idx = self.stack.get_visible_child_name()
        idx = names.index(current_idx)
        if idx > 0:
            self.stack.set_visible_child_name(names[idx - 1])
        self.update_button_state()

    def on_next_clicked(self, widget):
        current_idx = self.stack.get_visible_child_name()
        if current_idx == "disk_select":
            selected_disk_id = self.disk_combo.get_active_id()
            if not selected_disk_id or selected_disk_id == "select_disk":
                self.show_message_dialog("Error", "Please select a valid disk.", Gtk.MessageType.ERROR)
                return
            self.install_data["disk"] = selected_disk_id
        elif current_idx == "user_create":
            self.install_data["hostname"] = self.hostname_entry.get_text().strip()
            self.install_data["root_password"] = self.root_password_entry.get_text()
            root_pass_conf = self.root_password_confirm_entry.get_text()
            self.install_data["username"] = self.username_entry.get_text().strip()
            self.install_data["user_password"] = self.user_password_entry.get_text()
            user_pass_conf = self.user_password_confirm_entry.get_text()
            self.install_data["desktop_env"] = self.de_combo.get_active_id()
            self.install_data["locale"] = self.locale_entry.get_text().strip()
            self.install_data["timezone"] = self.timezone_entry.get_text().strip()

            if not self.install_data["hostname"]:
                self.show_message_dialog("Error", "Hostname cannot be empty.", Gtk.MessageType.ERROR)
                return
            if not self.install_data["root_password"] or self.install_data["root_password"] != root_pass_conf:
                self.show_message_dialog("Error", "Root passwords do not match.", Gtk.MessageType.ERROR)
                return
            if not self.install_data["username"]:
                self.show_message_dialog("Error", "Username cannot be empty.", Gtk.MessageType.ERROR)
                return
            if not self.install_data["user_password"] or self.install_data["user_password"] != user_pass_conf:
                self.show_message_dialog("Error", "User passwords do not match.", Gtk.MessageType.ERROR)
                return

        names = [self.stack.get_child_name(c) for c in self.stack.get_children()]
        current_idx = self.stack.get_visible_child_name()
        idx = names.index(current_idx)
        if idx < len(names) - 1:
            self.stack.set_visible_child_name(names[idx + 1])
        self.update_button_state()

    def on_quit_clicked(self, widget):
        self.show_message_dialog("Quit Installer", "Are you sure you want to quit?", Gtk.MessageType.QUESTION, self.do_quit)

    def do_quit(self, dialog, response_id):
        dialog.destroy()
        if response_id == Gtk.ResponseType.OK:
            Gtk.main_quit()

    def on_reboot_clicked(self, widget):
        self.show_message_dialog("Reboot System", "Do you want to reboot now?", Gtk.MessageType.QUESTION, self.do_reboot)

    def do_reboot(self, dialog, response_id):
        dialog.destroy()
        if response_id == Gtk.ResponseType.OK:
            self.append_log("Attempting to reboot the system...")
            try:
                subprocess.run(["sudo", "reboot"], check=True)
            except Exception as e:
                self.append_log(f"Failed to reboot: {e}")
                self.show_message_dialog("Reboot Failed", str(e), Gtk.MessageType.ERROR)
            Gtk.main_quit()

    def show_message_dialog(self, title, message, message_type, callback=None):
        dialog = Gtk.MessageDialog(
            parent=self,
            flags=Gtk.DialogFlags.MODAL,
            type=message_type,
            buttons=Gtk.ButtonsType.OK_CANCEL if message_type == Gtk.MessageType.QUESTION else Gtk.ButtonsType.OK,
            message_format=message
        )
        dialog.set_title(title)
        dialog.set_markup(f"<b>{message}</b>")
        if callback:
            dialog.connect("response", callback)
        dialog.show_all()

    def append_log(self, text):
        def append_to_buffer():
            end_iter = self.log_buffer.get_end_iter()
            self.log_buffer.insert(end_iter, text + "\n")
            self.log_view.scroll_to_mark(self.log_buffer.get_insert(), 0.0, False, 0.0, 0.0)
            return False
        GLib.idle_add(append_to_buffer)

    def update_progress(self, fraction, text):
        def update_gui():
            self.progress_bar.set_fraction(fraction)
            self.progress_bar.set_text(text)
            return False
        GLib.idle_add(update_gui)

    def on_start_install_clicked(self, widget):
        self.start_install_button.set_sensitive(False)
        self.back_button.set_sensitive(False)
        self.next_button.set_sensitive(False)
        self.quit_button.set_sensitive(False)
        self.append_log("Starting installation process...")
        thread = threading.Thread(target=self._run_installation)
        thread.start()

    def _run_installation(self):
        disk = self.install_data["disk"]
        hostname = self.install_data["hostname"]
        root_password = self.install_data["root_password"]
        username = self.install_data["username"]
        user_password = self.install_data["user_password"]
        desktop_env = self.install_data["desktop_env"]
        locale = self.install_data["locale"]
        timezone = self.install_data["timezone"]
        partition_option = self.partition_options_combo.get_active_id()

        # Phase 1: Disk Setup
        self.update_progress(0.1, "1/6: Setting up disk and partitioning...")
        self.append_log(f"Selected disk: {disk}")
        self.append_log(f"Partitioning option: {partition_option}")
        try:
            if partition_option == "auto_efi_root":
                confirm = self.confirm_action("Disk Wipe Warning", f"This will ERASE all data on {disk}. Continue?")
                if not confirm:
                    raise Exception("User canceled installation.")

                self.append_log(f"Wiping partitions on {disk}...")
                subprocess.run(["sgdisk", "-Z", disk], check=True)
                subprocess.run(["sgdisk", "-o", disk], check=True)
                self.append_log("Creating EFI partition...")
                subprocess.run(["sgdisk", "-n", "1:0:+512MiB", "-t", "1:ef00", "-c", "1:EFI System Partition", disk], check=True)
                self.append_log("Creating root partition...")
                subprocess.run(["sgdisk", "-n", "2:0:0", "-t", "2:8300", "-c", "2:Linux Root", disk], check=True)
                self.append_log("Formatting partitions...")
                subprocess.run(["mkfs.fat", "-F32", f"{disk}1"], check=True)
                subprocess.run(["mkfs.ext4", f"{disk}2"], check=True)
                self.append_log("Mounting partitions...")
                os.makedirs("/mnt/boot/efi", exist_ok=True)
                subprocess.run(["mount", f"{disk}2", "/mnt"], check=True)
                subprocess.run(["mount", f"{disk}1", "/mnt/boot/efi"], check=True)
        except subprocess.CalledProcessError as e:
            self.append_log(f"Partitioning failed: {e}")
            self.show_message_dialog("Installation Error", f"Disk setup failed: {e}", Gtk.MessageType.ERROR)
            self.reset_installer_state()
            return

        # Phase 2: Base Install
        self.update_progress(0.3, "2/6: Installing base system...")
        try:
            self.append_log("Installing base packages...")
            subprocess.run(["pacstrap", "/mnt", "base", "linux", "linux-firmware", "grub", "efibootmgr", "networkmanager"], check=True)
        except subprocess.CalledProcessError as e:
            self.append_log(f"Pacstrap failed: {e}")
            self.show_message_dialog("Installation Error", f"Base install failed: {e}", Gtk.MessageType.ERROR)
            self.reset_installer_state()
            return

        # Phase 3: Chroot Setup
        self.update_progress(0.6, "3/6: Configuring system...")
        chroot_script = f"""
        echo "Setting locale..."
        echo "{locale} UTF-8" >> /etc/locale.gen && locale-gen
        echo "LANG={locale}" > /etc/locale.conf
        echo "Setting hostname..."
        echo "{hostname}" > /etc/hostname
        ln -sf /usr/share/zoneinfo/{timezone} /etc/localtime
        hwclock --systohc
        echo "Setting root password..."
        echo "root:{root_password}" | chpasswd
        useradd -m -g users -G wheel {username}
        echo "{username}:{user_password}" | chpasswd
        echo "Installing GRUB..."
        grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=GRUB
        grub-mkconfig -o /boot/grub/grub.cfg
        systemctl enable NetworkManager
        echo "Cleaning up..."
        rm -f /root/install.sh
        """
        script_path = "/mnt/root/install.sh"
        with open(script_path, "w") as f:
            f.write(chroot_script)
        os.chmod(script_path, 0o755)
        try:
            subprocess.run(["arch-chroot", "/mnt", "/root/install.sh"], check=True)
        except subprocess.CalledProcessError as e:
            self.append_log(f"Chroot failed: {e}")
            self.show_message_dialog("Installation Error", f"Chroot setup failed: {e}", Gtk.MessageType.ERROR)
            self.reset_installer_state()
            return

        # Phase 4: Cleanup
        self.update_progress(0.9, "4/6: Unmounting filesystems...")
        try:
            subprocess.run(["umount", "-R", "/mnt"], check=True)
        except subprocess.CalledProcessError as e:
            self.append_log(f"Unmount warning: {e}")

        self.update_progress(1.0, "Installation Complete!")
        self.append_log("Installation complete.")
        GLib.idle_add(lambda: self.stack.set_visible_child_name("completion"))
        GLib.idle_add(self.update_button_state)

    def reset_installer_state(self):
        GLib.idle_add(lambda: self.start_install_button.set_sensitive(True))
        GLib.idle_add(lambda: self.next_button.set_sensitive(True))
        GLib.idle_add(lambda: self.back_button.set_sensitive(True))
        GLib.idle_add(lambda: self.quit_button.set_sensitive(True))

    def confirm_action(self, title, message):
        dialog = Gtk.MessageDialog(parent=self, flags=Gtk.DialogFlags.MODAL,
                                   type=Gtk.MessageType.WARNING,
                                   buttons=Gtk.ButtonsType.OK_CANCEL,
                                   message_format=message)
        dialog.set_title(title)
        response = dialog.run()
        dialog.destroy()
        return response == Gtk.ResponseType.OK

if __name__ == '__main__':
    css_provider = Gtk.CssProvider()
    css_path = "/usr/share/arch-installer/style.css"
    if os.path.exists(css_path):
        try:
            css_provider.load_from_path(css_path)
            Gtk.StyleContext.add_provider_for_screen(Gdk.Screen.get_default(),
                                                    css_provider,
                                                    Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        except Exception as e:
            print(f"CSS load error: {e}")
    win = ArchInstaller()
    win.show_all()
    Gtk.main()