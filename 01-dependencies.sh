## 01-dependencies.sh

sudo pacman -S archiso --noconfirm
sudo pacman -S qemu-full --noconfirm
sudo pacman -S libvirt --noconfirm
sudo pacman -S virt-manager --noconfirm
sudo systemctl enable libvirtd
sudo systemctl start libvirtd
