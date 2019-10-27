# -*- mode: ruby -*-
# vi: set ft=ruby :

$INSTALL_BASE = <<SCRIPT
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get -y upgrade
  apt-get -y install build-essential vim-nox emacs
  apt-get -y install git python-dev python-setuptools flex bison traceroute libbz2-dev libssl-dev
  apt-get -y install mininet expect
  apt-get -y install xauth
  apt-get -y install libzeroc-ice35-dev libboost-all-dev

  easy_install pip

  rm -Rf /opt/pox
  mkdir -p /opt/pox
  # Install POX controller
  git clone -b eel https://github.com/noxrepo/pox /opt/pox

  # Install packet redirector to simpler router and run it as a service
  pip install ucla-cs118
  cp /vagrant/pox.service /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable pox.service
  systemctl start pox.service
SCRIPT

Vagrant.configure(2) do |config|
  config.vm.box = "bento/ubuntu-16.04"

  config.vm.provider "virtualbox" do |vb|
  #   # Display the VirtualBox GUI when booting the machine
  #   vb.gui = true
  #
    # Customize the amount of memory on the VM:
    vb.memory = "1024"
  end

  config.vm.provision "shell", privileged: true, inline: $INSTALL_BASE
end


