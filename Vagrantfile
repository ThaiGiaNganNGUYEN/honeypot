# Lab VM for the honeypot. NAT port forwards are bound to localhost on the host.
Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"
  config.vm.hostname = "honeypot-lab"
  config.vm.network "private_network", ip: "192.168.56.20"
  config.vm.network "forwarded_port", guest: 2222, host: 2222, host_ip: "127.0.0.1"
  config.vm.network "forwarded_port", guest: 8080, host: 8080, host_ip: "127.0.0.1"
  config.vm.network "forwarded_port", guest: 2121, host: 2121, host_ip: "127.0.0.1"
  config.vm.network "forwarded_port", guest: 8090, host: 8090, host_ip: "127.0.0.1"

  config.vm.provider "virtualbox" do |vb|
    vb.name = "honeypot-lab"
    vb.memory = "1024"
    vb.cpus = 1
  end

  config.vm.provision "shell", path: "deploy/provision.sh"
end
