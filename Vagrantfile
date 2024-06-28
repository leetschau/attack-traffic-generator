Vagrant.configure("2") do |config|
  config.vm.define "attacker", primary: true do |attacker|
    attacker.vm.box = "kali2024"
    attacker.vm.network "private_network", ip: "192.168.56.33"
    attacker.vm.provision "team-server", type: "shell", path: "attacker_provision.sh", privileged: false
  end

  config.vm.define "victim" do |victim|
    victim.vm.box = "ubuntu/trusty64"
    victim.vm.network "private_network", ip: "192.168.56.44"
    victim.vm.provision "beacon", type: "shell", path: "victim_provision.sh", privileged: false
  end
end
