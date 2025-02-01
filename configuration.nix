{ config, pkgs, ... }:

{
  imports =
    [
      ./hardware-configuration.nix
    ];


  # ЗАВАНТАЖУВАЧ
  boot = {
    loader = {
      systemd-boot = {
        enable = true;
        consoleMode = "max";
        configurationLimit = 5;
        editor = false;
      };
      
      timeout = 10;
      efi = {
        canTouchEfiVariables = false;
        efiSysMountPoint = "/boot";
      };
    };

    initrd = {
      luks.devices."luks-911765a7-6ecb-4c99-88ef-b44c26fd3583".device = "/dev/disk/by-uuid/911765a7-6ecb-4c99-88ef-b44c26fd3583";
      systemd.enable = true;
    };

    kernelPackages = pkgs.linuxPackages_latest;
    kernelModules = [ "kvm-amd" ];
    kernelParams = [
      "kernel.printk=\"3 4 1 3\""
      "slab_nomerge"
      "amd_iommu=pt"
      "init_on_alloc=1"
      "init_on_free=1"
      "slub_debug=FZP"
      "page_poison=1"
      "l1tf=full,force"
      "mds=full,nosmt"
      "spectre_v2=on"
      "spec_store_bypass_disable=on"
      "stf_barrier=on"
      "module.sig_enforce=1"
      "slab_merge=off"
      "randomize_kstack_offset=on"
      "pti=on"
      "vsyscall=none"
      "debugfs=off"
      "lockdown=confidentiality"
      "usercopy=strict"
    ];

    supportedFilesystems = [ "btrfs" "reiserfs" "vfat" "ext4" "f2fs" "xfs" "ntfs" "cifs" ];

    kernel.sysctl = {
      "kernel.unprivileged_bpf_disabled" = 1;
      "net.core.bpf_jit_harden" = 2;
      "kernel.kptr_restrict" = 2;
      "kernel.perf_event_paranoid" = 3;
      "net.ipv4.conf.all.rp_filter" = 1;
      "net.ipv4.conf.default.rp_filter" = 1;
      "net.ipv4.tcp_syncookies" = 1;
      "net.ipv4.conf.all.accept_redirects" = 0;
      "net.ipv4.conf.default.accept_redirects" = 0;
      "net.ipv4.conf.all.send_redirects" = 0;
      "net.ipv4.conf.default.send_redirects" = 0;
      "kernel.yama.ptrace_scope" = 2;
      "net.ipv4.conf.all.log_martians" = 1;
      "net.ipv4.conf.default.log_martians" = 1;
      "net.ipv4.icmp_echo_ignore_broadcasts" = 1;
      "net.ipv4.icmp_ignore_bogus_error_responses" = 1;
      "vm.unprivileged_userfaultfd" = 0;
      "kernel.randomize_va_space" = 2;
    };
  };


  # МЕРЕЖА
  networking = {
    hostName = "nixos";
    enableIPv6 = true;
    tempAddresses = "disabled";
    nameservers = [ "1.1.1.1" "8.8.8.8" ];

    networkmanager = {
      enable = true;
      interfaces."wlp2s0".wpaConfig = {
        ssid = "TP-Link_5D4E";
        psk = "hash:";
      };
    };

    firewall = {
      enable = true;
      allowedTCPPorts = [
        53   # DNS
        80   # HTTP
        123  # NTP
        443  # HTTPS
        8080 # AltHTTP
        8443 # AltHTTPS
        5353 # mDNS
      ];

      allowedUDPPorts = [
        53   # DNS
        67   # DHCP
        68   # DHCP
        123  # NTP
        5353 # mDNS
      ];

      logRefusedConnections = true;
      allowPing = false;
      logIPv6Drops = true;
      extraCommands = ''
        iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
        ip6tables -A INPUT -p icmpv6 --icmpv6-type echo-request -j DROP
        iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
        iptables -A INPUT -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
        iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
        iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
        iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
        iptables -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
        iptables -A INPUT -p tcp --tcp-flags ACK,FIN FIN -j DROP
        iptables -A INPUT -p tcp --tcp-flags ACK,PSH PSH -j DROP
        iptables -A INPUT -p tcp --tcp-flags ACK,URG URG -j DROP
        iptables -A INPUT -p tcp --tcp-flags ALL ACK,PSH -j DROP
        iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
        iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
        iptables -A INPUT -p tcp --tcp-flags ALL FIN -j DROP
        iptables -A INPUT -p tcp --tcp-flags ALL URG,PSH,FIN -j DROP
        iptables -A INPUT -p tcp --tcp-flags ALL ACK,RST,SYN,FIN -j DROP
        iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
      '';
      
      extraStopCommands = ''
        iptables -F
        iptables -X
      '';

      checkReversePath = "loose";
      logReversePathDrops = true;
      autoLoadConntrackHelpers = false;
      connectionTrackingModules = [ "ftp" "irc" "sane" "sip" "tftp" ];
    };
  };


  # ЛОКАЛІЗАЦІЯ
  time = {
    timeZone = "Europe/Kyiv";
    hardwareClockInLocalTime = true;
  };

  i18n = {
    defaultLocale = "uk_UA.UTF-8";
    extraLocaleSettings = { LC_ALL = "uk_UA.UTF-8"; };
  };


  # СЕРВІСИ
  services = {

    # ГРАФІЧНИЙ ІНТЕРФЕЙС та взаємодія
    xserver = {
      enable = true;
      layout = "us,ua";
      xkbOptions = "grp:alt_shift_toggle";
    };

    libinput.enable = true;

    displayManager = {
      sddm.enable = true;
      desktopManager.plasma5.enable = true;
    };

    # ЖУРНАЛЮВАННЯ
    journald.extraConfig = ''
      Storage=persistent
      SystemMaxUse=500M
      ForwardToSyslog=yes
      Compress=yes
      Seal=yes
      Audit=yes
      MaxFileSec=1week
      RateLimitInterval=30s
      RateLimitBurst=100
      MaxLevelStore=info
      MaxLevelSyslog=err
      MaxRetentionSec=1week
      SystemMaxFiles=100
    '';

    # SSH
    openssh = {
      enable = false;
      settings = {
        AllowAgentForwarding = false;
        AllowStreamLocalForwarding = false;
        AllowTcpForwarding = false;
        AuthenticationMethods = "publickey";
        KbdInteractiveAuthentication = false;
        PasswordAuthentication = false;
        PermitRootLogin = "no";
        X11Forwarding = false;
        MaxAuthTries = 3;
        LoginGraceTime = "30s";
      };
      
      authorizedKeys = [ "ssh-ed25519 AAAAC3..." ];
      port = 2222;
    };

    # ПОВЕДІНКА ПРИ ВИМКНЕННІ
    logind = {
      powerKey = "ignore";
      rebootKey = "ignore";
      lidSwitch = "ignore";
      lidSwitchDocked = "ignore";
      lidSwitchExternalPower = "ignore";
      hibernateKey = "ignore";
      suspendKey = "ignore";
    };
  };

  # ШРИФТИ
  fonts.packages = with pkgs; [
    nerd-fonts.jetbrains-mono
    nerd-fonts.fira-code
    nerd-fonts.fira-mono
    cozette
    noto-fonts-emoji
    inter
    roboto
    vistafonts
    ];


  # КОНСОЛЬ
  console.keyMap = "us";


  # АУДІО
  security.rtkit.enable = true;
  hardware.pulseaudio.enable = false;
  services.pipewire = {
    enable = true;
    alsa.enable = true;
    alsa.support32Bit = true;
    pulse.enable = true;
    wireplumber.enable = true;
  };


  # КОРИСТУВАЧІ
  users.mutableUsers = false;

  users.users.oleksandr = {
    isNormalUser = true;
    description = "oleksandr";
    hashedPassword = "  ";
    extraGroups = [ "wheel" "video" "audio" "networkmanager" "libvirtd" "kvm" ];
    packages = with pkgs; [
      telegram-desktop
      discord
    ];
  };


  # БЕЗПЕКА
  users.users.root.hashedPassword = "  ";

  security = {
    sudo = {
      enable = true;
      execWheelOnly = true;
      extraConfig = ''
        Defaults timestamp_timeout=15
        Defaults passwd_timeout=25
        Defaults use_pty
      '';
    };

    auditd.enable = true;

    audit = {
      enable = true;
      rules = [
        "-a always,exit -F arch=b64 -S execve -k process_execution"
        "-a always,exit -F arch=b64 -S bind -k network_bind"
        "-a always,exit -F arch=b64 -S connect -k network_connect"
        "-a exit,always -F arch=b64 -S execve"
      ];
    };

    protectKernelImage = true;
    lockKernelModules = true;
    hideProcessesInformation = true;
    restrictSUIDSGID = true;
    unprivilegedUsernsClone = false;
    forcePageTableIsolation = true;
    allowSimultaneousMultithreading = false;
    virtualisation.flushL1DataCache = "always";

    pam = {
      services = {
        login.enableKrb5 = false;
        sudo.enableKrb5 = false;
        sshd.enableKrb5 = false;
      };
      loginLimits = [
        { domain = "*"; type = "hard"; item = "nofile"; value = "1024"; }
        { domain = "*"; type = "hard"; item = "nproc"; value = "512"; }
      ];
    };

    selinux = {
      enable = true;
      enforce = true;
    };

    /* apparmor = {
      enable = true;
      killUnconfinedConfinables = true;
    }; */
  };


  # NIX
  nix.settings = {
    extra-experimental-features = [ "nix-command" "flakes" ];
    sandbox = true;
    auto-optimise-store = true;
    trusted-users = [ "root" "@wheel" ];
    allowed-users = [ "root" "@wheel" ];
  };

  nixpkgs.config.allowUnfree = true;


  # ПАКЕТИ
  environment.systemPackages = with pkgs; [
    /* Код та текст */
    vscode
    kate
    vim

    /* Інтернет */
    firefox
    chromium

    /* Інструменти */
    wget
    curl

    /* Віртуалізація */
    sbctl
    libvirt
    pciutils
    virt-manager
    qemu_kvm
    bridge-utils
    kmod
    
    /* Дисковий простір */
    gparted
    ntfs-3g

    /* Відео */
    obs-studio
  ];


  # ВІРТУАЛІЗАЦІЯ
  virtualisation = {
    libvirtd = {
      enable = true;
      qemuPackage = pkgs.qemu_kvm;
      onBoot = "ignore";
      onShutdown = "shutdown";
      extraConfig = ''
        security_default_confined = 1
        security_driver = "selinux"
        user = "libvirt-qemu"
        group = "libvirt-qemu"
        dynamic_ownership = 1
        remember_owner = 1
        cgroup_device_acl = [
          /dev/null /dev/full /dev/zero
          /dev/random /dev/urandom
          /dev/ptmx /dev/kvm
        ]
        seccomp_sandbox = 1
        memory_backing_dir = "/var/lib/libvirt/memory"
      '';

      allowedBridges = [ "virbr0" "br0" ];
    };

    spiceUSBRedirection.enable = true;

    defaultNetwork = {
      enable = true;
      name = "virbr0";
      forwardMode = "nat";
    };
  };


  system.stateVersion = "24.11";
}
