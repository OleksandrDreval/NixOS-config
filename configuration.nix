{ config, pkgs, ... }:

{
  imports =
    [
      ./hardware-configuration.nix
    ];


  # ЗАВАНТАЖУВАЧ
  boot = {
    /* Налаштування завантажувача
    systemd-boot як основний завантажувач */
    loader = {
      systemd-boot = {
        enable              = true;  # Увімкнення systemd-boot
        consoleMode         = "max"; # Максимальна роздільна здатність консолі
        configurationLimit  = 5;     # Зберігати останні 5 конфігурацій завантаження
        editor              = false; # Вимкнення редактора в меню завантаження
        timeout             = 10;    # Час очікування вибору в меню завантаження (10 секунд)
      };
      
      efi = {
        canTouchEfiVariables  = false;   # Не дозволяти systemd-boot змінювати змінні EFI
        efiSysMountPoint      = "/boot"; # Точка монтування EFI розділу
      };
    };

    # Налаштування initrd (initial RAM disk)
    initrd = {
      # Налаштування LUKS шифрування
      luks.devices."luks-911765a7-6ecb-4c99-88ef-b44c26fd3583".device = "/dev/disk/by-uuid/911765a7-6ecb-4c99-88ef-b44c26fd3583"; # Пристрій з LUKS шифруванням
      systemd.enable = true; # Увімкнення systemd в initrd
    };

    # Використання захищеного ядра (hardened kernel) для підвищення безпеки
    kernelPackages = pkgs.linuxPackages_hardened;

    # Завантажувальні модулі ядра, необхідні для віртуалізації (kvm-amd)
    kernelModules = [ "kvm-amd" ];

    # Параметри ядра для безпеки та продуктивності
    kernelParams = [
      "amd_iommu                  =pt"  # AMD IOMMU Passthrough
      "debugfs                    =off" # Вимкнення debugfs для безпеки
      "init_on_alloc              =1"   # Ініціалізація пам'яті при виділенні
      "init_on_free               =1"   # Ініціалізація пам'яті при звільненні
      "kernel.printk              =\"3 4 1 3\"" # Налаштування рівня виводу ядра
      "l1tf                       =full,force"  # Захист від L1 Terminal Fault
      "lockdown                   =confidentiality:integrity" # Режим блокування ядра
      "mds                        =full,nosmt"                # Захист від Microarchitectural Data Sampling
      "module.sig_enforce         =1"   # Вимагати підписи модулів ядра
      "page_alloc.shuffle         =1"   # Рандомізація виділення сторінок пам'яті
      "page_poison                =1"   # Заповнення звільненої пам'яті значеннями для запобігання витоку даних
      "pti                        =on"  # Page Table Isolation
      "randomize_kstack_offset    =on"  # Рандомізація зміщення стеку ядра
      "slab_nomerge"                    # Вимкнення об'єднання slab-ів
      "slub_debug                 =FZP" # Налагодження SLAB allocator
      "spec_store_bypass_disable  =on"  # Захист від Spectre store bypass
      "spectre_v2                 =on"  # Захист від Spectre v2
      "stf_barrier                =on"  # Single Thread Fault barrier
      "usercopy                   =strict" # Суворі перевірки копіювання даних з/в user space
      "vsyscall                   =none"   # Вимкнення vsyscall
    ];

    /* Підтримувані файлові системи */
    supportedFilesystems =
      [ "btrfs" "vfat" "ext4" "xfs" "ntfs" ] ++
      lib.optional (lib.meta.availableOn pkgs.stdenv.hostPlatform config.boot.zfs.package) "zfs"; # Додати ZFS, якщо доступний

    /* Безпекові налаштування парметрів ядра sysctl*/
    kernel.sysctl = {
      "kernel.dmesg_restrict"                       = 1; # Обмеження доступу до dmesg
      "kernel.ftrace_enabled"                       = false; # Вимкнення ftrace
      "kernel.kptr_restrict"                        = 2; # Обмеження доступу до адрес ядра
      "kernel.perf_event_paranoid"                  = 3; # Параноїдальний режим для perf events
      "kernel.randomize_va_space"                   = 2; # Рандомізація адресного простору
      "kernel.unprivileged_bpf_disabled"            = 1; # Вимкнення BPF для непривілейованих користувачів
      "kernel.yama.ptrace_scope"                    = 2; # Обмеження ptrace
      "net.core.bpf_jit_enable"                     = false; # Вимкнення JIT для BPF
      "net.core.bpf_jit_harden"                     = 2; # Зміцнення JIT для BPF
      "net.ipv4.conf.all.accept_redirects"          = 0; # Не приймати ICMP redirects
      "net.ipv4.conf.all.log_martians"              = 1; # Логувати "марсіанські" пакети
      "net.ipv4.conf.all.rp_filter"                 = 1; # Reverse path filtering
      "net.ipv4.conf.all.secure_redirects"          = false; # Не приймати redirects від будь-кого
      "net.ipv4.conf.all.send_redirects"            = 0; # Не надсилати redirects
      "net.ipv4.conf.default.accept_redirects"      = 0; #  (те саме, що і вище, але для інтерфейсу за замовчуванням)
      "net.ipv4.conf.default.log_martians"          = 1;
      "net.ipv4.conf.default.rp_filter"             = 1;
      "net.ipv4.conf.default.secure_redirects"      = false;
      "net.ipv4.conf.default.send_redirects"        = 0;
      "net.ipv4.icmp_echo_ignore_broadcasts"        = 1; # Ігнорувати broadcast ping
      "net.ipv4.icmp_ignore_bogus_error_responses"  = 1; # Ігнорувати неправильні ICMP повідомлення про помилки
      "net.ipv4.tcp_syncookies"                     = 1; # Увімкнення SYN cookies для захисту від SYN flood
      "net.ipv6.conf.all.accept_redirects"          = false; # Не приймати IPv6 redirects
      "net.ipv6.conf.default.accept_redirects"      = false; # (те саме для IPv6 інтерфейсу за замовчуванням)
      "vm.unprivileged_userfaultfd"                 = 0; # Вимкнення userfaultfd для непривілейованих користувачів
    };

    /* Бан-лист небезпечних або застрілих модулів ядра та файлових систем */
    blacklistedKernelModules = [
      # Застарілі мережеві протоколи
      "ax25" "netrom" "rose"
      
      # Застарілі або потенційно небезпечні файлові системи
      "adfs" "affs" "befs" "bfs" "cifs" "cramfs" "reiserfs" "efs" "erofs" "exofs" "f2fs" 
      "freevxfs" "hfs" "hpfs" "jfs" "minix" "nilfs2" "omfs" "qnx4" "qnx6" "sysv" "ufs" 
    ];
  };


  # МЕРЕЖА
  networking = {
    hostName        = "nixos";
    enableIPv6      = true;
    tempAddresses   = "disabled";
    nameservers     = [ "1.1.1.1" "8.8.8.8" ];

    networkmanager.enable = true;

    /* Брандмауер */
    firewall = {
      enable = true;
      allowedTCPPorts = [
        53   # DNS
        80   # HTTP
        443  # HTTPS
        8080 # AltHTTP
        8443 # AltHTTPS
      ];

      allowedUDPPorts = [
        53   # DNS
        67   # DHCP
        68   # DHCP
      ];

      /* IPtables */
      logRefusedConnections   = true;
      allowPing               = false;
      logIPv6Drops            = true;
      extraCommands = ''
        iptables -A INPUT -p tcp --syn -m limit --limit 5/s --limit-burst 10 -j ACCEPT
        iptables -A INPUT -p tcp --syn -j DROP
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

        iptables -A INPUT -p udp --dport 123 -s 192.168.1.0/24 -j ACCEPT
        iptables -A INPUT -p udp --dport 5353 -j DROP
        iptables -A INPUT -p udp --dport 5353 -s 192.168.1.0/24 -j ACCEPT
        iptables -A INPUT -p udp --dport 123 -j DROP

        iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
        ip6tables -A INPUT -p icmpv6 --icmpv6-type echo-request -j DROP
      '';
      
      extraStopCommands = ''
        iptables -F
        iptables -X
      '';

      autoLoadConntrackHelpers    = false;
      checkReversePath            = "strict";
      connectionTrackingModules   = [ "ftp" "irc" "sane" "sip" "tftp" ];
      logReversePathDrops         = true;

      /* Журналювання відхилених з'єднань */
      logDenied = "all";
    };
  };


  # ЛОКАЛІЗАЦІЯ
  time = {
    timeZone                  = "Europe/Kyiv";
    hardwareClockInLocalTime  = true;
  };

  /* Мова інтерфейсу */
  i18n = {
    defaultLocale         = "uk_UA.UTF-8";
    extraLocaleSettings   = { LC_ALL = "uk_UA.UTF-8"; };
  };


  # КОНСОЛЬ
  console.keyMap = "us";


  # СЕРВІСИ
  services = {

    # ГРАФІЧНИЙ ІНТЕРФЕЙС та взаємодія
    xserver = {
      enable      = true;
      layout      = "us,ua";
      xkbOptions  = "grp:alt_shift_toggle";
    };

    libinput.enable = true;

    displayManager = {
      sddm.enable                     = true;
      desktopManager.plasma5.enable   = true;
    };

    # ЖУРНАЛЮВАННЯ
    journald.extraConfig = ''
      Audit             =yes
      Compress          =yes
      ForwardToSyslog   =yes
      MaxFileSec        =1week
      MaxLevelStore     =warning
      MaxLevelSyslog    =err
      MaxRetentionSec   =1week
      RateLimitBurst    =100
      RateLimitInterval =30s
      RuntimeKeepFree   =200M
      RuntimeMaxUse     =100M
      Seal              =yes
      Storage           =persistent
      SystemKeepFree    =1G
      SystemMaxFiles    =100
      SystemMaxUse      =500M
    '';

    # SSH
    openssh = {
      enable = false;
      settings = {
        AllowAgentForwarding          = false;
        AllowStreamLocalForwarding    = false;
        AllowTcpForwarding            = false;
        AuthenticationMethods         = "publickey";
        KbdInteractiveAuthentication  = false;
        LoginGraceTime                = "30s";
        MaxAuthTries                  = 3;
        PasswordAuthentication        = false;
        PermitRootLogin               = "no";
        X11Forwarding                 = false;
      };
      
      authorizedKeys  = [ "ssh-ed25519 AAAAC3..." ];
      port            = 2222;
    };

    # ПОВЕДІНКА ПРИ ВИМКНЕННІ
    logind = {
      hibernateKey            = "ignore";
      lidSwitch               = "ignore";
      lidSwitchDocked         = "ignore";
      lidSwitchExternalPower  = "ignore";
      powerKey                = "ignore";
      rebootKey               = "ignore";
      suspendKey              = "ignore";
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


  # АУДІО
  security.rtkit.enable       = true;
  hardware.pulseaudio.enable  = false;
  services.pipewire = {
    enable              = true;
    alsa.enable         = true;
    alsa.support32Bit   = true;
    pulse.enable        = true;
    wireplumber.enable  = true;
  };


  # КОРИСТУВАЧІ
  users.mutableUsers = false;

  users.users.oleksandr = {
    isNormalUser    = true;
    description     = "oleksandr";
    hashedPassword  = "  ";
    extraGroups     = [ "wheel" "video" "audio" "networkmanager" "libvirtd" "kvm" ];
    packages = with pkgs; [
      telegram-desktop
      discord
    ];
  };


  # БЕЗПЕКА
  users.users.root.hashedPassword = "  ";

  security = {

    /* sudo */
    sudo = {
      enable          = true;
      execWheelOnly   = true;
      extraConfig = ''
        Defaults insults
        Defaults passwd_timeout     =25
        Defaults timestamp_timeout  =15
        Defaults use_pty
      '';
    };

    /* Аудит */
    auditd.enable = true;
    audit = {
      enable = true;
      rules = [
        "-a always,exit -F arch=b64 -S execve -k process_execution"
        "-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat,open_by_handle_at -F exit=-EACCES -k access"
        "-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat,open_by_handle_at -F exit=-EPERM -k access"
      ];
    };

    /* Безпека та цілісність ядра */
    allowSimultaneousMultithreading   = false;
    forcePageTableIsolation           = true;
    hideProcessesInformation          = true;
    lockKernelModules                 = true;
    protectKernelImage                = true;
    restrictSUIDSGID                  = true;
    unprivilegedUsernsClone           = false;
    virtualisation.flushL1DataCache   = "always";

    /* Pluggable Authentication Modules */
    pam = {
      services = {
        login = {
          enableKrb5          = false;
          allowNullPasswords  = false;
          failDelay           = 4000000;
          maxRetries          = 3;
          unlockTime          = 600;
        };
        
        sudo.enableKrb5 = false;
        sshd.enableKrb5 = false;
      };

      loginLimits = [
        { domain = "*"; type = "hard"; item = "nofile"; value = "1024"; }
        { domain = "*"; type = "hard"; item = "nproc"; value = "512"; }
      ];
    };

    /* Security-Enhanced Linux */
    selinux = {
      enable    = true;
      enforce   = true;
    };

    /* apparmor = {
      enable                      = true;
      killUnconfinedConfinables   = true;
    }; */
  };

  environment.memoryAllocator.provider  = "scudo";
  environment.variables.SCUDO_OPTIONS   = "ZeroContents=1";


  # NIX
  nix.settings = {
    extra-experimental-features   = [ "nix-command" "flakes" ];
    sandbox                       = true;
    auto-optimise-store           = true;
    trusted-users                 = [ "root" "@wheel" ];
    allowed-users                 = [ "root" "@wheel" ];
  };

  /* Використання пропрієтарного ПО */
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
    unzip
    zip

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
      enable        = true;
      qemuPackage   = pkgs.qemu_kvm;
      onBoot        = "ignore";
      onShutdown    = "shutdown";
      extraConfig = ''
        security_default_confined   = 1
        security_driver             = "selinux"
        user                        = "@libvirt"
        group                       = "@libvirt"
        dynamic_ownership           = 1
        remember_owner              = 1
        cgroup_device_acl = [
          /dev/null /dev/full /dev/zero
          /dev/random /dev/urandom
          /dev/ptmx /dev/kvm
        ]
        seccomp_sandbox     = 1
        memory_backing_dir  = "/var/lib/libvirt/memory"
        cgroup_controllers  = [ "cpu" "memory" "pids" ]
        cgroup_device_acl   = []
      '';

      allowedBridges = [ "virbr0" "br0" ];
    };

    spiceUSBRedirection.enable = true;

    defaultNetwork = {
      enable        = true;
      name          = "virbr0";
      forwardMode   = "nat";
    };
  };


  system.stateVersion = "24.11";
}
