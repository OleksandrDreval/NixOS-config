{ config, pkgs, ... }:

{
  imports =
    [
      ./hardware-configuration.nix
    ];



  # ЗАВАНТАЖУВАЧ
  boot = {
    # Налаштування завантажувача systemd-boot як основного завантажувач
    loader = {
      systemd-boot = {
        enable              = true;   # Увімкнення systemd-boot
        consoleMode         = "max";  # Максимальна роздільна здатність консолі
        configurationLimit  = 5;      # Зберігати останні 5 конфігурацій завантаження
        editor              = false;  # Вимкнення редактора в меню завантаження
        timeout             = 10;     # Час очікування вибору в меню завантаження 10 секунд
      };
      
      efi = {
        canTouchEfiVariables  = false;    # Не дозволяти systemd-boot змінювати змінні EFI
        efiSysMountPoint      = "/boot";  # Точка монтування EFI розділу
      };
    };

    # Налаштування initrd (initial RAM disk)
    initrd = {
      # Налаштування LUKS шифрування
      luks.devices."luks-911765a7-6ecb-4c99-88ef-b44c26fd3583".device = "/dev/disk/by-uuid/911765a7-6ecb-4c99-88ef-b44c26fd3583";
      systemd.enable = true; # Увімкнення systemd в initrd
    };

    /*  Повернення до latest kernel в заміну hardened kernel 
        через недоцільність у використанні за умови прямого налаштування ядра через параметри ядра та sysctl  */
    kernelPackages = pkgs.linuxPackages_latest;
    # Завантажувальні модулі ядра, необхідні для віртуалізації kvm-amd
    kernelModules = [ "kvm-amd" ];

    # Параметри ядра для безпеки
    kernelParams = [
      "amd_iommu                  =pt"                         # AMD IOMMU Passthrough
      "debugfs                    =off"                        # Вимкнення debugfs для безпеки
      "init_on_alloc              =1"                          # Ініціалізація пам'яті при виділенні
      "init_on_free               =1"                          # Ініціалізація пам'яті при звільненні
      "kernel.printk              =\"3 4 1 3\""                # Налаштування рівня виводу ядра
      "l1tf                       =full,force"                 # Захист від L1 Terminal Fault
      "lockdown                   =confidentiality:integrity"  # Режим блокування ядра
      "mds                        =full,nosmt"                 # Захист від Microarchitectural Data Sampling
      "module.sig_enforce         =1"                          # Вимагати підписи модулів ядра
      "page_alloc.shuffle         =1"                          # Рандомізація виділення сторінок пам'яті
      "page_poison                =1"                          # Заповнення звільненої пам'яті значеннями для запобігання витоку даних
      "pti                        =on"                         # Page Table Isolation
      "randomize_kstack_offset    =on"                         # Рандомізація зміщення стеку ядра
      "slab_nomerge"                                           # Вимкнення об'єднання slab-ів
      "slub_debug                 =FZP"                        # Налагодження SLAB allocator
      "spec_store_bypass_disable  =on"                         # Захист від Spectre store bypass
      "spectre_v2                 =on"                         # Захист від Spectre v2
      "stf_barrier                =on"                         # Single Thread Fault barrier
      "usercopy                   =strict"                     # Суворі перевірки копіювання даних з/в user space
      "vsyscall                   =none"                       # Вимкнення vsyscall
    ];

    # Підтримувані файлові системи
    supportedFilesystems =
      [ "btrfs" "vfat" "ext4" "xfs" "ntfs" ] ++
      lib.optional (lib.meta.availableOn pkgs.stdenv.hostPlatform config.boot.zfs.package) "zfs"; # Додати ZFS, якщо доступний

    # Безпекові налаштування парметрів ядра sysctl
    kernel.sysctl = {
      "dev.tty.ldisc_autoload"                      = 0;      # Вимкнення автоматичного завантаження лінійних дисциплін для терміналів. Це покращує безпеку, запобігаючи завантаженню шкідливих лінійних дисциплін.
      "kernel.dmesg_restrict"                       = 1;      # Обмеження доступу до dmesg
      "kernel.ftrace_enabled"                       = false;  # Вимкнення ftrace для покращення безпеки та продуктивності. ftrace - це інструмент трасування ядра, який може бути використаний для атак.
      "kernel.kptr_restrict"                        = 2;      # Обмеження доступу до адрес ядра. Рівень 2 забезпечує максимальний захист.
      "kernel.perf_event_paranoid"                  = 3;      # Параноїдальний режим для perf events. Це запобігає використанню perf events для атак.
      "kernel.randomize_va_space"                   = 2;      # Рандомізація адресного простору. Рівень 2 забезпечує більш сильну рандомізацію.
      "kernel.sysrq"                                = 4;      # Обмеження можливостей магічної клавіші SysRq. Рівень 4 дозволяє лише деякі функції.
      "kernel.unprivileged_bpf_disabled"            = 1;      # Вимкнення BPF для непривілейованих користувачів. Це запобігає використанню BPF для атак.
      "kernel.yama.ptrace_scope"                    = 2;      # Обмеження ptrace. Рівень 2 дозволяє ptrace тільки для процесів з тим самим UID.
      "net.core.bpf_jit_enable"                     = false;  # Вимкнення JIT для BPF. Це покращує безпеку, запобігаючи використанню JIT для атак.
      "net.core.bpf_jit_harden"                     = 2;      # Зміцнення JIT для BPF. Рівень 2 забезпечує більш сильне зміцнення.
      "net.ipv4.conf.all.accept_redirects"          = false;  # Не приймати ICMP redirects. Це запобігає атакам маршрутизації.
      "net.ipv4.conf.all.log_martians"              = true;   # Логувати "марсіанські" пакети. Це допомагає виявити атаки.
      "net.ipv4.conf.all.rp_filter"                 = 1;      # Reverse path filtering. Це допомагає запобігти атакам підробки IP-адрес.
      "net.ipv4.conf.all.secure_redirects"          = false;  # Не приймати redirects від будь-кого. Це запобігає атакам маршрутизації.
      "net.ipv4.conf.all.send_redirects"            = false;  # Не надсилати redirects. Це запобігає атакам маршрутизації.
      "net.ipv4.conf.default.accept_redirects"      = false;  # accept_redirects, але для інтерфейсу за замовчуванням
      "net.ipv4.conf.default.log_martians"          = true;   # log_martians, але для інтерфейсу за замовчуванням
      "net.ipv4.conf.default.rp_filter"             = 1;      # rp_filter, але для інтерфейсу за замовчуванням
      "net.ipv4.conf.default.secure_redirects"      = false;  # secure_redirects, але для інтерфейсу за замовчуванням
      "net.ipv4.conf.default.send_redirects"        = false;  # send_redirects, але для інтерфейсу за замовчуванням
      "net.ipv4.icmp_echo_ignore_all"               = 1;      # Ігнорувати всі ICMP echo запити (ping). Це покращує безпеку, запобігаючи DoS атакам.
      "net.ipv4.icmp_echo_ignore_broadcasts"        = 1;      # Ігнорувати broadcast ping
      "net.ipv4.icmp_ignore_bogus_error_responses"  = 1;      # Ігнорувати неправильні ICMP повідомлення про помилки. Це допомагає запобігти атакам.
      "net.ipv4.tcp_rfc1337"                        = 1;      # Вмикає захист від TCP атак, описаних в RFC 1337.
      "net.ipv4.tcp_syncookies"                     = 1;      # Увімкнення SYN cookies для захисту від SYN flood
      "net.ipv6.conf.all.accept_redirects"          = false;  # Не приймати IPv6 redirects. Це запобігає атакам маршрутизації.
      "net.ipv6.conf.default.accept_redirects"      = false;  # те саме для IPv6 інтерфейсу за замовчуванням
      "vm.unprivileged_userfaultfd"                 = 0;      # Вимкнення userfaultfd для непривілейованих користувачів. Це покращує безпеку, запобігаючи використанню userfaultfd для атак.
    };

    /* Бан-лист небезпечних або застрілих модулів ядра */
    blacklistedKernelModules = [
      # Застарілі мережеві протоколи
      "ax25" "netrom" "rose"
      
      # Застарілі або потенційно небезпечні файлові системи
      "adfs"    "affs"      "befs"       "bfs" 
      "cifs"    "cramfs"    "efs"        "erofs" 
      "exofs"   "f2fs"      "freevxfs"   "gfs2" 
      "hfs"     "hfsplus"   "hpfs"       "jffs2" 
      "jfs"     "ksmbd"     "minix"      "nilfs2" 
      "nfs"     "nfsv3"     "nfsv4"      "omfs" 
      "qnx4"    "qnx6"      "reiserfs"   "squashfs" 
      "sysv"    "udf"       "ufs"        "vivid"
    ];

    cleanTmpDir = true; # Очищення тимчасової директорії при кожному запуску системи
    tmpOnTmpfs = true;  # Використання tmpfs для /tmp
  };


  # МЕРЕЖА
  networking = {
    hostName = "Rampart-Nix";     # Назва хоста
    networkmanager.enable = true; # Використання NetworkManager
    enableIPv6 = true;            # Увімкнення IPv6
    tempAddresses = "disabled";   # Вимкнення тимчасових адрес

    
    # DNS-сервери
    nameservers = [
      "1.1.1.1" # Cloudflare
      "8.8.8.8" # Google Public DNS
      "9.9.9.9" # Quad9
    ];


    #БРАНДМАУЕР
    firewall = {
      enable = true;      # Увімкнення брандмауера
      allowPing = false;  # Заборона ping запитів
      # Дозволені TCP порти:
      allowedTCPPorts = [
        53    # DNS
        67    # DHCP-сервер
        68    # DHCP-клієнт
        80    # HTTP
        443   # HTTPS
        8080  # altHTTP
        # 737   # specific SSH port
      ];

      # Дозволені UDP порти:
      allowedUDPPorts = [
        53    # DNS
        67    # DHCP-сервер
        68    # DHCP-клієнт
        80    # HTTP
        443   # HTTPS
      ];


                            ####################################
                            #             IPtables             #
                            ####################################
      /*  Дозволити 5 SYN пакетів в секунду, з burst 10, для запобігання SYN flood
          Відкидати всі інші SYN пакети
          Відкидати невалідні пакети
          Відкидати нові TCP пакети, які не є SYN

          Блокування різних комбінацій TCP прапорів, захист від аномального трафіку

          Блокувати NTP та mDNS запити ззовні
          Дозволити NTP та mDNS з локальної мережі

          Блокування ICMP echo-request, ping  */
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

        iptables -A INPUT -p udp --dport 123 -j DROP
        iptables -A INPUT -p udp --dport 123 -s 192.168.1.0/24 -j ACCEPT
        iptables -A INPUT -p udp --dport 5353 -j DROP
        iptables -A INPUT -p udp --dport 5353 -s 192.168.1.0/24 -j ACCEPT
        
        iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
        ip6tables -A INPUT -p icmpv6 --icmpv6-type echo-request -j DROP
      '';

                       # Очищення правил IPtables при зупинці
      /*  Використовуємо -F для видалення всіх правил у вказаних ланцюжках
          Використовуємо -X для видалення всіх користувацьких ланцюжків
          Це забезпечує чистий стан мережевого фільтру при перезапуску системи
          та уникнення конфліктів між старими та новими правилами  */
      extraStopCommands = ''
        iptables -F
        iptables -X
      '';

      autoLoadConntrackHelpers = false; # Вимкнення автоматичного завантаження conntrack helpers
      checkReversePath = "strict";      # Строга перевірка зворотнього шляху
      # Модулі для відстеження з'єднань
      connectionTrackingModules = [
        "amanda"
        "ftp" 
        "h323"
        "irc"
        "netbios_sn"
        "pptp"
        "sane"
        "sip"
        "snmp"
        "tftp"
      ];

      logRefusedConnections = true; # Логування відхилених з'єднань
      logReversePathDrops = true;   # Логування відкинутих пакетів через зворотній шлях
      logIPv6Drops = true;          # Логування відкинутих IPv6 пакетів
      logDenied = "all";            # Журналювання всіх відхилених з'єднань
    };
  };



  # ЛОКАЛІЗАЦІЯ
  # Налаштування часового поясу та годинника
  time = {
    timeZone                  = "Europe/Kyiv";  # Встановлюємо часовий пояс Київ
    hardwareClockInLocalTime  = true;           # Годинник системи працює у локальному часі
  };

  # Налаштування локалізації та мови інтерфейсу
  i18n = {
    defaultLocale       = "uk_UA.UTF-8";                # Встановлюємо мову за замовчуванням (UTF-8 кодування)
    extraLocaleSettings = { LC_ALL = "uk_UA.UTF-8"; };  # Встановлюємо мову для всіх категорій локалізації.
  };

  # Налаштування макету клавіатури консолі
  # Використовуємо американську розкладку клавіатури.
  console = { 
    keyMap = "us";
    earlySetup = true;
    font = "sun12x22";
    colors = theme.colors16;
  };



  # СЕРВІСИ
  services = {

              # ГРАФІЧНИЙ ІНТЕРФЕЙС та взаємодія з ним.
    /*  Вмикаємо X server з розкладками клавіатури "us" та "ua",
        дозволяючи перемикання між ними за допомогою Alt+Shift.  */
    xserver = {
      enable      = true;
      layout      = "us,ua";
      xkbOptions  = "grp:alt_shift_toggle";
      # Вмикаємо libinput для керування пристроями вводу.
      libinput = {
        enable = true;  # Вмикаємо підтримку libinput для всіх пристроїв вводу
        # Налаштування тачпаду
        touchpad = {
          tappingDragLock = false;  # Вимкнено функцію блокування перетягування при тапінгу. Це зменшує ризик випадкових дій під час роботи.
          naturalScrolling = true;  # Вмикаємо "природне" прокручування. Збільшує інтуїтивність використання для більшості користувачів.
        };
      };
    };

    /*  Використовуємо sddm як дисплей менеджер та Plasma 6 як робоче середовище.
        SDDM обраний через його легкість, швидкодію та гарну інтеграцію з KDE Plasma.
        Plasma 6 обрана як стабільне та функціональне середовище з гарною підтримкою 
        та зручним користувацьким інтерфейсом.  */
    displayManager = {
      sddm.enable                     = true;  # Вмикаємо SDDM як менеджер дисплея
      desktopManager.plasma6.enable   = true;   # Вмикаємо KDE Plasma 6 як робоче середовище
    };


                          # ЖУРНАЛЮВАННЯ
    /*  Налаштування journald для журналювання подій системи.
        Вмикаємо аудит, стиснення логів, пересилання до syslog,
        встановлюємо обмеження на розмір та час зберігання файлів,
        а також інші параметри для оптимізації та безпеки.  */
    journald.extraConfig = ''
      Audit             =yes          # Вмикаємо аудит системи
      Compress          =yes          # Вмикаємо стиснення лог-файлів
      ForwardToSyslog   =yes          # Пересилаємо логи до syslog
      MaxFileSec        =1week        # Максимальний розмір файлу журналу - 1 тиждень
      MaxLevelStore     =warning      # Максимальний рівень повідомлень, що зберігаються локально
      MaxLevelSyslog    =err          # Максимальний рівень повідомлень, що відправляються до syslog
      MaxRetentionSec   =1week        # Максимальний час зберігання логів - 1 тиждень
      RateLimitBurst    =100          # Кількість повідомлень перед застосуванням обмеження швидкості
      RateLimitInterval =30s          # Інтервал часу для обмеження швидкості
      RuntimeKeepFree   =200M         # Мінімальний вільний простір для runtime логів
      RuntimeMaxUse     =100M         # Максимальний розмір runtime логів
      Seal              =yes          # Захист цілісності логів
      Storage           =persistent   # Зберігання логів на постійному носії
      SystemKeepFree    =1G           # Мінімальний вільний простір для системних логів
      SystemMaxFiles    =100          # Максимальна кількість системних лог-файлів
      SystemMaxUse      =500M         # Максимальний розмір системних логів
    '';


                  # SSH
    /*  Налаштування SSH сервера.
        Вимкнено за замовчуванням для підвищення безпеки.
        Використовується тільки ключова аутентифікація,
        обмежена кількість спроб авторизації,
        заборонено використання паролів та root-логіну.  */
    openssh = {
      enable = false; # SSH вимкнено за замовчуванням
      settings = {
        AllowAgentForwarding          = false;        # Забороняємо переадресацію агентів
        AllowStreamLocalForwarding    = false;        # Забороняємо локальну переадресацію потоків
        AllowTcpForwarding            = false;        # Забороняємо TCP переадресацію
        AuthenticationMethods         = "publickey";  # Дозволяємо тільки ключову аутентифікацію
        KbdInteractiveAuthentication  = false;        # Забороняємо інтерактивну аутентифікацію
        LoginGraceTime                = "30s";        # Час на авторизацію - 30 секунд
        MaxAuthTries                  = 3;            # Максимальна кількість спроб авторизації - 3
        PasswordAuthentication        = false;        # Забороняємо аутентифікацію за допомогою паролів
        PermitRootLogin               = "no";         # Забороняємо root-логін
        X11Forwarding                 = false;        # Забороняємо X11 переадресацію
      };
      
      authorizedKeys  = [ "..." ];  # Список авторизованих ключів
      port            = 737;        # Порт для SSH з'єднання
    };


                  # ПОВЕДІНКА ПРИ ВИМКНЕННІ
    /*  Налаштування поведінки системи при вимкненні.
        Всі дії при вимкненні ігноруються.  */
    logind = {
      hibernateKey            = "ignore";   # Ігноруємо кнопку гібернації
      lidSwitch               = "ignore";   # Ігноруємо закриття кришки ноутбука
      lidSwitchDocked         = "ignore";   # Ігноруємо закриття кришки ноутбука в док-станції
      lidSwitchExternalPower  = "ignore";   # Ігноруємо закриття кришки ноутбука при підключенні до зовнішнього живлення
      powerKey                = "ignore";   # Ігноруємо кнопку живлення
      rebootKey               = "ignore";   # Ігноруємо кнопку перезавантаження
      suspendKey              = "ignore";   # Ігноруємо кнопку сну
    };
  };



  # ШРИФТИ.
  # Використовуємо набір шрифтів з підтримкою лігатур та емоджі.
  fonts = {
    fontDir.enable = true;
    fonts = with pkgs; [
    nerd-fonts.jetbrains-mono
    nerd-fonts.fira-code
    nerd-fonts.fira-mono
    cozette
    noto-fonts-emoji
    inter
    roboto
    vistafonts
    ];
  };



                            # Налаштування АУДІО.
  /*  Вмикаємо rtkit для реального часу та pipewire для обробки аудіо.  */
  security.rtkit.enable       = true;   # Вмикаємо rtkit для процесів у реальному часі
  hardware.pulseaudio.enable  = false;  # Вимикаємо PulseAudio на користь Pipewire.
  services.pipewire = {
    enable              = true;   # Вмикаємо Pipewire
    alsa.enable         = true;   # Вмикаємо ALSA підтримку
    alsa.support32Bit   = true;   # Вмикаємо 32-бітну підтримку ALSA
    pulse.enable        = true;   # Вмикаємо PulseAudio емуляцію в Pipewire
    wireplumber.enable  = true;   # Вмикаємо WirePlumber
  };



                        # КОРИСТУВАЧІ
  /*  Вимкнення можливості зміни користувачів через NixOS
      Це забезпечує імутабельність користувачів та їх налаштувань  */
  users.mutableUsers = false;

  # Основна конфігурація користувача
  users.users.oleksandr = {
    isNormalUser    = true;         # Вказуємо, що це звичайний користувач (не системний)
    description     = "oleksandr";  # Опис користувача
    
    # Хешований пароль
    hashedPassword  = "  ";
    
    # Додаткові групи для надання прав доступу:
    /*  wheel - права адміністратора через sudo
        video - доступ до графічного обладнання
        audio - доступ до аудіо системи
        networkmanager - управління мережевими з'єднаннями
        libvirtd, kvm - віртуалізація через KVM  */
    extraGroups     = [ "wheel" "video" "audio" "networkmanager" "libvirtd" "kvm" ];
    
    # Пакети, які будуть встановлені лише для цього користувача
    packages = with pkgs; [
      telegram-desktop
    ];
  };



  # БЕЗПЕКА
  # Хешований root пароль 
  users.users.root.hashedPassword = "  ";

  security = {
    # Налаштування sudo
    sudo = {
      enable          = true;  # Вмикаємо sudo
      execWheelOnly   = true;  # Дозволяємо виконання sudo лише користувачам з групи wheel
      extraConfig = ''
        Defaults insults                 # Додаємо образливі повідомлення при невдалій спробі sudo
        Defaults passwd_timeout     =25  # Час очікування введення пароля (25 секунд)
        Defaults timestamp_timeout  =15  # Час дії кешування пароля (15 хвилин)
        Defaults use_pty                 # Використання PTY для всіх команд sudo
      '';
    };

    # Налаштування аудиту системи
    auditd.enable = true;
    audit = {
      enable = true;
      rules = [
        "-a always,exit -F arch=b64 -S execve -k process_execution"                                                      # Логування виконання процесів
        "-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat,open_by_handle_at -F exit=-EACCES -k access" # Логування спроб доступу до файлів з помилками EACCES
        "-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat,open_by_handle_at -F exit=-EPERM -k access"  # Логування спроб доступу до файлів з помилками EPERM
      ];
    };

    # Налаштування безпеки ядра
    allowSimultaneousMultithreading   = false;    # Вимкнення SMT для запобігання атак типу Spectre
    forcePageTableIsolation           = true;     # Увімкнення PTI для захисту від Meltdown
    hideProcessesInformation          = true;     # Приховування інформації про процеси
    lockKernelModules                 = true;     # Блокування завантаження нових модулів ядра
    protectKernelImage                = true;     # Захист образу ядра
    restrictSUIDSGID                  = true;     # Обмеження SUID/SGID бітів
    unprivilegedUsernsClone           = false;    # Заборона створення просторів імен користувачів без привілеїв
    virtualisation.flushL1DataCache   = "always"; # Очищення кешу L1 для запобігання атак типу L1TF

    # Налаштування PAM (Pluggable Authentication Modules)
    pam = {
      services = {
        login = {
          enableKrb5          = false;    # Вимкнення Kerberos для входу
          allowNullPasswords  = false;    # Заборона пустих паролів
          failDelay           = 4000000;  # Затримка після невдалої спроби входу (4 секунди)
          maxRetries          = 3;        # Максимальна кількість спроб входу
          unlockTime          = 600;      # Час блокування облікового запису після невдалих спроб (10 хвилин)
        };
        
        sudo.enableKrb5 = false;  # Вимкнення Kerberos для sudo
        sshd.enableKrb5 = false;  # Вимкнення Kerberos для SSH
      };

      # Обмеження ресурсів для користувачів
      loginLimits = [
        { domain = "*"; type = "hard"; item = "nofile"; value = "1024"; }  # Максимум відкритих файлів
        { domain = "*"; type = "hard"; item = "nproc"; value = "512"; }    # Максимум процесів
      ];
    };

    # Налаштування SELinux
    selinux = {
      enable    = true;  # Вмикаємо SELinux
      enforce   = true;  # Увімкнення режиму застосування політик
    };

    /* apparmor = {
      enable                      = true;
      killUnconfinedConfinables   = true;
    }; */
  };

  environment.memoryAllocator.provider  = "scudo";          # Використання scudo як аллокатора пам'яті для підвищення безпеки
  environment.variables.SCUDO_OPTIONS   = "ZeroContents=1"; # Налаштування scudo для ініціалізації пам'яті нулями



  # NIX
  nix.settings = {
    /*  Включення експериментальних функцій:
        - nix-command: дозволяє використовувати нову команду nix
        - flakes: впроваджує нову модель управління пакетами  */
    extra-experimental-features   = [ "nix-command" "flakes" ];

    sandbox                       = true; # Увімкнення пісочниці для більшої безпеки під час збірки пакетів
    auto-optimise-store           = true; # Автоматична оптимізація сховища для зменшення використання дискового простору

    /*  Користувачі, яким дозволено виконувати привілейовані операції:
        - root: системний адміністратор
        - @wheel: користувачі з правами адміністратора  */
    trusted-users                 = [ "root" "@wheel" ];

    /*  Користувачі, яким дозволено використовувати Nix:
        - root: системний адміністратор
        - @wheel: користувачі з правами адміністратора  */
    allowed-users                 = [ "root" "@wheel" ];
  };

  /*  Дозвіл на використання пропрієтарного програмного забезпечення
      Необхідно для деяких програм, які не мають відкритих альтернатив  */
  nixpkgs.config.allowUnfree = true;



  # ПАКЕТИ
  environment.systemPackages = with pkgs; [
    # Код та текст
    vscode
    kate
    vim

    # Інтернет
    firefox

    # Інструменти
    wget
    curl
    unzip
    zip

    # Віртуалізація
    sbctl
    libvirt
    pciutils
    virt-manager
    qemu_kvm
    bridge-utils
    kmod
    
    # Дисковий простір
    gparted
    ntfs-3g

    # Відео
    obs-studio
  ];



  # ВІРТУАЛІЗАЦІЯ
  virtualisation = {

    # Налаштування libvirt для керування віртуалізацією
    libvirtd = {
      enable        = true;           # Увімкнення служби libvirt
      qemuPackage   = pkgs.qemu_kvm;  # Використання KVM для апаратного прискорення
      onBoot        = "ignore";       # Не запускати віртуальні машини автоматично при завантаженні
      onShutdown    = "shutdown";     # Завершувати віртуальні машини при вимкненні системи
      
      extraConfig = ''
        security_default_confined   = 1           # Увімкнення захисту за замовчуванням
        security_driver             = "selinux"   # Використання SELinux для захисту
        user                        = "@libvirt"  # Користувач для запуску віртуальних машин
        group                       = "@libvirt"  # Група для запуску віртуальних машин
        dynamic_ownership           = 1           # Динамічне призначення власника файлів
        remember_owner              = 1           # Запам'ятовування власника файлів

        cgroup_device_acl = [                     # Дозволені пристрої для cgroup
          /dev/null /dev/full /dev/zero
          /dev/random /dev/urandom
          /dev/ptmx /dev/kvm
        ]

        seccomp_sandbox     = 1                          # Увімкнення захисту через seccomp
        memory_backing_dir  = "/var/lib/libvirt/memory"  # Директорія для файлів підкачки
        cgroup_controllers  = [ "cpu" "memory" "pids" ]  # Контролери ресурсів
        cgroup_device_acl   = []                         # Додаткові дозволені пристрої
      '';

      # Дозволені мережеві мости для віртуальних машин
      allowedBridges = [ "virbr0" "br0" ];
    };

    # Увімкнення перенаправлення USB через SPICE для віртуальних машин
    spiceUSBRedirection.enable = true;

    # Налаштування мережі за замовчуванням для віртуальних машин
    defaultNetwork = {
      enable        = true;     # Увімкнення мережі за замовчуванням
      name          = "virbr0"; # Ім'я мережевого інтерфейсу
      forwardMode   = "nat";    # Використання NAT для виходу в інтернет
    };
  };



  system.stateVersion = "24.11";
}
