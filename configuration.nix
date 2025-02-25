{ config, pkgs, lib, ... }:

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

    # Налаштування initrd
    initrd = {
      # Налаштування LUKS шифрування
      luks = {
        devices."luks-911765a7-6ecb-4c99-88ef-b44c26fd3583".device = "/dev/disk/by-uuid/911765a7-6ecb-4c99-88ef-b44c26fd3583";
        mitigateDMAAttacks = true;  # Захист від атак DMA
      };

      systemd.enable = true;  # Увімкнення systemd в initrd
    };

    /*  Повернення до latest kernel в заміну hardened kernel 
        через недоцільність у використанні за умови прямого налаштування ядра через параметри ядра та sysctl  */
    kernelPackages = pkgs.linuxPackages_latest;
    # Завантажувальні модулі ядра, необхідні для віртуалізації kvm-amd
    kernelModules = [ "kvm-amd" ];

    # Параметри ядра для безпеки
    kernelParams = [
      "amd_iommu                  =force_isolation"           # Примусова ізоляція AMD IOMMU для захисту пристроїв вводу/виводу від зловмисного доступу до пам'яті.
      "apparmor                   =1"                         # Увімкнення AppArmor
      "audit                      =1"                         # Увімкнення аудиту для AppArmor
      "debugfs                    =off"                       # Вимкнення debugfs для безпеки; запобігає потенційному витоку системної інформації через механізми налагодження.
      "efi=disable_early_pci_dma"                             # Відключення раннього PCI DMA в режимі EFI; запобігає використанню ранньої ініціалізації DMA для експлуатації вразливостей.
      "ia32_emulation             =0"                         # Відключення емуляції 32-бітної архітектури; забезпечує використання 64-бітного режиму для покращення безпеки і продуктивності.
      "init_on_alloc              =1"                         # Ініціалізація пам'яті при виділенні; гарантує, що ново-виділена пам'ять не містить залишкових даних.
      "init_on_free               =1"                         # Ініціалізація пам'яті при звільненні; запобігає можливості витоку конфіденційної інформації після звільнення пам'яті.
      "iommu                      =force"                     # Примусове включення IOMMU; ізолює пристрої вводу/виводу для захисту від несанкціонованого доступу до пам'яті.
      "iommu.passthrough          =0"                         # Вимкнення passthrough режиму для IOMMU; забезпечує додаткові перевірки доступу до пам'яті пристроями.
      "iommu.strict               =1"                         # Активує строгий режим IOMMU; посилює контроль над доступом пристроїв до системної пам'яті.
      "kernel.printk              =\"3 4 1 3\""               # Налаштування рівня логування ядра; обмежує обсяг виводу для зменшення потенційної витоку інформації.
      "l1tf                       =full,force"                # Захист від L1 Terminal Fault; забезпечує повний захист від атак з використанням недоліків кешу першого рівня.
      "lockdown                   =confidentiality:integrity" # Режим блокування ядра; обмежує зміну критичних параметрів для підтримки конфіденційності та цілісності системи.
      "mds                        =full,nosmt"                # Захист від MDS (Microarchitectural Data Sampling); запобігає передачі даних між потоками завдяки відключенню SMT.
      "mitigations                =auto,nosmt"                # Автоматичне застосування патчів для відомих вразливостей з відключенням SMT для підвищення безпеки.
      "module.sig_enforce         =1"                         # Вимога підпису модулів ядра; гарантує, що завантажуються лише авторизовані і перевірені модулі.
      "oops                       =panic"                     # При виникненні критичної помилки ядра встановлюється panic; запобігає подальшій роботі системи у потенційно небезпечному стані.
      "page_alloc.shuffle         =1"                         # Рандомізація розподілу сторінок пам'яті; ускладнює передбачення розташування даних для експлойтів.
      "page_poison                =1"                         # Заповнення звільненої пам'яті спеціальними значеннями; запобігає можливості відновити раніше використані дані.
      "pti                        =on"                        # Активація Page Table Isolation; ізолює таблиці сторінок ядра для захисту від атак через витік пам'яті.
      "quiet"                                                 # Зменшення виводу системних повідомлень; забезпечує чистішу консоль під час завантаження.
      "random.trust_bootloader    =off"                       # Відключення довіри до завантажувача для генерації випадкових чисел; захищає від можливих атак через компрометацію bootloader.
      "random.trust_cpu           =off"                       # Вимикається довіра до генерації випадкових чисел CPU; використовується більш безпечний метод генерації випадкових чисел.
      "randomize_kstack_offset    =on"                        # Рандомізація зміщення стеку ядра; ускладнює експлуатацію уразливостей, пов'язаних з передбаченням адрес у пам'яті.
      "security                   =apparmor"                  # Встановлення AppArmor як LSM (Linux Security Module)
      "slab_nomerge"                                          # Вимкнення об'єднання slab-ів; дозволяє уникнути потенційних атак за рахунок передачі інформації між кешованими об'єктами.
      "slub_debug                 =FZP"                       # Налагодження SLUB аллокатора; розширене логування та перевірки для виявлення помилок у розподілі пам'яті.
      "spec_store_bypass_disable  =on"                        # Захист від Spectre store bypass; відключає небезпечні механізми для запобігання атак спектрального характеру.
      "spectre_v2                 =on"                        # Захист від Spectre v2; активує механізми для зменшення ризиків, пов'язаних з недоліками предиктивного виконання.
      "stf_barrier                =on"                        # Активує бар'єр Single Thread Fault; встановлює додатковий захист від атак, що використовують однониткові вразливості.
      "usercopy                   =strict"                    # Суворі перевірки копіювання даних між user space та ядром; знижує ризик передачі некоректних або шкідливих даних.
      "vsyscall                   =none"                      # Вимкнення vsyscall; відключає застарілий механізм викликів, що може бути використаний у атаках.
    ];

    # Підтримувані файлові системи
    supportedFilesystems =
      [ "btrfs" "vfat" "ext4" "xfs" "ntfs" ] ++
      lib.optional (lib.meta.availableOn pkgs.stdenv.hostPlatform config.boot.zfs.package) "zfs"; # Додати ZFS, якщо доступний

    # Безпекові налаштування парметрів ядра sysctl
    kernel.sysctl = {
      "dev.tty.ldisc_autoload"                      = "0";            # Вимкнення автоматичного завантаження лінійних дисциплін для терміналів. Це покращує безпеку, запобігаючи завантаженню шкідливих лінійних дисциплін.
      "fs.binfmt_misc.status"                       = "0";            # Вимкнення підтримки binfmt_misc для запобігання виконання сторонніх форматів. Зменшує поверхню атаки.
      "fs.protected_fifos"                          = "2";            # Захист FIFO файлів. Запобігає атакам через іменовані канали.
      "fs.protected_hardlinks"                      = "1";            # Захист жорстких посилань. Запобігає маніпуляціям з файлами.
      "fs.protected_regular"                        = "2";            # Захист звичайних файлів. Запобігає перезапису важливих файлів.
      "fs.protected_symlinks"                       = "1";            # Захист символічних посилань. Запобігає атакам через симлінки.
      "fs.suid_dumpable"                            = "0";            # Заборона dump для SUID програм. Запобігає витоку конфіденційних даних.
      "kernel.core_pattern"                         = "|/bin/false";  # Заборона створення core dump файлів. Запобігає витоку конфіденційних даних.
      "kernel.dmesg_restrict"                       = "1";            # Обмеження доступу до dmesg
      "kernel.ftrace_enabled"                       = "false";        # Вимкнення ftrace для покращення безпеки та продуктивності. ftrace - це інструмент трасування ядра, який може бути використаний для атак.
      "kernel.io_uring_disabled"                    = "2";            # Повне вимкнення io_uring через вразливості в реалізації. Запобігає витоку пам'яті та іншим атакам.
      "kernel.kexec_load_disabled"                  = "1";            # Заборона завантаження нових ядер через kexec. Запобігає завантаженню шкідливого коду.
      "kernel.kptr_restrict"                        = "2";            # Обмеження доступу до адрес ядра. Рівень 2 забезпечує максимальний захист.
      "kernel.perf_cpu_time_max_percent"            = "1";            # Обмеження використання CPU для perf. Запобігає DoS через perf.
      "kernel.perf_event_max_sample_rate"           = "1";            # Обмеження частоти семплів perf. Зменшує навантаження на систему.
      "kernel.perf_event_paranoid"                  = "3";            # Параноїдальний режим для perf events. Це запобігає використанню perf events для атак.
      "kernel.randomize_va_space"                   = "2";            # Рандомізація адресного простору. Рівень 2 забезпечує більш сильну рандомізацію.
      "kernel.sysrq"                                = "4";            # Обмеження можливостей магічної клавіші SysRq. Рівень 4 дозвляє лише деякі функції.
      "kernel.unprivileged_bpf_disabled"            = "1";            # Вимкнення BPF для непривілейованих користувачів. Це запобігає використанню BPF для атак.
      "kernel.yama.ptrace_scope"                    = "2";            # Обмеження ptrace. Рівень 2 дозволяє ptrace тільки для процесів з тим самим UID.
      "net.core.bpf_jit_enable"                     = "false";        # Вимкнення JIT для BPF. Це покращує безпеку, запобігаючи використанню JIT для атак.
      "net.core.bpf_jit_harden"                     = "2";            # Зміцнення JIT для BPF. Рівень 2 забезпечує більш сильне зміцнення.
      "net.ipv4.conf.all.accept_redirects"          = "false";        # Не приймати ICMP redirects. Це запобігає атакам маршрутизації.
      "net.ipv4.conf.all.accept_source_route"       = "0";            # Заборона source routing для всіх інтерфейсів. Запобігає спуфінгу IP-адрес.
      "net.ipv4.conf.all.arp_announce"              = "2";            # Налаштування ARP announce для всіх інтерфейсів. Додатковий захист від спуфінгу.
      "net.ipv4.conf.all.drop_gratuitous_arp"       = "1";            # Відкидання gratuitous ARP для всіх інтерфейсів. Додатковий захист від ARP poisoning.
      "net.ipv4.conf.all.forwarding"                = "0";            # Вимкнення forwarding для всіх інтерфейсів. Запобігає несанкціонованій маршрутизації.
      "net.ipv4.conf.all.log_martians"              = "true";         # Логувати martians пакети. Це допомагає виявити атаки.
      "net.ipv4.conf.all.rp_filter"                 = "1";            # Reverse path filtering. Це допомагає запобігти атакам підробки IP-адрес.
      "net.ipv4.conf.all.secure_redirects"          = "false";        # Не приймати redirects від будь-кого. Це запобігає атакам маршрутизації.
      "net.ipv4.conf.all.send_redirects"            = "false";        # Не надсилати redirects. Це запобігає атакам маршрутизації.
      "net.ipv4.conf.all.shared_media"              = "0";            # Вимкнення shared media для всіх інтерфейсів. Додатковий захист від конфліктів.
      "net.ipv4.conf.default.accept_redirects"      = "false";        # accept_redirects, але для інтерфейсу за замовчуванням
      "net.ipv4.conf.default.accept_source_route"   = "0";            # Заборона source routing за замовчуванням. Додатковий захист від спуфінгу.
      "net.ipv4.conf.default.arp_announce"          = "2";            # Налаштування ARP announce. Запобігає спуфінгу ARP.
      "net.ipv4.conf.default.arp_ignore"            = "1";            # Налаштування ARP ignore. Запобігає несанкціонованим ARP відповідям.
      "net.ipv4.conf.default.drop_gratuitous_arp"   = "1";            # Відкидання gratuitous ARP. Запобігає ARP poisoning.
      "net.ipv4.conf.default.forwarding"            = "0";            # Вимкнення forwarding за замовчуванням. Додатковий захист від маршрутизації.
      "net.ipv4.conf.default.log_martians"          = "true";         # log_martians, але для інтерфейсу за замовчуванням
      "net.ipv4.conf.default.rp_filter"             = "1";            # rp_filter, але для інтерфейсу за замовчуванням
      "net.ipv4.conf.default.secure_redirects"      = "false";        # secure_redirects, але для інтерфейсу за замовчуванням
      "net.ipv4.conf.default.send_redirects"        = "false";        # send_redirects, але для інтерфейсу за замовчуванням
      "net.ipv4.conf.default.shared_media"          = "0";            # Вимкнення shared media за замовчуванням. Запобігає конфліктам мережі.
      "net.ipv4.icmp_echo_ignore_all"               = "1";            # Ігнорувати всі ICMP echo запити (ping). Це покращує безпеку, запобігаючи DoS атакам.
      "net.ipv4.icmp_echo_ignore_broadcasts"        = "1";            # Ігнорувати broadcast ping
      "net.ipv4.icmp_ignore_bogus_error_responses"  = "1";            # Ігнорувати неправильні ICMP повідомлення про помилки. Це допомагає запобігти атакам.
      "net.ipv4.ip_forward"                         = "0";            # Вимкнення IP forwarding для запобігає використання як маршрутизатора. Зменшує ризик MITM атак.
      "net.ipv4.tcp_dsack"                          = "0";            # Вимкнення D-SACK для TCP. Зменшує навантаження на мережу.
      "net.ipv4.tcp_fack"                           = "0";            # Вимкнення FACK для TCP. Покращує стабільність TCP з'єднань.
      "net.ipv4.tcp_rfc1337"                        = "1";            # Вмикає захист від TCP атак, описаних в RFC 1337.
      "net.ipv4.tcp_sack"                           = "0";            # Вимкнення SACK для TCP. Зменшує складність обробки пакетів.
      "net.ipv4.tcp_syncookies"                     = "1";            # Увімкнення SYN cookies для захисту від SYN flood
      "net.ipv4.tcp_timestamps"                     = "1";            # Увімкнення TCP timestamp для покращення продуктивності. Дозволяє точніше визначати RTT.
      "net.ipv6.conf.all.accept_ra"                 = "0";            # Заборона прийому Router Advertisements. Запобігає несанкціонованій конфігурації мережі.
      "net.ipv6.conf.all.accept_ra_defrtr"          = "0";            # Заборона маршруту за замовчуванням для всіх інтерфейсів. Додатковий захист від атак через RA.
      "net.ipv6.conf.all.accept_ra_pinfo"           = "0";            # Заборона інформації про префікси для всіх інтерфейсів. Додатковий захист від атак через RA.
      "net.ipv6.conf.all.accept_ra_rtr_pref"        = "0";            # Заборона параметрів маршрутизатора для всіх інтерфейсів. Додатковий захист від атак через RA.
      "net.ipv6.conf.all.accept_redirects"          = "false";        # Не приймати IPv6 redirects. Це запобігає атакам маршрутизації.
      "net.ipv6.conf.all.accept_source_route"       = "0";            # Заборона IPv6 source routing. Аналогічний захист для IPv6.
      "net.ipv6.conf.all.autoconf"                  = "0";            # Вимкнення автоконфігурації для всіх інтерфейсів. Додатковий захист від атак через RA.
      "net.ipv6.conf.all.dad_transmits"             = "0";            # Вимкнення DAD для всіх інтерфейсів. Додаткове прискорення ініціалізації мережі.
      "net.ipv6.conf.all.forwarding"                = "0";            # Вимкнення IPv6 forwarding. Аналогічний захист для IPv6.
      "net.ipv6.conf.all.max_addresses"             = "1";            # Обмеження кількості адрес для всіх інтерфейсів. Додатковий захист від атак через багатоадресність.
      "net.ipv6.conf.all.router_solicitations"      = "0";            # Вимкнення router solicitations для всіх інтерфейсів. Додатковий захист від конфігурації.
      "net.ipv6.conf.default.accept_ra_defrtr"      = "0";            # Заборона отримання маршруту за замовчуванням через RA. Запобігає перенаправленню трафіку.
      "net.ipv6.conf.default.accept_ra_pinfo"       = "0";            # Заборона отримання інформації про префікси через RA. Запобігає конфігурації мережі зловмисниками.
      "net.ipv6.conf.default.accept_ra_rtr_pref"    = "0";            # Заборона отримання параметрів маршрутизатора через RA. Запобігає несанкціонованій зміні маршрутів.
      "net.ipv6.conf.default.accept_redirects"      = "false";        # те саме для IPv6 інтерфейсу за замовчуванням
      "net.ipv6.conf.default.accept_source_route"   = "0";            # Заборона IPv6 source routing за замовчуванням. Додатковий захист для IPv6.
      "net.ipv6.conf.default.autoconf"              = "0";            # Вимкнення автоматичної конфігурації IPv6. Запобігає несанкціонованій настройці мережі.
      "net.ipv6.conf.default.dad_transmits"         = "0";            # Вимкнення перевірки унікальності адрес (DAD). Зменшує час ініціалізації інтерфейсу.
      "net.ipv6.conf.default.forwarding"            = "0";            # Вимкнення forwarding для IPv6 за замовчуванням. Запобігає несанкціонованій передачі даних.
      "net.ipv6.conf.default.max_addresses"         = "1";            # Обмеження кількості IPv6 адрес на інтерфейсі. Запобігає атакам через багатоадресність.
      "net.ipv6.conf.default.router_solicitations"  = "0";            # Вимкнення router solicitations. Запобігає несанкціонованій конфігурації мережі.
      "net.ipv6.icmp.echo_ignore_all"               = "1";            # Ігнорування всіх ICMP IPv6 echo запитів. Запобігає DoS атакам через ping.
      "net.ipv6.icmp.echo_ignore_anycast"           = "1";            # Ігнорування anycast ICMPv6 echo. Запобігає атакам через anycast адреси.
      "net.ipv6.icmp.echo_ignore_multicast"         = "1";            # Ігнорування multicast ICMPv6 echo. Запобігає атакам через multicast адреси.
      "net.ipv6.default.accept_ra"                  = "0";            # Заборона RA за замовчуванням. Запобігає автоматичній конфігурації мережі.
      "vm.mmap_min_addr"                            = "65536";        # Мінімальна адреса для mmap. Запобігає атакам через нульові сторінки.
      "vm.mmap_rnd_bits"                            = "32";           # Рандомізація адресного простору. Ускладнює використання ROP-атак.
      "vm.mmap_rnd_compat_bits"                     = "16";           # Рандомізація для 32-бітних додатків. Аналогічний захист для 32-бітних програм.
      "vm.unprivileged_userfaultfd"                 = "0";            # Вимкнення userfaultfd для непривілейованих користувачів. Це покращує безпеку, запобігаючи використанню userfaultfd для атак.
      "vm.swappiness"                               = "10";           # Налаштування swappiness для зменшення використання swap
    };

    /* Бан-лист небезпечних або застрілих модулів ядра */
    blacklistedKernelModules = [
      # Застарілі мережеві протоколи
      "ax25" "netrom" "rose"

      # Блокування інтерфейсів передачі даних та бездротового зв'язку
      "bluetooth" "firewire-core" "thunderbolt"
      
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

    cleanTmpDir  = true;  # Очищення тимчасової директорії при кожному запуску системи
    tmpOnTmpfs   = true;  # Використання tmpfs для /tmp
  };

  # SYSTEMD SERVICES
  systemd = {
    extraConfig = ''
      DefaultTimeoutStartSec=15s
      DefaultTimeoutStopSec=15s
      DefaultRestartSec=5s
    '';
    
    services.coredump.enable = false;

    services.grafana.serviceConfig = {
      Restart        = "on-failure";  # Перезапуск при збоях
      RuntimeMaxSec  = 12h;           # Автовимкнення після 12 годин
    };

    services.prometheus.serviceConfig = {
      Restart = "no";  # Не перезапускати автоматично
    };

    services."borg-check" = {
      serviceConfig = {
        Type       = "oneshot";
        ExecStart  = "${pkgs.borgbackup}/bin/borg check /backup";
      };

      startAt = "weekly";
    };

    services.nginx.serviceConfig = {
      PrivateTmp = true;  # Використовувати ізольований /tmp
    };

    services.aide-init = {
      description = "Initialize AIDE database";
      serviceConfig = {
        Type           = "oneshot";
        ExecStart      = "${pkgs.aide}/bin/aide --init";
        ExecStartPost  = "${pkgs.coreutils}/bin/mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz";
      };

      wantedBy = [ "multi-user.target" ];
    };
  };



  # МЕРЕЖА
  networking = {
    hostName                     = "Rampart-Nix";  # Назва хоста
    networkmanager.enable        = true;           # Використання NetworkManager
    networkmanager.wifi.backend  = "iwd";          # Використання iwd як бекенду для Wi-Fi
    enableIPv6                   = true;           # Увімкнення IPv6
    tempAddresses                = "disabled";     # Вимкнення тимчасових адрес

    # Налаштування iwd для Wi-Fi з рандомізацією MAC-адрес
    wireless.iwd = {
      enable = true;
      settings = {
        General = {
          AddressRandomization    = "network";  # Рандомізація MAC-адрес для кожного мережевого підключення
        };

        Settings = {
          AlwaysRandomizeAddress  = true;       # Завжди рандомізувати MAC-адресу
        };
      };
    };

    # DNS-сервери
    nameservers = [
      "1.1.1.1" # Cloudflare
      "8.8.8.8" # Google Public DNS
      "9.9.9.9" # Quad9
    ];


    #БРАНДМАУЕР
    firewall = {
      enable         = true;   # Увімкнення брандмауера
      allowPing      = false;  # Заборона ping запитів
      rejectPackets  = true;   # Блокування замість відкидання пакетів
      # Дозволені TCP порти:
      allowedTCPPorts = [
        53    # DNS
        80    # HTTP
        443   # HTTPS
        # 737   # specific SSH port
        8080  # altHTTP
      ];

      # Дозволені UDP порти:
      allowedUDPPorts = [
        53    # DNS
        68    # DHCP
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

        iptables -A INPUT -p udp --dport 123 -s 192.168.1.0/24 -j ACCEPT
        iptables -A INPUT -p udp --dport 5353 -s 192.168.1.0/24 -j ACCEPT
        iptables -A INPUT -p udp --dport 123 -j DROP
        iptables -A INPUT -p udp --dport 5353 -j DROP
        
        iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
        ip6tables -A INPUT -p icmpv6 --icmpv6-type echo-request -j DROP
      '';

                      # Очищення правил IPtables при зупинці
      /*  Використовуємо iptables -F для видалення всіх правил у вказаних ланцюжках
          Використовуємо iptables -X для видалення всіх користувацьких ланцюжків
          Це забезпечує чистий стан мережевого фільтру при перезапуску системи
          та уникнення конфліктів між старими та новими правилами  */
      extraStopCommands = ''
        iptables -F
        iptables -X
      '';

      autoLoadConntrackHelpers  = false;    # Вимкнення автоматичного завантаження conntrack helpers
      checkReversePath          = "strict"; # Строга перевірка зворотнього шляху
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

      logRefusedConnections  = true;   # Логування відхилених з'єднань
      logReversePathDrops    = true;   # Логування відкинутих пакетів через зворотній шлях
      logIPv6Drops           = true;   # Логування відкинутих IPv6 пакетів
      logDenied              = "all";  # Журналювання всіх відхилених з'єднань
    };

    extraHosts = ''
      127.0.0.1 monitoring.local
      ::1 monitoring.local
    '';
  };



  # ЛОКАЛІЗАЦІЯ
  # Налаштування часового поясу та годинника
  time = {
    timeZone                  = "Europe/Kyiv";  # Встановлюємо часовий пояс Київ
    hardwareClockInLocalTime  = true;           # Годинник системи працює у локальному часі
  };

  # Налаштування локалізації та мови інтерфейсу
  i18n = {
    defaultLocale        = "uk_UA.UTF-8";                # Встановлюємо мову за замовчуванням (UTF-8 кодування)
    extraLocaleSettings  = { LC_ALL = "uk_UA.UTF-8"; };  # Встановлюємо мову для всіх категорій локалізації.
  };


            # КОНСОЛЬ
  /*  Налаштування консолі для системи. 
      Ці параметри обрано для забезпечення зрозумілого та послідовного вигляду текстового інтерфейсу.  */
  console = { 
    keyMap      = "us";            # Встановлюється "us" розкладка клавіатури, оскільки американська розкладка широко використовується та є стандартною.
    earlySetup  = true;            # Значення true гарантує, що налаштування консолі завантажуються на ранньому етапі старту системи, що покращує сумісність.
    font        = "sun12x22";      # Вказуємо шрифт для консолі. Обрано "sun12x22" через його високу читабельність.
    colors      = theme.colors16;  # Використання colors16 палітри кольорів для консолі, що дозволяє зберегти узгоджену колірну схему з іншими елементами системи.
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
          tappingDragLock   = false;  # Вимкнено функцію блокування перетягування при тапінгу. Це зменшує ризик випадкових дій під час роботи.
          naturalScrolling  = true;   # Вмикаємо "природне" прокручування. Збільшує інтуїтивність використання для більшості користувачів.
        };
      };
    };

    /*  Використовуємо sddm як дисплей менеджер та Plasma 6 як робоче середовище.
        SDDM обраний через його легкість, швидкодію та гарну інтеграцію з KDE Plasma.
        Plasma 6 обрана як стабільне та функціональне середовище з гарною підтримкою 
        та зручним користувацьким інтерфейсом.  */
    displayManager = {
      sddm.enable                    = true;  # Вмикаємо SDDM як менеджер дисплея
      desktopManager.plasma6.enable  = true;  # Вмикаємо KDE Plasma 6 як робоче середовище
    };


              # Налаштування АУДІО.
    /*  Вмикаємо Pipewire для обробки аудіо.
        Pipewire є сучасним рішенням, яке замінює старий PulseAudio, забезпечуючи більш стабільну 
        та гнучку обробку звуку. Ці налаштування обрані для досягнення низької латентності та сумісності 
        зі збільшеним спектром аудіо застосувань.
        pulseaudio.enable = false; - відмова від PulseAudio дозволяє уникнути конфліктів 
        з Pipewire між двома аудіосистемами та покращити продуктивність  */
    pulseaudio.enable   = false;  # Вимикаємо PulseAudio на користь Pipewire.
    pipewire = {
      enable             = true;   # Активуємо Pipewire як основну аудіосистему для сучасного оброблення звукових потоків
      alsa.enable        = true;   # ALSA забезпечує прямий доступ до апаратного забезпечення, що необхідно для сумісності з різними пристроями
      pulse.enable       = true;   # Емуляція PulseAudio забезпечує підтримку додатків, що розраховані на цей старіший інтерфейс, без необхідності їх модифікації
      alsa.support32Bit  = true;   # Ця опція важлива для сумісності з 32-бітними додатками, які можуть використовувати застарілі драйвери чи програмне забезпечення
      extraConfig.pipewire."92-low-latency" = {
        # Налаштування для зниження затримок аудіо сигналу, що важливо для забезпечення плавного відтворення звуку
        context.properties.default.clock = {
          rate         = 48000; # Встановлюємо частоту дискретизації в 48000 Гц для високоякісного аудіо
          quantum      = 32;    # Визначаємо розмір буфера обробки аудіо даних (quantum), що впливає на продуктивність та латентність
          min-quantum  = 32;    # Встановлюємо мінімальний розмір квантового буфера для стабільної роботи системи
          max-quantum  = 32;    # Встановлюємо максимальний розмір квантового буфера для уникнення надмірних затримок
        };
      };
    };


    # BACKUP
    /*  Ініціалізація сховища: 
          sudo -s
          borg init --encryption=repokey /backup

        Перевірка бекапів:
          borg list /backup

        Відновлення даних:
          borg extract /backup::<назва-бекапу> <шлях-для-відновлення>  */
    borgbackup = {
      jobs."system-backup" = {
        paths = [
          "/etc/nixos"  # Основна конфігурація NixOS
          "/var/lib"    # Дані служб та додатків
          "/home"       # Користувацькі дані
        ];

        exclude = [
          "*.tmp"           # Всі тимчасові файли
          "*.cache"         # Кеш-файли
          "/home/*/.cache"  # Користувацькі кеші
        ];

        repo = "/backup";  # Шлях до сховища бекапів
        # Шифрування для безпеки
        encryption = {
          mode        = "repokey";
          passphrase  = "...mysecretpassphrase...";
        };

        compression = "auto,zstd";                 # Автоматичний вибір алгоритму
        startAt   = "daily";                       # Щоденний бекап о 00:00
        preHook   = "systemctl stop postgresql";   # Зупинка служб перед бекапом
        postHook  = "systemctl start postgresql";  # Запуск служб після бекапу
        # Політика зберігання
        prune.keep = {
          daily    = 7;
          weekly   = 4;
          monthly  = 12;
        };
      };

      extraSettings = {
        "repository" = {
          "append_only"    = 1;       # Захист від випадкового видалення
          "storage_quota"  = "500G";  # Обмеження місця
        };
        
        "cache" = {
          "max_cache_age"  = "30d";   # Оновлення кешу
        };
      };
    };


    # ЛОКАЛЬНИЙ DNS
    dnsmasq = {
      enable = true;
      settings = {
        address         = "/monitoring.local/127.0.0.1";
        listen-address  = "127.0.0.1";
      };
    };


    # NTOPNG
    ntopng = {
      extraConfig = ''
        --interface=lo              # Аналіз лише локального трафіку
        --http-port=127.0.0.1:3001  # Правильне обмеження
        --disable-autologout
        --user=ntopng
      '';
    };


                          # ЖУРНАЛЮВАННЯ
    /*  Налаштування journald для журналювання подій системи.
        Вмикаємо аудит, стиснення логів, пересилання до syslog,
        встановлюємо обмеження на розмір та час зберігання файлів,
        а також інші параметри для оптимізації та безпеки.  */
    journald.extraConfig = ''
      Audit              =yes          # Вмикаємо аудит системи
      Compress           =yes          # Вмикаємо стиснення лог-файлів
      ForwardToSyslog    =yes          # Пересилаємо логи до syslog
      MaxLevelStore      =warning      # Максимальний рівень повідомлень, що зберігаються локально
      MaxLevelSyslog     =info         # Максимальний рівень повідомлень, що відправляються до syslog
      MaxRetentionSec    =30day        # Максимальний час зберігання логів - 30 днів
      RateLimitBurst     =100          # Кількість повідомлень перед застосуванням обмеження швидкості
      RateLimitInterval  =30s          # Інтервал часу для обмеження швидкості
      RuntimeKeepFree    =200M         # Мінімальний вільний простір для runtime логів
      RuntimeMaxUse      =100M         # Максимальний розмір runtime логів
      Seal               =yes          # Захист цілісності логів
      Storage            =persistent   # Зберігання логів на постійному носії
      SystemKeepFree     =1G           # Мінімальний вільний простір для системних логів
      SystemMaxFiles     =100          # Максимальна кількість системних лог-файлів
      SystemMaxUse       =500M         # Максимальний розмір системних логів
    '';


    # МОНІТОРИНГ ЛОГІВ
    # Система збору метрик
    prometheus = {
      enable                       = true;
      retentionTime                = "720h";  # 30 днів
      storage.tsdb.retention.size  = "10GB";  # Для SSD
      exporters = {
        node = {
          enable             = true;
          enabledCollectors  = [ "systemd" "logind" "network" ];
          openFirewall       = false;
        };
      };

      scrapeConfigs = [
        {
          job_name        = "nixos";
          static_configs  = [{ targets = [ "localhost:9100" ]; }];
        }
        # Додано інтеграцію з Loki
        {
          job_name = "loki";
          static_configs = [{ targets = [ "localhost:3100" ]; }];
        }
      ];
    };


    # Візуалізація логів Grafana
    grafana = {
      enable = true;
      provision = {
        alerting = {
          contactPoints = [{
            name          = "local-alerts";
            type          = "webhook";
            settings.url  = "http://localhost:9093/alertmanager";
          }];
        };
      };

      settings = {
        server = {
          http_addr  = "127.0.0.1";
          http_port  = 4000;
          domain     = "localhost";
        };
        # Додано інтеграцію з Prometheus та Loki
        "datasources.yaml" = {
          apiVersion = 1;
          datasources = [
            {
              name = "Prometheus";
              type = "prometheus";
              url = "http://localhost:9090";
            },
            {
              name = "Loki";
              type = "loki";
              url = "http://localhost:3100";
            }
          ];
        };
        
        alerting = {
          enabled         = true;
          execute_alerts  = true;
        };

        database = {
          max_open_conn      = 25;     # Оптимально для SSD
          conn_max_lifetime  = 14400;  # 4 години
        };
      };
    };


    # Централізоване зберігання логів
    loki = {
      enable = true;
      configuration = {
        auth_enabled = false;
        ingester = {
          lifecycler = {
            address  = "127.0.0.1";
            ring     = { kvstore = { store = "inmemory"; }; };
          };
        };
      };
    };


    # AIDE
    aide = {
      enable = true;                                        # Вимикаємо зовнішні сповіщення
      reportPath   = "/var/log/aide/report-$(date +%Y-%m-%d).txt";
      extraConfig = ''
        !define DBdir      /var/lib/aide
        !define LOGdir     /var/log/aide
        database          =file:${DBdir}/aide.db.gz
        database_out      =file:${DBdir}/aide.db.new.gz
        /var/lib/aide/daily.db.gz
        /var/lib/aide/aide.db.gz
      '';

      cron = {
        enable  = true;
        at      = "daily";  # Щоденна перевірка
      };

      initOnStartup = true;  # Автоматичне оновлення бази даних після встановлення оновлень
      # Налаштування електронної пошти для сповіщень
      mail = {
        enable     = true;
        recipient  = "root@localhost";
      };
    };

    # Збір та аналіз логів
    promtail = {
      enable = true;
      configuration = {
        server   = { http_listen_port = 9080; };
        clients  = [{ url = "http://localhost:3100/loki/api/v1/push"; }];
        scrape_configs = [
          {
            job_name  = "journal";
            journal   = { max_age = "12h"; };
            relabel_configs = [
              {
                source_labels  = ["__journal__hostname"];
                target_label   = "host";
              }
            ];
          }
        ];
      };

      openFirewall = false;
    };


    # NGINX
    nginx = {
      enable                  = true;
      recommendedTlsSettings  = true;
      virtualHosts = {
        "monitoring.local" = {
          serverName = "monitoring.local";
          listen = [{ 
            addr  = "127.0.0.1"; 
            port  = 443; 
            ssl   = true; 
          }];

          sslCertificate     = "/var/lib/acme/monitoring.local/fullchain.pem";
          sslCertificateKey  = "/var/lib/acme/monitoring.local/key.pem";
          locations."/" = {
            proxyPass        = "http://localhost:4000";  # Grafana на порту 4000
            proxyWebsockets  = true;
            extraConfig = ''
              allow 192.168.1.0/24;  # Локальна мережа
              deny all;
            '';
          };
        };
      };
    };


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


    cron = {
      enable = true;
      systemCronJobs = [
        "30 23 * * * root /path/to/backup-script"  # Щоденний бекап о 23:30 (якщо система активна)
        "@reboot root rm -rf /tmp/*"               # Очищення тимчасових файлів при запуску
      ];
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



                      # КОРИСТУВАЧІ
  /*  Вимкнення можливості зміни користувачів через NixOS
      Це забезпечує імутабельність користувачів та їх налаштувань  */
  users.mutableUsers = false;

  # Основна конфігурація користувача
  users.users.oleksandr = {
    isNormalUser    = true;         # Вказуємо, що це звичайний користувач (не системний)
    description     = "oleksandr";  # Опис користувача
    
    # Хешований пароль
    hashedPassword  = "...";
    
    # Додаткові групи для надання прав доступу:
    /*  wheel - права адміністратора через sudo
        video - доступ до графічного обладнання
        audio - доступ до аудіо системи
        networkmanager - управління мережевими з'єднаннями
        libvirt, kvm - віртуалізація через KVM  */
    extraGroups     = [ "wheel" "video" "audio" "networkmanager" "libvirt" "kvm" ];
    
    # Пакети, які будуть встановлені лише для цього користувача
    packages = with pkgs; [
      telegram-desktop
    ];
  };



  # БЕЗПЕКА
  # Хешований root пароль 
  users.users.root.hashedPassword = "...";

  security = {
    # Налаштування sudo
    sudo = {
      enable          = true;  # Вмикаємо sudo
      execWheelOnly   = true;  # Дозволяємо виконання sudo лише користувачам з групи wheel
      extraConfig = ''
        Defaults insults                 # Додаємо образливі повідомлення при невдалій спробі sudo
        Defaults passwd_timeout     =25  # Час очікування введення пароля
        Defaults timestamp_timeout  =15  # Час дії кешування пароля
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
    unprivilegedUsernsClone           = false;    # Заборона створення user namespaces для непривілейованих користувачів.
    virtualisation.flushL1DataCache   = "always"; # Очищення кешу L1 для запобігання атак типу L1TF

    # Налаштування PAM (Pluggable Authentication Modules)
    pam = {
      services = {
        login = {
          enableKrb5          = false;    # Вимкнення Kerberos для входу
          allowNullPasswords  = false;    # Заборона пустих паролів
          failDelay           = 400;      # Затримка після невдалої спроби входу
          maxRetries          = 3;        # Максимальна кількість спроб входу
          unlockTime          = 600;      # Час блокування облікового запису після невдалих спроб
        };
        
        sudo.enableKrb5  = false;  # Вимкнення Kerberos для sudo
        sshd.enableKrb5  = false;  # Вимкнення Kerberos для SSH
      };

      # Обмеження ресурсів для користувачів
      loginLimits = [
        { domain = "*"; type = "hard"; item = "nofile"; value = "1024"; }  # Максимум відкритих файлів
        { domain = "*"; type = "hard"; item = "nproc"; value = "512"; }    # Максимум процесів
      ];
    };
    
    rtkit.enable = true;  # Вмикаємо rtkit для процесів у реальному часі

    # Налаштування AppArmor для контролю доступу
    apparmor = {
      enable                     = true;                                            # Вмикаємо AppArmor
      killUnconfinedConfinables  = true;                                            # Завершувати процеси, які повинні бути обмежені, але не є
      packages                   = [ pkgs.apparmor-profiles pkgs.apparmor-utils ];  # Встановлюємо профілі та утиліти
      
      # Завантаження профілів AppArmor
      profiles = [
        # Стандартні профілі для системних сервісів
        {
          name    = "usr.bin.firefox";
          profile = "${pkgs.apparmor-profiles}/etc/apparmor.d/usr.bin.firefox";
        }
        {
          name    = "usr.sbin.nginx";
          profile = "${pkgs.apparmor-profiles}/etc/apparmor.d/usr.sbin.nginx";
        }
        {
          name    = "usr.sbin.ntpd";
          profile = "${pkgs.apparmor-profiles}/etc/apparmor.d/usr.sbin.ntpd";
        }
        {
          name    = "usr.sbin.sshd";
          profile = "${pkgs.apparmor-profiles}/etc/apparmor.d/usr.sbin.sshd";
        }
        # Профілі для віртуалізації
        {
          name    = "usr.sbin.libvirtd";
          profile = "${pkgs.apparmor-profiles}/etc/apparmor.d/usr.sbin.libvirtd";
        }
        {
          name    = "virt-aa-helper";
          profile = "${pkgs.apparmor-profiles}/etc/apparmor.d/usr.lib.libvirt.virt-aa-helper";
        }
        # Власний профіль для Grafana
        {
          name    = "grafana";
          profile = ''
            #include <tunables/global>

            profile grafana flags=(attach_disconnected) {
              #include <abstractions/base>
              #include <abstractions/nameservice>
              #include <abstractions/openssl>

              # Дозволи для виконуваних файлів
              ${pkgs.grafana}/bin/grafana-server mr,
              ${pkgs.grafana}/bin/grafana-cli mr,

              # Дозволи для конфігураційних файлів
              /etc/grafana/** r,
              /var/lib/grafana/** rwk,
              /var/log/grafana/** rwk,

              # Мережеві дозволи
              network tcp,
              network udp,

              # Дозволи для тимчасових файлів
              owner /tmp/** rwk,
              owner /var/tmp/** rwk,

              # Дозволи для системних файлів
              /proc/sys/net/core/somaxconn r,
              /sys/kernel/mm/transparent_hugepage/enabled r,
            }
          '';
        }
        # Власний профіль для Prometheus
        {
          name    = "prometheus";
          profile = ''
            #include <tunables/global>

            profile prometheus flags=(attach_disconnected) {
              #include <abstractions/base>
              #include <abstractions/nameservice>

              # Дозволи для виконуваних файлів
              ${pkgs.prometheus}/bin/prometheus mr,

              # Дозволи для конфігураційних файлів
              /etc/prometheus/** r,
              /var/lib/prometheus/** rwk,

              # Мережеві дозволи
              network tcp,
              network udp,

              # Дозволи для тимчасових файлів
              owner /tmp/** rwk,
              owner /var/tmp/** rwk,
            }
          '';
        }
      ];
    };


    # TLS СЕРТИФІКАТИ (ЛОКАЛЬНІ)
    acme = {
      acceptTerms = true;
      certs."monitoring.local" = {
        domain = "monitoring.local";
        # Використовуємо самопідписані сертифікати
        credentialsFile = "/var/lib/acme/self-signed-credentials";
        # Генерація самопідписаного сертифіката
        postRun = ''
          ${pkgs.openssl}/bin/openssl req -x509 -nodes -days 365 \
            -newkey rsa:2048 \
            -keyout ${config.security.acme.certs."monitoring.local".directory}/key.pem \
            -out ${config.security.acme.certs."monitoring.local".directory}/cert.pem \
            -subj "/CN=monitoring.local"
        '';
      };
    };
  };


  environment.etc = {
    # Заборона входу root через TTY
    securetty.text = ''
      # /etc/securetty: list of terminals on which root is allowed to login.
    '';

    # Встановлення статичного machine-id для покращення конфіденційності
    machine-id.text = ''
      4e8b0b4e0ef1f0e5d2c8d39f8c77f6b3
    '';
  };



  # ПАМ'ЯТЬ
  environment.memoryAllocator.provider  = "scudo";           # Використання scudo як аллокатора пам'яті для підвищення безпеки
  environment.variables.SCUDO_OPTIONS   = "ZeroContents=1";  # Налаштування scudo для ініціалізації пам'яті нулями
  zramSwap = {
    enable         = true;
    algorithm      = "zstd";  # Найкраща стиснення
    memoryPercent  = 25;      # Чверть(1/4) від загального обсягу оперативної пам'яті
  };

  /*    Перевірка розміру
          df -h /tmp

        Перегляд inode
          df -i /tmp

        Деталі монтування
          findmnt -T /tmp
  
      Перевірка статусу:
        mount | grep /tmp
          # tmpfs on /tmp type tmpfs (rw,nosuid,nodev,noexec,relatime,size=4096M,mode=1777)
      
      Зміна розміру під час роботи:
        sudo mount -o remount,size=8G /tmp
      
      Створення резервної копії:
        tar -czf /persistent/tmp-backup.tar.gz -C /tmp .  */
  fileSystems."/tmp" = {
    device  = "none";   # Спеціальне значення для tmpfs
    fsType  = "tmpfs";
    # Основні параметри монтування
    options = [
      "encrypted"
      "mode=1777"         # Права доступу (sticky bit + rwx для всіх)
      "nodev"             # Заборона спеціальних пристроїв
      "noexec"            # Заборона виконання файлів
      "nosuid"            # Заборона SUID/SGID бітів
      "nr_inodes=1M"      # Максимальна кількість inode
      "size=4G"           # Максимальний розмір 2 ГБ
    ];

    # Додаткові параметри безпеки
    neededForBoot  = false;  # Не потрібен під час завантаження
    noCheck        = true;   # Пропустити fsck
  };



  # NIX
  nix = {
    settings = {
    /*  Включення експериментальних функцій:
        nix-command: дозволяє використовувати нову команду nix
        flakes: впроваджує нову модель управління пакетами  */
    extra-experimental-features = [ "nix-command" "flakes" ];

    sandbox              = true; # Увімкнення пісочниці для більшої безпеки під час збірки пакетів
    auto-optimise-store  = true; # Автоматична оптимізація сховища для зменшення використання дискового простору

    /*  Користувачі, яким дозволено виконувати привілейовані операції:
        - root: системний адміністратор
        - @wheel: користувачі з правами адміністратора  */
    trusted-users  = [ "root" "@wheel" ];
    allowed-users  = [ "root" "@wheel" ];
    };
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

    # Інструмент для виявлення вторгнень
    audit
    aide
    lynis
    osquery

    ntopng
    
    # Дисковий простір
    gparted
    ntfs-3g

    # Відео
    obs-studio
  ];



  # ВІРТУАЛІЗАЦІЯ
  virtualisation = {
    useEFIBoot     = true;
    useSecureBoot  = true;
    # Налаштування libvirt для керування віртуалізацією
    libvirtd = {
      enable      = true;           # Увімкнення служби libvirt
      onBoot      = "ignore";       # Не запускати віртуальні машини автоматично при завантаженні
      onShutdown  = "shutdown";     # Завершувати віртуальні машини при вимкненні системи
      
      qemu = {
        package            = pkgs.qemu_kvm;    # Використання KVM для апаратного прискорення
        runAsRoot          = false;            # Запуск QEMU без прав root
        swtpm.enable       = true;             # Увімкнення підтримки TPM
        vhostUserPackages  = [pkgs.virtiofsd]; # Підтримка virtiofsd
        ovmf = {
          enable = true; # Увімкнення OVMF для UEFI
          packages = [
            (pkgs.OVMF.override {
              secureBoot  = true; # Увімкнення Secure Boot
              tpmSupport  = true; # Підтримка TPM
            }).fd
          ];
        };
      };

      extraConfig = ''
        security_default_confined  = 1            # Увімкнення захисту за замовчуванням
        security_driver            = "apparmor"   # Використання AppArmor для захисту
        user                       = "oleksandr"  # Користувач для запуску віртуальних машин
        group                      = "libvirt"    # Виправлено групу для запуску віртуальних машин
        dynamic_ownership          = 1            # Динамічне призначення власника файлів
        remember_owner             = 1            # Запам'ятовування власника файлів

        # Дозволені пристрої для cgroup
        cgroup_device_acl = [
          /dev/null /dev/full /dev/zero
          /dev/random /dev/urandom
          /dev/ptmx /dev/kvm
        ]

        seccomp_sandbox     = 1                          # Увімкнення захисту через seccomp
        memory_backing_dir  = "/var/lib/libvirt/memory"  # Директорія для файлів підкачки
        cgroup_controllers  = [ "cpu" "memory" "pids" ]  # Контролери ресурсів
      '';

      # Дозволені мережеві мости для віртуальних машин
      allowedBridges = [ "virbr0" "br0" ];
    };

    # Налаштування мережі за замовчуванням для віртуальних машин
    defaultNetwork = {
      enable       = true;     # Увімкнення мережі за замовчуванням
      name         = "virbr0"; # Ім'я мережевого інтерфейсу
      forwardMode  = "nat";    # Використання NAT для виходу в інтернет
    };
  };



  system.stateVersion = "24.11";
}
