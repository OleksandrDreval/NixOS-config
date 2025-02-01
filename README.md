# NixOS Безпечна Конфігурація ![NixOS](https://img.shields.io/badge/NixOS-24.11-blue.svg)

**Декларативна система з фокусом на безпеку.**  
*Останнє оновлення: 01/02/2025*

---

## 🔐 Ключові особливості безпеки

### 1. Захист завантажувального середовища

```nix
boot.initrd.luks.devices."luks-911765a7-6ecb-4c99-88ef-b44c26fd3583".device = "/dev/disk/by-uuid/911765a7-6ecb-4c99-88ef-b44c26fd3583";
boot.initrd.systemd.enable = true; # Використання systemd-initrd
boot.loader.efi.canTouchEfiVariables = false; # Заборона зміни EFI змінних
```

- **LUKS2** шифрування диска з використанням UUID для ідентифікації розділу.
- `systemd-initrd` для швидкого та безпечного завантаження.
- Заборона зміни EFI змінних для запобігання несанкціонованим модифікаціям.
- Secure Boot через пакет `sbctl` для захисту від завантаження шкідливого коду.


### 2. Параметри ядра Linux

```nix
boot.kernelParams = [
  "kernel.printk=\"3 4 1 3\"" # Контроль виводу ядра
  "slab_nomerge" # Захист від heap експлоїтів
  "page_poison=1" # Захист від використання звільненої пам'яті
  "l1tf=full,force" # Захист від L1 Terminal Fault
  "mds=full,nosmt" # Захист від Microarchitectural Data Sampling
  "spectre_v2=on" # Захист від Spectre v2
  "spec_store_bypass_disable=on" # Захист від Spectre Variant 4: Speculative Store Bypass
  "stf_barrier=on" # Бар'єр для Spectre Variant 4
  "module.sig_enforce=1" # Примусове підписування модулів ядра
  "randomize_kstack_offset=on" # Рандомізація зміщення стеку ядра
  "pti=on" # Page Table Isolation
  "vsyscall=none" # Відключення vsyscall
  "debugfs=off" # Відключення debugfs
  "lockdown=confidentiality" # Режим блокування ядра
  "usercopy=strict" # Строгий режим копіювання даних з/до простору користувача
];
```

- Розширений набір параметрів ядра для захисту від різних типів атак, включаючи Spectre, Meltdown, та інші.
-  `lockdown=confidentiality` для максимального обмеження доступу до ядра.
-  `module.sig_enforce=1` гарантує, що завантажуються тільки підписані модулі ядра.


### 3. Мережева безпека

```nix
networking.firewall.enable = true;
networking.firewall.allowedTCPPorts = [ 53 80 123 443 8080 8443 5353 ];
networking.firewall.allowedUDPPorts = [ 53 67 68 123 5353 ];
networking.firewall.logRefusedConnections = true; # Логування відхилених з'єднань
networking.firewall.allowPing = false; # Заборона ping
networking.firewall.logIPv6Drops = true; # Логування відкинутих IPv6 пакетів
# Додаткові правила iptables для блокування підозрілих пакетів
networking.firewall.extraCommands = ''
  ...
'';
```

- Stateful firewall з обмеженим набором дозволених портів.
-  `logRefusedConnections` для відстеження спроб несанкціонованого доступу.
-  `allowPing = false` для зменшення видимості системи в мережі.
-  Додаткові правила `iptables` для блокування підозрілих TCP-флагів та інших аномалій.


### 4. Системний моніторинг

```nix
services.journald.extraConfig = ''
  Storage=persistent # Зберігання журналів на диску
  SystemMaxUse=500M # Максимальний розмір журналів
  ForwardToSyslog=yes # Пересилання журналів до syslog
  Compress=yes # Стиснення журналів
  Seal=yes # Підпис журналів
  Audit=yes # Інтеграція з auditd
  ...
'';

security.auditd.enable = true;
security.audit.enable = true;
security.audit.rules = [
  "-a always,exit -F arch=b64 -S execve -k process_execution" # Відстеження запуску програм
  "-a always,exit -F arch=b64 -S bind -k network_bind" # Моніторинг мережевих з'єднань (bind)
  "-a always,exit -F arch=b64 -S connect -k network_connect" # Моніторинг мережевих з'єднань (connect)
];
```

- `journald` налаштовано для постійного зберігання журналів, стиснення та підпису.
- Інтеграція з `auditd` для детального аудиту системних подій.
-  Правила `auditd` для відстеження запуску програм та мережевої активності.


### 5. Віртуалізація

```nix
virtualisation.libvirtd.enable = true;
virtualisation.libvirtd.extraConfig = ''
  security_driver = "selinux" # Використання SELinux
  seccomp_sandbox = 1 # Пісочниця seccomp
  ...
'';
```

- `libvirtd` з використанням SELinux для ізоляції віртуальних машин.
- `seccomp` пісочниця для обмеження системних викликів віртуальних машин.
-  Додаткові налаштування безпеки `libvirtd` для обмеження доступу до ресурсів системи.

---

## 📊 Архітектура безпеки
