# NixOS Безпечна Конфігурація ![NixOS](https://img.shields.io/badge/NixOS-24.11-blue.svg)

**Декларативна система з фокусом на безпеку.**
*Останнє оновлення: 01/02/2025*

---

## 🔐 Ключові особливості безпеки та структура конфігурації

Цей документ описує ключові аспекти безпеки конфігурації NixOS, а також структуру самого конфігураційного файлу `configuration.nix`.  Детальніше про конфігурацію NixOS можна дізнатися з [офіційної документації](https://nixos.org/manual/nixos/stable/).  Для додаткових прикладів та натхнення, зверніться до [NixOS Configuration Collection](https://github.com/NixOS/nixpkgs/tree/master/nixos/modules).  Питання безпеки в NixOS детально розглянуті в розділі [Security](https://nixos.org/manual/nixos/stable/#sec-hardening) офіційної документації.

### Структура `configuration.nix`

Файл `configuration.nix` організовано за логічними блоками, що відповідають за різні аспекти системи. Кожен блок містить опції, які налаштовують певну функціональність. Наприклад, блок `boot` відповідає за налаштування завантаження, `networking` - за мережу, `services` - за служби, `security` - за безпеку, `virtualisation` - за віртуалізацію тощо. Така структура забезпечує модульність та легкість в управлінні конфігурацією.

### 1. Захист завантажувального середовища (`boot`)

```nix
boot.initrd.luks.devices."luks-911765a7-6ecb-4c99-88ef-b44c26fd3583".device = "/dev/disk/by-uuid/911765a7-6ecb-4c99-88ef-b44c26fd3583";
boot.initrd.systemd.enable = true;
boot.loader.efi.canTouchEfiVariables = false;
boot.loader.systemd-boot.enable = true;
boot.loader.timeout = 10;
```

- **LUKS2 шифрування (**`boot.initrd.luks.devices."luks-UUID".device`**):** Шифрує кореневий розділ за допомогою LUKS2, захищаючи дані навіть при фізичному викраденні. Використання UUID (Universally Unique Identifier) замість назви пристрою (/dev/sda1) гарантує коректне завантаження навіть після змін в порядку пристроїв.  [Докладніше про LUKS в NixOS](https://nixos.org/manual/nixos/stable/#module-boot-initrd-luks).
- **systemd-initrd (**`boot.initrd.systemd.enable`**):** Використання systemd в initrd забезпечує швидке та безпечне завантаження, оскільки systemd керує ініціалізацією ще до монтування кореневої файлової системи, мінімізуючи час вразливості. [Детальніше про systemd-initrd](https://nixos.org/manual/nixos/stable/#module-boot-initrd-systemd).
- **Заборона зміни EFI змінних (**`boot.loader.efi.canTouchEfiVariables`**):**  Запобігає несанкціонованій зміні EFI (Extensible Firmware Interface), захищаючи від зловмисного ПЗ, яке може спробувати змінити процес завантаження.  [Більше про EFI в NixOS](https://nixos.org/manual/nixos/stable/#module-boot-loader-efi).
- **systemd-boot (**`boot.loader.systemd-boot.enable`**):** Використання systemd-boot як завантажувача спрощує та захищає процес завантаження. [Детальніше про systemd-boot](https://nixos.org/manual/nixos/stable/#module-boot-loader-systemd-boot).
- **Таймаут завантажувача (**`boot.loader.timeout`**):**  10 секунд - час очікування вибору опцій завантаження.  Короткий таймаут зменшує можливість несанкціонованого втручання.


### 2. Параметри ядра Linux (`boot.kernelParams`)

```nix
boot.kernelParams = [
  "kernel.printk=\"3 4 1 3\""
  "slab_nomerge"
  "page_poison=1"
  "l1tf=full,force"
  "mds=full,nosmt"
  "spectre_v2=on"
  "spec_store_bypass_disable=on"
  "stf_barrier=on"
  "module.sig_enforce=1"
  "randomize_kstack_offset=on"
  "pti=on"
  "vsyscall=none"
  "debugfs=off"
  "lockdown=confidentiality"
  "usercopy=strict"
];
```

- **`kernel.printk="3 4 1 3"`:** Налаштування рівня деталізації повідомлень ядра (не критично для безпеки, але корисно для діагностики).  [Kernel parameters documentation](https://www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html)
- **`slab_nomerge`**: Ускладнює деякі типи експлойтів, запобігаючи об'єднанню частково використаних блоків пам'яті.
- **`page_poison=1`**: Заповнює звільнену пам'ять спеціальним значенням, ускладнюючи експлойти, пов'язані з доступом до неініціалізованої пам'яті.
- **Захист від атак на мікроархітектуру:**
    - **`l1tf=full,force`**:  Захист від L1 Terminal Fault.
    - **`mds=full,nosmt`**: Захист від Microarchitectural Data Sampling.
    - **`spectre_v2=on`**:  Захист від Spectre Variant 2.
    - **`spec_store_bypass_disable=on`**:  Вимкнення Speculative Store Bypass.
    - **`stf_barrier=on`**:  Вмикає STF barriers.
  Ці опції зменшують продуктивність, але суттєво підвищують безпеку, захищаючи від атак Spectre та Meltdown.
- **`module.sig_enforce=1`**:  Дозволяє завантаження лише підписаних модулів ядра, запобігаючи завантаженню зловмисного коду.
- **`randomize_kstack_offset=on`**: Рандомізує розташування стеку ядра, ускладнюючи експлойти переповнення буфера стеку.
- **`pti=on`**: Page Table Isolation - розділяє таблиці сторінок ядра та користувача, ускладнюючи атаки Meltdown.
- **`vsyscall=none`**:  Вимикає vsyscall - застарілий механізм системних викликів, який може бути використаний для атак.
- **`debugfs=off`**: Вимкнення debugfs, яка може містити конфіденційну інформацію.
- **`lockdown=confidentiality`**:  Максимально обмежує доступ до ядра після завантаження, захищаючи від зловмисного ПЗ. [Докладніше про Lockdown mode](https://www.kernel.org/doc/html/latest/admin-guide/lockdown.html)
- **`usercopy=strict`**:  Забезпечує безпечніше копіювання даних між простором користувача та ядром, перевіряючи адреси пам'яті.

### 3. Мережева безпека (`networking.firewall`)

```nix
networking.firewall.enable = true;
networking.firewall.allowedTCPPorts = [ 53 80 123 443 8080 8443 5353 ];
networking.firewall.allowedUDPPorts = [ 53 67 68 123 5353 ];
networking.firewall.logRefusedConnections = true;
networking.firewall.allowPing = false;
networking.firewall.logIPv6Drops = true;
# networking.firewall.extraCommands = '' ... '';
```

- **`networking.firewall.enable = true`**:  Вмикає stateful firewall, який відстежує з'єднання та блокує несанкціоновані пакети. [Firewall documentation](https://nixos.org/manual/nixos/stable/#module-firewall)
- **`allowedTCPPorts` / `allowedUDPPorts`**:  Списки дозволених портів TCP та UDP.  Обмежує доступ до служб лише необхідними портами (80 - HTTP, 443 - HTTPS, 53 - DNS, 123 - NTP,  8080/8443 - альтернативні HTTP/HTTPS, 5353 - mDNS).
- **`logRefusedConnections = true`**:  Логує відхилені з'єднання для аналізу та виявлення загроз.
- **`allowPing = false`**:  Забороняє відповіді на ICMP ping, зменшуючи видимість системи в мережі.
- **`logIPv6Drops = true`**:  Логує відкинуті IPv6 пакети.
- **`extraCommands`**:  Дозволяє додавати власні правила iptables для гнучкішого налаштування firewall.

### 4. Віртуалізація (`virtualisation.libvirtd`)

```nix
virtualisation.libvirtd.enable = true;
virtualisation.libvirtd.extraConfig = ''
  security_driver = "selinux"
  seccomp_sandbox = 1
  security_default_confined = 1
  user = "libvirt-qemu"
  group = "libvirt-qemu"
  dynamic_ownership = 1
  remember_owner = 1
  cgroup_device_acl = [
    /dev/null /dev/full /dev/zero
    /dev/random /dev/urandom
    /dev/ptmx /dev/kvm
  ]
  memory_backing_dir = "/var/lib/libvirt/memory"
'';
virtualisation.spiceUSBRedirection.enable = true;
```

- **`virtualisation.libvirtd.enable = true`**:  Вмикає libvirtd daemon. [Libvirt documentation](https://nixos.org/manual/nixos/stable/#module-libvirtd)
- **`security_driver = "selinux"`**: Використовує SELinux для ізоляції віртуальних машин, обмежуючи можливості зловмисного ПЗ.
- **`seccomp_sandbox = 1`**:  Вмикає seccomp пісочницю, обмежуючи системні виклики віртуальних машин.
- **`security_default_confined = 1`**: Запускає ВМ в обмеженому середовищі.
- **`user = "libvirt-qemu"` / `group = "libvirt-qemu"`**:  Визначає користувача та групу для запуску ВМ.
- **`dynamic_ownership = 1` / `remember_owner = 1`**: Дозволяє libvirtd динамічно змінювати власника файлів ВМ.
- **`cgroup_device_acl`**:  Список пристроїв, доступних ВМ. Обмежує доступ ВМ до ресурсів системи.
- **`memory_backing_dir`**: Директорія для файлів підтримки пам'яті ВМ.
- **`virtualisation.spiceUSBRedirection.enable = true`**: Дозволяє перенаправлення USB до ВМ (зручно, але потенційно ризиковано).


