# NixOS Безпечна Конфігурація ![NixOS](https://img.shields.io/badge/NixOS-24.11-blue.svg)

**Декларативна система з фокусом на безпеку.**  
*Останнє оновлення: 01/02/2025*

---

## 🔐 Ключові особливості безпеки та структура конфігурації

Цей документ описує ключові аспекти безпеки конфігурації NixOS, а також структуру самого конфігураційного файлу `configuration.nix`.

### Структура `configuration.nix`

Файл `configuration.nix` організовано за логічними блоками, що відповідають за різні аспекти системи.  Кожен блок містить опції, які налаштовують певну функціональність. Наприклад, блок `boot` відповідає за налаштування завантаження, `networking` - за мережу, `services` - за служби, `security` - за безпеку, `virtualisation` - за віртуалізацію, тощо.  Така структура забезпечує модульність та легкість в управлінні конфігурацією.

### 1. Захист завантажувального середовища (`boot`)

```nix
boot.initrd.luks.devices."luks-911765a7-6ecb-4c99-88ef-b44c26fd3583".device = "/dev/disk/by-uuid/911765a7-6ecb-4c99-88ef-b44c26fd3583";
boot.initrd.systemd.enable = true;
boot.loader.efi.canTouchEfiVariables = false;
boot.loader.systemd-boot.enable = true;
boot.loader.timeout = 10;
```

- **LUKS2 шифрування:**  Диск зашифровано за допомогою LUKS2.  Використання UUID для ідентифікації розділу запобігає проблемам, пов'язаним зі зміною імен пристроїв.
- **systemd-initrd:** Використання `systemd-initrd` забезпечує швидке та безпечне завантаження.
- **Заборона зміни EFI змінних:**  `boot.loader.efi.canTouchEfiVariables = false` запобігає несанкціонованим модифікаціям EFI.
- **systemd-boot:**  Використання `systemd-boot` як завантажувача.
- **Таймаут завантажувача:** 10 секунд (`boot.loader.timeout`).


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

- **Захист від експлоїтів:**  `slab_nomerge`, `page_poison=1` ускладнюють експлуатацію вразливостей, пов'язаних з керуванням пам'яттю.
- **Захист від атак на мікроархітектуру:** `l1tf=full,force`, `mds=full,nosmt`, `spectre_v2=on`, `spec_store_bypass_disable=on`, `stf_barrier=on` пом'якшують вплив атак Spectre та Meltdown.
- **Підписування модулів ядра:** `module.sig_enforce=1` гарантує завантаження тільки підписаних модулів.
- **Рандомізація стеку:** `randomize_kstack_offset=on` ускладнює експлуатацію вразливостей, пов'язаних зі стеком.
- **Ізоляція таблиць сторінок:** `pti=on` підвищує безпеку віртуалізації.
- **Безпека ядра:** `vsyscall=none`, `debugfs=off`  зменшують площу атаки ядра.
- **Режим блокування:** `lockdown=confidentiality` максимально обмежує доступ до ядра.
- **Строгий режим копіювання:** `usercopy=strict`  забезпечує безпечніше копіювання даних між простором користувача та ядром.

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

- **Stateful firewall:**  `networking.firewall.enable = true` активує stateful firewall.
- **Обмеження портів:**  `allowedTCPPorts` та `allowedUDPPorts` обмежують доступні порти.
- **Логування:** `logRefusedConnections`  дозволяє відстежувати спроби несанкціонованого доступу.
- **Заборона ping:** `allowPing = false` зменшує видимість системи.
- **Логування IPv6:** `logIPv6Drops` логує відкинуті IPv6 пакети.
- **Додаткові правила:**  `extraCommands` (не показано) дозволяє додавати власні правила iptables.


###  4. Віртуалізація (`virtualisation.libvirtd`)

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

- **SELinux:** `security_driver = "selinux"`  використовує SELinux для ізоляції віртуальних машин.
- **Seccomp пісочниця:** `seccomp_sandbox = 1` обмежує системні виклики віртуальних машин.
- **Обмеження доступу:**  `security_default_confined`, `user`, `group`, `dynamic_ownership`, `remember_owner`, `cgroup_device_acl` обмежують доступ віртуальних машин до ресурсів системи.
- **USB перенаправлення:** `spiceUSBRedirection.enable` дозволяє перенаправляти USB пристрої до віртуальних машин.


