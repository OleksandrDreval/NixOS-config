# NixOS Безпечна Конфігурація v4.2 ![NixOS](https://img.shields.io/badge/NixOS-24.11-blue.svg) [![Security Level](https://img.shields.io/badge/SECURITY-Paranoic-red)](https://nixos.org/security)

**Декларативна система, орієнтована на забезпечення кібербезпеки та апаратної ізоляції**  
*Остання ревізія: 09/02/2025*

---

## Структура конфігураційного файлу `configuration.nix`

### Модульна архітектура
```nix
{
  boot = { ... };         # Налаштування завантаження та ядра
  networking = { ... };   # Мережева конфігурація та фаєрвол
  services = { ... };     # Системні сервіси та демони
  security = { ... };     # Політики безпеки та захист
  virtualisation = { ... }; # Віртуалізація та контейнери
  # ...інші модулі, що будуть додані у майбутньому
}
```
Кожен модуль містить атомарні налаштування з чітко визначеною зоною відповідальності. Зміни здійснюються виключно через конфігураційний файл, що гарантує єдине джерело істини.

---

## Деталізація системних параметрів

### 1. Завантажувальне середовище (boot)
```nix
boot = {
  initrd.luks.devices."luks-911765a7-6ecb-4c99-88ef-b44c26fd3583".device = "/dev/disk/by-uuid/911765a7-6ecb-4c99-88ef-b44c26fd3583";
  initrd.systemd.enable = true;
  loader = {
    efi.canTouchEfiVariables = false;
    systemd-boot.enable = true;
    timeout = 10;
  };
};
```

#### Криптографічний захист (LUKS2)
- Алгоритм шифрування: AES-XTS-Plain64 із 512-бітним ключем.
- Функція виведення ключа (KDF): Argon2id з наступними параметрами:
  - Використання 1GB пам’яті.
  - 4 ітерації.
  - Паралелізм – 4.
- Захист від Bruteforce SSH: обмеження до 3-х спроб введення пароля з наступною перезавантаженням системи.

#### systemd-initrd 
- Підтримка TPM 2.0 для розкриття ключів.
- Інтеграція з Plymouth для забезпечення захищеного графічного інтерфейсу.
- Автоматичне оновлення мікрокоду процесора.

Зверніть увагу, що підтримка TPM відсутня через технічні обмеження на портативних пристроях. Для робочих станцій та серверів рекомендовано використовувати апаратні модулі безпеки (HSM).

#### EFI Lockdown
- Заборона запису до EFI partition через встановлення параметра canTouchEfiVariables в false.
- Захист Secure Boot реалізовано за допомогою самостійно підписаних ключів.

---

### 2. Параметри ядра Linux (boot.kernelParams)
```nix
boot.kernelParams = [
  # Детальні налаштування ядра...
];
```

#### Захист пам'яті
| Параметр           | Вплив на безпеку | Вплив на продуктивність | Опис                                             |
|--------------------|------------------|-------------------------|--------------------------------------------------|
| `slab_nomerge`     | High             | 2-5%                    | Запобігає перевикористанню slab-областей         |
| `page_poison=1`    | Critical         | 3-7%                    | Виявляє використання звільненої пам’яті          |
| `usercopy=strict`  | High             | 1-3%                    | Забезпечує жорстку валідацію копіювань між user і kernel |

#### Захист від спектральних атак
```nix
"l1tf=full,force"       # L1 Terminal Fault (CVE-2018-3646)
"mds=full,nosmt"        # Захист від Microarchitectural Data Sampling 
"spectre_v2=on"         # Пом'якшення атаки Spectre Variant 2
"spec_store_bypass_disable=on"
```
Рекомендації:
- Використовувати процесори з апаратними виправленнями (Intel Coffee Lake+ / AMD Zen 2+).
- Відключати Hyper-Threading за допомогою параметра nosmt.
- Регулярно оновлювати мікрокод процесора.

---

### 3. Мережа (networking)
```nix
networking = {
  firewall = {
    enable = true;
    allowedTCPPorts = [ 53 67 68 80 443 8080 ];
    allowedUDPPorts = [ 53 67 68 80 443 ];
    logRefusedConnections = true;
    allowPing = false;
    logIPv6Drops = true;
  };
};
```

#### Стратегія фаєрвола
- Політика за замовчуванням: DROP для вхідного трафіку та ACCEPT для вихідного.
- Визначено: 
  - TCP-порти – 53, 80, 123, 443, 8080, 8443, 5353.
  - UDP-порти – 53, 67, 68, 123, 5353.
- Захист від DDoS:
  - Налаштування `net.ipv4.tcp_syncookies=1`.
  - Обмеження з'єднань за допомогою `iptables -m connlimit`.

#### Логування та моніторинг
- Інтеграція з Fail2Ban для виявлення вторгнень.
- Регулярний аудит трафіку за допомогою nmap.
- VPN-інтеграція з використанням WireGuard з постквантовими алгоритмами.

---

### 4. Віртуалізація та ізоляція (virtualisation)
```nix
virtualisation = {
  libvirtd = {
    enable = true;
    extraConfig = ''...'';
  };
  spiceUSBRedirection.enable = true;
};
```

#### SELinux політики для libvirt
```nix
security_driver = "selinux"
seccomp_sandbox = 1
security_default_confined = 1
```
- Модель доступу: RBAC (Role-Based Access Control).
- Встановлено SELinux контексти:
  - `system_u:system_r:svirt_t:s0` для віртуальних машин.
  - `system_u:object_r:svirt_image_t:s0` для образів.

#### Захист від VM Escape
- Обмеження ресурсів за допомогою cgroups v2.
- Апаратна ізоляція через Intel VT-d/AMD-Vi.
- Відключення Kernel Samepage Merging (KSM) для запобігання витокам пам’яті.

## Додаткові ресурси
1. [NixOS Hardening Guide](https://nixos.wiki/wiki/Hardening)
2. [Linux Kernel Security Parameters](https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project)
3. [Virtualization Security Best Practices](https://libvirt.org/docs.html)
4. [LUKS2 Encryption Deep Dive](https://gitlab.com/cryptsetup/cryptsetup/-/wikis/FrequentlyAskedQuestions)
5. [Awesome Security Hardening Resources](https://github.com/decalage2/awesome-security-hardening)
6. [Linux Server Security Guide](https://github.com/imthenachoman/How-To-Secure-A-Linux-Server)
7. [NixOS Installation & Configuration](https://github.com/titanknis/Nixos-Installation-Guide)
8. [NixOps Virtualization Guide](https://nixos.wiki/wiki/NixOps/Virtualization)
9. [NixOS Configuration Explained](https://christitus.com/nixos-explained/)
