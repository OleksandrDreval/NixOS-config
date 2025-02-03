# 🔒 NixOS Безпечна Конфігурація v4.2 ![NixOS](https://img.shields.io/badge/NixOS-24.11-blue.svg) [![Security Level](https://img.shields.io/badge/SECURITY-Paranoic-red)](https://nixos.org/security)

**Декларативна система з акцентом на кібербезпеку та апаратну ізоляцію**  
*Остання ревізія: 03/02/2025*

---

## 📜 Структура конфігураційного файлу `configuration.nix`

### 🧩 Модульна архітектура
```nix
{
  boot = { ... };       # Налаштування завантаження та ядра
  networking = { ... }; # Мережева конфігурація та фаєрвол
  services = { ... };   # Системні сервіси та демони
  security = { ... };   # Політики безпеки та захист
  virtualisation = { ... }; # Віртуалізація та контейнери
  # ...інші модулі
}
```
Кожен модуль містить атомарні налаштування з чіткою зоною відповідальності. Використовується принцип "єдиного джерела істини" - всі зміни відбуваються виключно через конфігураційний файл.

---

## 🛡️ Деталізація системних параметрів

### 1. 🖥️ Завантажувальне середовище (`boot`)
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

#### 🔐 Криптографічний захист (LUKS2)
- **Алгоритм шифрування**: AES-XTS-Plain64 з 512-бітним ключем
- **Key derivation function**: Argon2id з параметрами:
  - Візум пам'яті: 1GB
  - Ітерації: 4
  - Паралелізм: 4
- **Захист від Bruteforce SSH**: Обмеження спроб введення пароля (3 спроби перед перезавантаженням)

#### ⚡ systemd-initrd 
- **Переваги**:
  - Підтримка TPM 2.0 для розкриття ключів ( в конфігурації не передбачено підтримку TPM через фундаментальні проблеми цієї платворми "Ваші мізки куди надійніше")
  - Інтеграція з Plymouth для захищеного графічного інтерфейсу
  - Автоматичне оновлення microcode процесора

#### 🛑 EFI Lockdown
- **Заборона запису** в EFI partition через `canTouchEfiVariables=false`
- **Захист Secure Boot**: Використання самостійно підписаних ключів

---

### 2. 🧠 Параметри ядра Linux (`boot.kernelParams`)
```nix
boot.kernelParams = [
  # Детальні налаштування ядра...
];
```

#### 🛡️ Захист пам'яті
| Параметр          | Вплив на безпеку 💂  | Вплив на продуктивність 📉 | Опис |
|--------------------|----------------------|--------------------------|------|
| `slab_nomerge`     | High                 | 2-5%                     | Запобігає перевикористанню slab-областей |
| `page_poison=1`    | Critical             | 3-7%                     | Детектує використання звільненої пам'яті |
| `usercopy=strict`  | High                 | 1-3%                     | Строга валідація копіювань user↔kernel |

#### ⚡ Захист від спектральних атак
```nix
"l1tf=full,force"       # L1 Terminal Fault (CVE-2018-3646)
"mds=full,nosmt"        # Microarchitectural Data Sampling 
"spectre_v2=on"         # Spectre Variant 2 Mitigation
"spec_store_bypass_disable=on"
```
**Рекомендації**:  
- Використовувати CPU з аппаратним фіксами (Intel Coffee Lake+ / AMD Zen 2+)
- Вимкнути Hyper-Threading через `nosmt`
- Регулярно оновлювати microcode

---

### 3. 🌐 Мережа (`networking`)
```nix
networking = {
  firewall = {
    enable = true;
    allowedTCPPorts = [ 53 80 123 443 8080 8443 5353 ];
    allowedUDPPorts = [ 53 67 68 123 5353 ];
    logRefusedConnections = true;
    allowPing = false;
    logIPv6Drops = true;
  };
};
```

#### 🛡️ Стратегія фаєрвола
- **Default policy**: DROP для вхідних, ACCEPT для вихідних
- **Port Whitelisting**:
  - **TCP**: HTTP(S), DNS, NTP, mDNS
  - **UDP**: DHCP, DNS, NTP
- **Захист від DDoS**: 
  - Конфігурація `net.ipv4.tcp_syncookies=1`
  - Обмеження кількості з'єднань через `iptables -m connlimit`

#### 📊 Логування та моніторинг
- **Система детекції вторгнень**: Інтеграція з Fail2Ban
- **Аналіз трафіку**: Регулярний аудит через `nmap -sV -O`
- **VPN Integration**: WireGuard з постквантовими алгоритмами

---

### 4. 🖥️ Віртуалізація та ізоляція (`virtualisation`)
```nix
virtualisation = {
  libvirtd = {
    enable = true;
    extraConfig = ''...'';
  };
  spiceUSBRedirection.enable = true;
};
```

#### 🔒 SELinux політики для libvirt
```nix
security_driver = "selinux"
seccomp_sandbox = 1
security_default_confined = 1
```
- **Модель доступу**: RBAC (Role-Based Access Control)
- **SELinux Contexts**: 
  - `system_u:system_r:svirt_t:s0` для ВМ
  - `system_u:object_r:svirt_image_t:s0` для образів

#### 🛡️ Захист від VM Escape
- **Обмеження ресурсів** через cgroups v2
- **Апаратна ізоляція**: Використання Intel VT-d/AMD-Vi
- **Захист пам'яті**: Kernel Samepage Merging (KSM) disabled

---

## 📚 Додаткові ресурси
1. [NixOS Hardening Guide](https://nixos.wiki/wiki/Hardening)
2. [Linux Kernel Security Parameters](https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project)
3. [Virtualization Security Best Practices](https://libvirt.org/docs.html)
4. [LUKS2 Encryption Deep Dive](https://gitlab.com/cryptsetup/cryptsetup/-/wikis/FrequentlyAskedQuestions)
5. [Awesome Security Hardening Resources](https://github.com/decalage2/awesome-security-hardening)
6. [Linux Server Security Guide](https://github.com/imthenachoman/How-To-Secure-A-Linux-Server)
7. [NixOS Installation & Configuration](https://github.com/titanknis/Nixos-Installation-Guide)
8. [NixOps Virtualization Guide](https://nixos.wiki/wiki/NixOps/Virtualization)
9. [NixOS Configuration Explained](https://christitus.com/nixos-explained/)
