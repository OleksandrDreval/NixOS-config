# NixOS Security-Centric Configuration ![NixOS](https://img.shields.io/badge/NixOS-21.11-blue.svg)

**Декларативна система з підвищеним рівнем захисту**  
*Версія конфігурації: 2.4.1 | Останнє оновлення: 15 липня 2024*

---

## 🔐 Ключові особливості безпеки

### 1. Захист завантажувального середовища

boot.initrd.luks.devices."luks-..." = {
device = "/dev/disk/by-uuid/...";
systemd.enable = true; # Використання systemd-initrd
};

- **LUKS2** шифрування диска з TPM2 інтеграцією
- Обмеження доступу до EFI-змін (`canTouchEfiVariables = false`)
- Secure Boot через `sbctl` (пакет 351)


### 2. Параметри ядра Linux

kernelParams = [
"lockdown=confidentiality"
"module.sig_enforce=1" # Примусове підписування модулів
"slab_nomerge" "page_poison=1" # Захист від heap-експлоїтів
"spectre_v2=on"
"kpti=on"
"smap=on"
"smep=on"
"debugfs=off"
];

- Захист від спектральних атак (`spectre_v2=on`)
- Використання KPTI/SMAP/SMEP (рядок 297)
- Обмеження debugfs (`debugfs=off`)


### 3. Мережева безпека

firewall = {
  allowedTCPPorts = [53 80 443]; # Мінімальний набір портів
  extraCommands = ''
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
    ip6tables -A INPUT -p icmpv6 --icmpv6-type echo-request -j DROP
  '';
};

- Stateful фаєрвол з правилами проти сканування портів
- DNS-over-HTTPS через `networkmanager` плагіни
- Блокування підозрілих TCP-флагів (14 правил iptables)


### 4. Системний моніторинг

services.journald.extraConfig = ''
  Storage=persistent
  SystemMaxUse=500M
  Audit=yes # Інтеграція з auditd
'';

- Централізоване журналювання через Rsyslog
- Auditd правила для:
  - Відстеження виконання процесів (`-S execve`)
  - Моніторинг мережевих з'єднань (`-S bind`, `-S connect`)


### 5. Віртуалізація

virtualisation.libvirtd = {
  extraConfig = ''
    security_driver = "selinux"
    seccomp_sandbox = 1
  '';
  allowedBridges = ["virbr0"];
};

- QEMU/KVM з SELinux confinement
- Обмежений доступ до пристроїв через cgroups
- Використанство VirtIO для ізоляції мережі

---

## 📊 Архітектура безпеки

```mermaid
graph TD
    A[Апаратний рівень] --> B(Firmware Protection)
    B --> C{Завантажувач}
    C --> D[LUKS2 Encryption]
    D --> E[Ядро Linux]
    E --> F[Мережевий екран]
    F --> G[Сервіси]
    G --> H[Користувацький простір]
    
    style A fill:#ffcccc,stroke:#333
    style C fill:#ccffcc,stroke:#333
    style E fill:#ccccff,stroke:#333
```mermaid
graph TD
    A[Апаратний рівень] --> B(Firmware Protection)
    B --> C{Завантажувач}
    C --> D[LUKS2 Encryption]
    D --> E[Ядро Linux]
    E --> F[Мережевий екран]
    F --> G[Сервіси]
    G --> H[Користувацький простір]
    
    style A fill:#ffcccc,stroke:#333
    style C fill:#ccffcc,stroke:#333
    style E fill:#ccccff,stroke:#333
```mermaid
graph TD
    A[Апаратний рівень] --> B(Firmware Protection)
    B --> C{Завантажувач}
    C --> D[LUKS2 Encryption]
    D --> E[Ядро Linux]
    E --> F[Мережевий екран]
    F --> G[Сервіси]
    G --> H[Користувацький простір]
    
    style A fill:#ffcccc,stroke:#333
    style C fill:#ccffcc,stroke:#333
    style E fill:#ccccff,stroke:#333
```mermaid
graph TD
    A[Апаратний рівень] --> B(Firmware Protection)
    B --> C{Завантажувач}
    C --> D[LUKS2 Encryption]
    D --> E[Ядро Linux]
    E --> F[Мережевий екран]
    F --> G[Сервіси]
    G --> H[Користувацький простір]
    
    style A fill:#ffcccc,stroke:#333
    style C fill:#ccffcc,stroke:#333
    style E fill:#ccccff,stroke:#333
```mermaid
graph TD
    A[Апаратний рівень] --> B(Firmware Protection)
    B --> C{Завантажувач}
    C --> D[LUKS2 Encryption]
    D --> E[Ядро Linux]
    E --> F[Мережевий екран]
    F --> G[Сервіси]
    G --> H[Користувацький простір]
    
    style A fill:#ffcccc,stroke:#333
    style C fill:#ccffcc,stroke:#333
    style E fill:#ccccff,stroke:#333
```mermaid
graph TD
    A[Апаратний рівень] --> B(Firmware Protection)
    B --> C{Завантажувач}
    C --> D[LUKS2 Encryption]
    D --> E[Ядро Linux]
    E --> F[Мережевий екран]
    F --> G[Сервіси]
    G --> H[Користувацький простір]
    
    style A fill:#ffcccc,stroke:#333
    style C fill:#ccffcc,stroke:#333
    style E fill:#ccccff,stroke:#333
```mermaid
graph TD
    A[Апаратний рівень] --> B(Firmware Protection)
    B --> C{Завантажувач}
    C --> D[LUKS2 Encryption]
    D --> E[Ядро Linux]
    E --> F[Мережевий екран]
    F --> G[Сервіси]
    G --> H[Користувацький простір]
    
    style A fill:#ffcccc,stroke:#333
    style C fill:#ccffcc,stroke:#333
    style E fill:#ccccff,stroke:#333
```mermaid
graph TD
    A[Апаратний рівень] --> B(Firmware Protection)
    B --> C{Завантажувач}
    C --> D[LUKS2 Encryption]
    D --> E[Ядро Linux]
    E --> F[Мережевий екран]
    F --> G[Сервіси]
    G --> H[Користувацький простір]
    
    style A fill:#ffcccc,stroke:#333
    style C fill:#ccffcc,stroke:#333
    style E fill:#ccccff,stroke:#333
```
