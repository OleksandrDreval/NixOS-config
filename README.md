# NixOS Безпечна Конфігурація v4.2 ![NixOS](https://img.shields.io/badge/NixOS-24.11-blue.svg) [![Security Level](https://img.shields.io/badge/SECURITY-Paranoic-red)](https://nixos.org/security)

**Декларативна система, орієнтована на забезпечення кібербезпеки та апаратної ізоляції**  
*Остання ревізія: 09/02/2025*

---

Ця конфігурація NixOS є кібернетичним форпостом, де кожен параметр вивірений до мікроскопічної точності. Система інтегрує:

- **Криптографічний фундамент**: LUKS2 з апаратним захистом DMA (mitigateDMAAttacks)
- **Ядро з хитрим тюнінгом**: 32 параметри завантаження + 105 sysctl-оптимізацій
- **Мережева фортеця**: 28 правил IPv4 + 20 правил IPv6 + рандомізація MAC через iwd
- **Віртуалізаційний сендбокс**: Libvirt/QEMU з Secure Boot + TPM емуляцією
- **Апаратний маршалінг**: Повне вимкнення SMT + Scudo allocator з ZeroContents
- **Сили спецпризначення SELinux**: Повний enforcement режим

**Архітектурні особливості:**
1. **Завантажувальний ланцюг**: 
   -Systemd-boot з криптографічною цілісністю
   - Двофакторна ініціалізація ядра (kexec_load_disabled + module.sig_enforce)
2. **Мережевий імунітет**: 
   - Синхронний захист від TCP-флагових аномалій
   - Проактивне блокування ARP-spoofing через rp_filter
   - Генератор MAC-маскування для кожного Wi-Fi сеансу
   - Повна ізоляція IPv6 (autoconf=0, accept_ra=0)
3. **Апаратна дисципліна**: 
   - Повне вимкнення SMT/Spectre/Meltdown векторів
   - Scudo allocator з нульовою ініціалізацією пам'яті
4. **Віртуальний периметр**: 
   - QEMU/KVM з апаратною ізоляцією
   - Seccomp-фільтри для кожного VM-інтерфейсу

3. **Ресурсний суверенітет**:
   - Cgroups v2 з обмеженням 512 процесів/користувача
   - PTI + KPTI для поділу адресних просторів
   - Проактивний аудит з частотною ротацією логів
   - SLUB Hardening з FZP-дебагінгом

**Операційні характеристики:**
- Детермінована імутабельність (users.mutableUsers = false)
- Атомарна верифікація пакетів (nix.settings.trusted-users)
- Жорсткий аудит (security.auditd + кастомні правила)
- Нульова толерантність до:
  - SUID/SGID (security.restrictSUIDSGID)
  - User namespaces (security.unprivilegedUsernsClone)
  - Підробки ядра (security.protectKernelImage)

Ця конфігурація - це кібернетичний організм, де кожен sysctl-параметр є захисним редутом, кожен мережевий пакет - під протокольним наглядом, а кожен системний виклик - у жорсткому SElinux-контексті.

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

### 1. Завантажувальне середовище
Розділ `boot` відповідає за налаштування процесу завантаження системи та ядра.  Правильна конфігурація цього розділу є критично важливою для забезпечення безпеки системи з самого початку її запуску.


---

### 2. Мережа 

---

### 3. Сервіси 
Розділ `services` визначає список сервісів, які будуть запущені під час роботи системи.  Це включає в себе як системні сервіси, так і сервіси, встановлені користувачем.  Важливо ретельно вибирати та налаштовувати сервіси, щоб уникнути потенційних проблем безпеки та оптимізувати продуктивність системи.  Кожен сервіс повинен бути чітко визначений та мати відповідні параметри безпеки.

---

### 4. Безпеки

---

### 5. Віртуалізація та ізоляція

---


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
