# Rampart-Nix: Безпечна Конфігурація NixOS
![NixOS](https://img.shields.io/badge/NixOS-24.11-blue.svg) [![Security Level](https://img.shields.io/badge/SECURITY-Paranoic-red)](https://nixos.org/security)

*Остання ревізія: 09/02/2025*

---

## Зміст
- [Опис конфігурації](#опис-конфігурації)
- [Архітектура і безпека](#архітектура-і-безпека)
  - [Інтеграція компонентів](#інтеграція-компонентів)
    - [Криптографічний фундамент](#криптографічний-фундамент)
    - [Ядро з хитрим тюнінгом](#ядро-з-хитрим-тюнінгом)
    - [Мережева фортеця](#мережева-фортеця)
    - [Віртуалізаційний сендбокс](#віртуалізаційний-сендбокс)
    - [Апаратний маршалінг](#апаратний-маршалінг)
    - [Сили спецпризначення SELinux](#сили-спецпризначення-selinux)
  - [Архітектурні особливості](#архітектурні-особливості)
    - [Завантажувальний ланцюг](#завантажувальний-ланцюг)
    - [Мережевий імунітет](#мережевий-імунітет)
    - [Апаратна дисципліна](#апаратна-дисципліна)
    - [Віртуальний периметр](#віртуальний-периметр)
    - [Ресурсний суверенітет](#ресурсний-суверенітет)
- [Встановлення та використання](#встановлення-та-використання)
- [Структура конфігурації](#структура-конфігурації)
- [Додаткові ресурси](#додаткові-ресурси)

---

## Опис конфігурації

Ця конфігурація NixOS є кібернетичним форпостом нового покоління, де кожен параметр вивірений до мікроскопічної точності, а кожен системний компонент функціонує як захисний редут. Вона поєднує:

- **Архітектурну цілісність:** криптографічний фундамент LUKS2 з апаратним захистом DMA.
- **Протокольний детермінізм:** мережова цитадель із 28 правил IPv4 та 20 правил IPv6, доповнена рандомізацією MAC через iwd.
- **Ресурсний суверенітет:** cgroups v2 для керування процесами та ізоляція через PTI/KPTI.
- **Віртуальний периметр:** Libvirt/QEMU з Secure Boot та TPM емуляцією, що забезпечує ізоляцію.
- **Захисний механізм SELinux:** повний enforcement режим для управління системними привілеями.

---

## **Архітектура і безпека**

**Ядро системи** — це синтез 137 ручно налаштованих параметрів безпеки, де:
- 32 завантажувальні опції формують броньований ланцюг ініціалізації.
- 105 sysctl-оптимізацій створюють захисний периметр пам'яті.
- 48 IP-правил реалізують превентивний захист мережі.

Система інтегрує:

- **Криптографічний фундамент**: LUKS2 з апаратним захистом DMA (`mitigateDMAAttacks`)
- **Ядро з хитрим тюнінгом**: 32 параметри завантаження + 105 sysctl-оптимізацій
- **Мережева фортеця**: 28 правил IPv4 + 20 правил IPv6 + рандомізація MAC через iwd
- **Віртуалізаційний сендбокс**: Libvirt/QEMU з Secure Boot + TPM емуляцією
- **Апаратний маршалінг**: Повне вимкнення SMT + Scudo allocator з ZeroContents
- **Сили спецпризначення SELinux**: Повний enforcement режим

**Архітектурні особливості:**
1. **Завантажувальний ланцюг**: 
   -Systemd-boot з криптографічною цілісністю
   - Двофакторна ініціалізація ядра (`kexec_load_disabled` + `module.sig_enforce`)
2. **Мережевий імунітет**: 
   - Синхронний захист від TCP-флагових аномалій
   - Проактивне блокування ARP-spoofing через rp_filter
   - Генератор MAC-маскування для кожного Wi-Fi сеансу
   - Повна ізоляція IPv6 (`autoconf=0`, `accept_ra=0`)
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
- Детермінована імутабельність (`users.mutableUsers = false`)
- Атомарна верифікація пакетів (`nix.settings.trusted-users`)
- Жорсткий аудит (`security.auditd` + кастомні правила)
- Нульова толерантність до:
  - SUID/SGID (`security.restrictSUIDSGID`)
  - User namespaces (`security.unprivilegedUsernsClone`)
  - Підробки ядра (`security.protectKernelImage`)

---

## Структура конфігурації

Конфігурація побудована за модульною схемою:
```nix
{
  boot = { ... };         # Налаштування завантаження та ядра
  networking = { ... };   # Мережеві налаштування та фаєрвол
  services = { ... };     # Системні сервіси та демони
  security = { ... };     # Політики безпеки та модуляція доступу
  virtualisation = { ... }; # Віртуалізація та контейнери
}
```
Кожен модуль містить атомарні налаштування з чітко визначеною зоною відповідальності. Зміни здійснюються виключно через конфігураційний файл, що гарантує єдине джерело істини.

---

## Деталізація системних параметрів

### 1. Завантажувальне середовище

 Розділ `boot` відповідає за налаштування процесу завантаження системи та ядра.  Правильна конфігурація цього розділу є критично важливою для забезпечення безпеки системи з самого початку її запуску.

---

### 2. Мережа

 Розділ `networking` визначає параметри мережевого підключення системи.  Це включає в себе налаштування IP-адрес, масок підмереж, шлюзів, DNS-серверів та інших мережевих параметрів.  Правильна конфігурація мережі є критично важливою для забезпечення безпеки та доступності системи.  Всі мережеві параметри повинні бути чітко визначені та захищені від несанкціонованого доступу.

---

### 3. Сервіси

 Розділ `services` визначає список сервісів, які будуть запущені під час роботи системи.  Це включає в себе як системні сервіси, так і сервіси, встановлені користувачем.  Важливо ретельно вибирати та налаштовувати сервіси, щоб уникнути потенційних проблем безпеки та оптимізувати продуктивність системи.  Кожен сервіс повинен бути чітко визначений та мати відповідні параметри безпеки.

---

### 4. Безпеки

 Розділ `security` містить налаштування, пов'язані з безпекою системи.  Це включає в себе налаштування брандмауера, контроль доступу, аудитування та інші заходи безпеки.  Правильна конфігурація цього розділу є критично важливою для захисту системи від несанкціонованого доступу та шкідливих дій.
 *Важливо регулярно перевіряти та оновлювати налаштування безпеки, щоб уникнути потенційних загроз.

---

### 5. Віртуалізація та ізоляція

 Розділ `virtualization` містить налаштування, пов'язані з віртуалізацією та ізоляцією програмного забезпечення та систем.  Це може включати в себе налаштування віртуальних машин (наприклад, за допомогою VirtualBox, KVM, Xen), контейнерів (наприклад, Docker, LXC), та інших технологій ізоляції.  Правильна конфігурація цього розділу є важливою для забезпечення безпеки та ізоляції різних компонентів системи.  Наприклад, віртуальні машини можуть бути ізольовані одна від одної, а контейнери можуть бути обмежені в доступі до ресурсів системи.

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
