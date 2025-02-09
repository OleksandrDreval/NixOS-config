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

### 1. Завантажувальне середовище
Розділ `boot` відповідає за налаштування процесу завантаження системи та ядра.  Правильна конфігурація цього розділу є критично важливою для забезпечення безпеки системи з самого початку її запуску.

### `boot.loader`

Цей підрозділ налаштовує завантажувач systemd-boot.

*   `enable = true;`: Увімкнення systemd-boot як основного завантажувача.
*   `consoleMode = "max";`: Встановлення максимальної роздільної здатності консолі для зручності користування.  Не має прямого відношення до безпеки.
*   `configurationLimit = 5;`: Зберігання останніх 5 конфігурацій завантаження.  Може бути корисним для відновлення системи після невдалого оновлення.
*   `editor = false;`: Вимкнення редактора в меню завантаження для запобігання несанкціонованим змінам конфігурації завантаження.
*   `timeout = 10;`: Час очікування вибору в меню завантаження (10 секунд).

### `boot.kernelParams`

Цей підрозділ визначає параметри, що передаються ядру під час завантаження.  Правильне налаштування цих параметрів суттєво впливає на безпеку та стабільність системи.

### Група 1: Захист від апаратних вразливостей

Сучасні процесори мають ряд апаратних вразливостей, які можуть бути використані зловмисниками.  Наступні параметри допомагають зменшити ризики, пов'язані з цими вразливостями:

*   `l1tf = full,force`:  **L1 Terminal Fault (L1TF)**.  Цей параметр вмикає повний захист від L1TF, усуваючи можливість атак, що використовують уразливості спекулятивного виконання в кеші першого рівня процесора.  Опція `force` гарантує застосування захисту, навіть якщо це може призвести до незначного зниження продуктивності.

*   `mds = full,nosmt`: **Microarchitectural Data Sampling (MDS)**.  Вмикає повний захист від MDS, запобігаючи витоку даних через апаратні уразливості.  `nosmt` відключає Simultaneous Multithreading (SMT), що забезпечує максимальний рівень захисту, але може вплинути на продуктивність.

*   `mitigations = auto,nosmt`: **Загальні пом'якшення**.  Цей параметр автоматично застосовує патчі для відомих апаратних вразливостей.  `nosmt` також відключає SMT для підвищення безпеки.

*   `pti = on`: **Page Table Isolation (PTI)**.  Вмикає ізоляцію таблиць сторінок ядра та користувацького простору.  Це зменшує ризик атак Meltdown та Spectre, запобігаючи несанкціонованому доступу до даних ядра.

*   `spec_store_bypass_disable = on`, `spectre_v2 = on`, `stf_barrier = on`:  **Spectre та інші атаки спекулятивного виконання**. Ці параметри вмикають захист від різних варіантів атак Spectre та інших подібних вразливостей, пов'язаних з спекулятивним виконанням команд процесора.

### Група 2: Контроль модулів ядра

*   `module.sig_enforce = 1`: **Підпис модулів**.  Цей параметр вимагає наявності цифрового підпису для всіх модулів ядра.  Це гарантує, що завантажуються лише авторизовані та перевірені модулі, запобігаючи використанню шкідливих або модифікованих модулів.

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
