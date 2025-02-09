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

### Захист від апаратних вразливостей

Сучасні процесори мають ряд апаратних вразливостей, які можуть бути використані зловмисниками.  Наступні параметри допомагають зменшити ризики, пов'язані з цими вразливостями:

*   `l1tf = full,force`:  **L1 Terminal Fault (L1TF)**.  Цей параметр вмикає повний захист від L1TF, усуваючи можливість атак, що використовують уразливості спекулятивного виконання в кеші першого рівня процесора.  Опція `force` гарантує застосування захисту, навіть якщо це може призвести до незначного зниження продуктивності.

*   `mds = full,nosmt`: **Microarchitectural Data Sampling (MDS)**.  Вмикає повний захист від MDS, запобігаючи витоку даних через апаратні уразливості.  `nosmt` відключає Simultaneous Multithreading (SMT), що забезпечує максимальний рівень захисту, але може вплинути на продуктивність.

*   `mitigations = auto,nosmt`: **Загальні пом'якшення**.  Цей параметр автоматично застосовує патчі для відомих апаратних вразливостей.  `nosmt` також відключає SMT для підвищення безпеки.

*   `pti = on`: **Page Table Isolation (PTI)**.  Вмикає ізоляцію таблиць сторінок ядра та користувацького простору.  Це зменшує ризик атак Meltdown та Spectre, запобігаючи несанкціонованому доступу до даних ядра.

*   `spec_store_bypass_disable = on`, `spectre_v2 = on`, `stf_barrier = on`:  **Spectre та інші атаки спекулятивного виконання**. Ці параметри вмикають захист від різних варіантів атак Spectre та інших подібних вразливостей, пов'язаних з спекулятивним виконанням команд процесора.

### Контроль модулів ядра

*   `module.sig_enforce = 1`: **Підпис модулів**.  Цей параметр вимагає наявності цифрового підпису для всіх модулів ядра.  Це гарантує, що завантажуються лише авторизовані та перевірені модулі, запобігаючи використанню шкідливих або модифікованих модулів.

### Безпека пам'яті

Ці параметри налаштовують механізми захисту пам'яті, запобігаючи витоку інформації та підвищуючи стійкість до експлойтів:

*   `init_on_alloc = 1`: **Ініціалізація пам'яті при виділенні**.  Гарантує, що нововиділена пам'ять буде заповнена нулями або іншими визначеними значеннями, запобігаючи доступу до залишків даних попередніх процесів.

*   `init_on_free = 1`: **Ініціалізація пам'яті при звільненні**.  Аналогічно до попереднього параметра, але ініціалізує пам'ять після її звільнення, ускладнюючи відновлення конфіденційних даних.

*   `page_poison = 1`: **"Отруєння" пам'яті**.  Заповнює звільнену пам'ять спеціальними значеннями ("отрутою"), що ускладнює використання вразливостей, пов'язаних з доступом до неініціалізованої пам'яті.

*   `slab_nomerge`: **Відключення об'єднання slab-ів**.  Запобігає об'єднанню slab-ів пам'яті, що може призвести до витоку інформації між різними процесами.

*   `slub_debug = FZP`: **Налагодження SLUB аллокатора**.  Вмикає додаткові перевірки та логування для SLUB аллокатора, що допомагає виявляти помилки та потенційні вразливості в управлінні пам'яттю.


### IOMMU (Input/Output Memory Management Unit)

IOMMU забезпечує апаратну ізоляцію пристроїв вводу/виводу, захищаючи систему від DMA-атак:

*   `amd_iommu = force_isolation`: **Примусова ізоляція AMD IOMMU**.  Вмикає примусову ізоляцію IOMMU для процесорів AMD, захищаючи систему від несанкціонованого доступу до пам'яті з боку пристроїв вводу/виводу.

*   `iommu = force`: **Примусове включення IOMMU**.  Вмикає IOMMU, незалежно від налаштувань BIOS.

*   `iommu.passthrough = 0`: **Вимкнення режиму passthrough для IOMMU**.  Забезпечує додаткові перевірки доступу до пам'яті пристроями, підвищуючи безпеку.

*   `iommu.strict = 1`: **Строгий режим IOMMU**.  Посилює контроль над доступом пристроїв до системної пам'яті.


### Інші параметри безпеки

*   `debugfs = off`: **Вимкнення debugfs**.  Вимикає файлову систему debugfs, яка може бути використана для отримання доступу до системної інформації та налагодження ядра.  Вимкнення debugfs зменшує поверхню атаки.

*   `efi=disable_early_pci_dma`: **Відключення раннього PCI DMA в EFI**.  Запобігає використанню ранньої ініціалізації DMA для експлуатації вразливостей.

*   `ia32_emulation = 0`: **Вимкнення емуляції ia32**.  Вимикає емуляцію 32-бітної архітектури на 64-бітних системах.

*   `random.trust_bootloader = off`, `random.trust_cpu = off`: **Безпечна генерація випадкових чисел**.  Вимикає використання завантажувача та CPU для генерації випадкових чисел, що підвищує безпеку генерації криптографічних ключів.

*   `randomize_kstack_offset = on`: **Рандомізація зміщення стеку ядра**.  Ускладнює експлуатацію вразливостей, пов'язаних з переповненням буфера в стеку ядра.

*   `usercopy = strict`: **Строгий режим копіювання даних**.  Вмикає суворі перевірки при копіюванні даних між користувацьким простором та ядром, запобігаючи помилкам та потенційним вразливостям.

*   `vsyscall = none`: **Вимкнення vsyscall**.  Вимикає застарілий механізм системних викликів vsyscall, який може бути використаний в атаках.


### Логування та вивід інформації

*   `kernel.printk = "3 4 1 3"`: **Налаштування рівня логування ядра**.  Обмежує обсяг виводу повідомлень ядра, зменшуючи потенційний витік інформації.

*   `lockdown = confidentiality:integrity`: **Режим блокування ядра**.  Обмежує зміну критичних параметрів ядра після завантаження, підвищуючи безпеку та цілісність системи.

*   `loglevel = 0`: **Мінімальний рівень логування**.  Встановлює мінімальний рівень деталізації повідомлень ядра, зменшуючи кількість інформації, доступної потенційним зловмисникам.

*   `oops = panic`: **Обробка критичних помилок**.  В разі виникнення критичної помилки ядра (oops) система переходить в стан паніки (panic), запобігаючи подальшій роботі в нестабільному стані.

*   `quiet`: **Зменшення виводу повідомлень**.  Зменшує кількість повідомлень, що виводяться на консоль під час завантаження.

### Підтримувані файлові системи

У конфігурації NixOS підтримуються кілька файлових систем, що забезпечують гнучкість та можливість вибору в залежності від потреб користувача. Ось список підтримуваних файлових систем:

*   **btrfs**: Сучасна файлові система, що підтримує знімки, підключення до RAID, а також автоматичне управління простором. Вона ідеально підходить для серверів і робочих станцій, де важлива надійність даних.

*   **vfat**: Файлова система, що використовується для знімних носіїв, таких як USB-накопичувачі. Вона забезпечує сумісність з різними операційними системами.

*   **ext4**: Одна з найпопулярніших файлових систем для Linux, що забезпечує високу продуктивність і надійність. Вона підтримує великі обсяги даних і має механізми для відновлення після збоїв.

*   **xfs**: Файлова система, оптимізована для роботи з великими файлами та обсягами даних. Вона забезпечує високу продуктивність при обробці великих обсягів інформації.

*   **ntfs**: Файлова система, що використовується в Windows. Вона дозволяє читати та записувати дані на NTFS-форматовані диски, що робить її корисною для користувачів, які працюють з Windows.

*   **zfs**: Додаткова файлові система, яка може бути включена, якщо вона доступна на вашій платформі. ZFS забезпечує високу надійність, знімки, та автоматичне управління простором.


---

### 3. Мережа (networking)

---

### 4. Віртуалізація та ізоляція (virtualisation)

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
