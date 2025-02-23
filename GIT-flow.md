#Впровадження Git-flow

## 1. Створення основних гілок
За замовчуванням у проєкті є лише гілка `main`. Для впровадження Git-flow потрібно створити гілку `develop`:
```bash
# Перейти в main (на всякий випадок)
git checkout main

# Створити нову гілку develop і переключитися на неї
git checkout -b develop

# Завантажити зміни в віддалений репозиторій
git push -u origin develop
```
Тепер у проєкті є дві основні гілки:
- `main` – для стабільних релізів
- `develop` – для активної розробки

## 2. Створення та злиття гілок

### 2.1 Додавання нової функції (Feature)
```bash
# Переключитися на develop
git checkout develop

# Створити нову гілку для функції
git checkout -b feature/назва-функції

# Після завершення розробки злити зміни в develop
git checkout develop
git merge feature/назва-функції

# Видалити непотрібну гілку
git branch -d feature/назва-функції
```

### 2.2 Підготовка до релізу (Release)
```bash
# Переключитися на develop
git checkout develop

# Створити нову гілку для релізу
git checkout -b release/версія

# Після тестування злити зміни в main
git checkout main
git merge release/версія

git tag версія  # Позначити реліз тегом

# Злити зміни назад у develop
git checkout develop
git merge release/версія

# Видалити непотрібну гілку
git branch -d release/версія
```

### 2.3 Термінове виправлення (Hotfix)
```bash
# Переключитися на main
git checkout main

# Створити нову гілку для виправлення
git checkout -b hotfix/назва

# Після виправлення злити зміни в main
git checkout main
git merge hotfix/назва

git tag нова-версія  # Позначити новий реліз

# Злити зміни в develop, щоб вони не загубилися
git checkout develop
git merge hotfix/назва

# Видалити непотрібну гілку
git branch -d hotfix/назва
```

## 3. Перемикання між гілками
```bash
# Перейти на main
git checkout main

# Перейти на develop
git checkout develop

# Перейти на гілку функції
git checkout feature/назва
```
Або скорочена версія (для нових версій Git):
```bash
git switch main
git switch develop
git switch feature/назва
```

## 4. Злиття гілок

### 4.1 Об’єднання `develop` → `main` (перед релізом)
```bash
git checkout main  # Перейти в main
git merge develop  # Злити зміни з develop у main
```

### 4.2 Об’єднання `main` → `develop` (після hotfix)
```bash
git checkout develop  # Перейти в develop
git merge main  # Злити зміни з main у develop
```

## 5. Видалення гілок
Після злиття можна видалити непотрібну гілку:
```bash
git branch -d назва-гілки  # Видалити локально
git push origin --delete назва-гілки  # Видалити у віддаленому репозиторії
```
