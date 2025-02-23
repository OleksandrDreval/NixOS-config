# Гайд Git-flow

## 1. Ініціалізація Git-flow

```bash
git init
git checkout -b develop
git push -u origin develop
```

## 2. Основні гілки в Git-flow

\*релізна конфігурація після перевірки та налагодження повинна бути перенесена з гілок розробки(any develop\`s branch) до основної (main).

- **main** – Cтабільна (релізна) версія коду.
- **develop** – Гілка розробки.
- Функціональні гілки.
- **hotfix/** – Виправлення критичних багів.

## 3. Створення нових гілок

```bash
git checkout -b назва
```

Після завершення роботи:

```bash
git checkout develop
git merge назва
git branch -d назва
git push origin develop --delete назва
```

## 4. Перемикання між гілками

```bash
git checkout main  # Перехід у main
git checkout develop  # Перехід у develop
```

## 5. Злиття гілок

Злиття `develop` у `main`:

```bash
git checkout main
git merge develop
git push origin main
```

## ??? Використання rebase

```bash
git checkout develop
git rebase main
git push origin develop --force-with-lease
```

## 6. Створення файлів, які існують лише у `develop`

```bash
git checkout develop
mkdir dev-only-files
echo "Цей файл існує лише у розробці" > dev-only-files/example.txt
git add dev-only-files/
git commit -m "Додані файли, що існують лише у develop"
git push origin develop
```

Щоб **файли не потрапили в `main`**, уникай `merge develop → main`. Якщо потрібно злити лише частину змін, використовуй `cherry-pick`:
*abc123^..def456 – НЕ включає abc123, але включає def456.
 abc123..def456 – ВКЛЮЧАЄ abc123 і всі наступні до def456.

```bash
git checkout main
git cherry-pick <початковий_commit>..<кінцевий_commit>
git push origin main
```

Якщо файли випадково потрапили в `main`:

```bash
git checkout main
git rm -r dev-only-files/
git commit -m "Видалення файлів, що мають бути лише у develop"
git push origin main
```

Таким чином, файли залишаться лише у `develop`, а `main` буде чистим.

