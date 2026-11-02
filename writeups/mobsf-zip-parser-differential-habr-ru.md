# Анатомия парсерного дифференциала: обход нейтрализатора симлинков в MobSF через теневой EOCD (GHSA-j7g2-gm7j-mfvm)

*Автор: Сергей Шунько ([@ccsimplyspolit](https://github.com/ccsimplyspolit) / [@sshunko](https://hackerone.com/sshunko))*  
*Статус: Уязвимость закрыта в релизе MobSF 4.6.5*  
*Идентификатор: [GHSA-j7g2-gm7j-mfvm](https://github.com/MobSF/Mobile-Security-Framework-MobSF/security/advisories/GHSA-j7g2-gm7j-mfvm)*  
*CVSS v3.1: 3.1 (Low) / CVSS v4.0: 2.3 (Low)*  

---

В современных CI/CD-пайплайнах и лабораториях анализа защищенности мобильных приложений фреймворк **Mobile Security Framework (MobSF)** является стандартом де-факто. При загрузке APK, IPA или ZIP-архивов движок распаковывает тысячи файлов на хостовую файловую систему перед передачей их декомпиляторам (JADX, Ghidra, Baksmali).

Распаковка архивов — исторически опасная операция. Ранее в MobSF была выявлена проблема ([GHSA-mc92-j6mp-x9cp](https://github.com/MobSF/Mobile-Security-Framework-MobSF/security/advisories/GHSA-mc92-j6mp-x9cp)), когда наличие символических ссылок (Unix symlinks, `S_IFLNK` `0o120000`) в архиве позволяло последующим файлам перезаписывать произвольные пути на сервере.

Для защиты разработчики добавили механизм пре-экстракционной нейтрализации `neutralize_zip_special_modes()`. Однако в реализации этой защиты возник классический **парсерный дифференциал** в сочетании с логической ошибкой **fail-open**.

В этой статье мы подробно разберем:
1. Как устроен конвейер распаковки в MobSF и где допущен fail-open.
2. Почему поиск сигнатуры `PK\x05\x06` через `rfind` ломается на комментариях ZIP.
3. Почему уязвимость получила статус Low, а не Critical (разбор поведения Info-ZIP 6.0).
4. Как вендор исправил проблему в релизе 4.6.5.

---

## 1. Архитектура распаковки и ошибка Fail-Open

В файле `mobsf/StaticAnalyzer/views/common/shared_func.py` распаковка архивов устроена по многоуровневой схеме. Сначала MobSF пробует использовать стандартный модуль Python `zipfile`. Однако обфусцированные или вредоносные APK часто нарушают спецификации PKWARE, вызывая сбои в `zipfile`.

На этот случай предусмотрен резервный механизм — функция `os_unzip()`, которая вызывает системную утилиту `/usr/bin/unzip` (Info-ZIP).

Чтобы системный `unzip` не создал опасных симлинков, перед вызовом запускается `neutralize_zip_special_modes(app_path, ext_path)`: она создает копию архива, проходит по заголовкам Central Directory и зануляет биты специальных режимов POSIX.

Посмотрим на код `os_unzip` в MobSF <= 4.6.4:

```python
# mobsf/StaticAnalyzer/views/common/shared_func.py:400-415
extract_from = app_path
try:
    patched = neutralize_zip_special_modes(app_path, ext_path)
    extract_from = patched
except Exception:
    logger.warning('Could not strip symlink modes before OS unzip')

# OS unzip strips absolute paths and '..' from member names.
# Symlink modes are rewritten above so it cannot create a link.
subprocess.call(
    [unzip_b, '-o', '-q', extract_from, '-d', ext_path])

set_permissions(ext_path)
remove_external_symlinks(ext_path)
```

Обратите внимание на логическую развилку:
- Переменная `extract_from` инициализируется исходным файлом `app_path`.
- Если `neutralize_zip_special_modes` успешно модифицирует архив, `extract_from` переключается на очищенный временный файл `patched`.
- Но если `neutralize_zip_special_modes` падает с **любым исключением** (`except Exception`), MobSF просто пишет предупреждение в лог... и запускает `subprocess.call` с исходным `app_path`!

А как ведет себя `neutralize_zip_special_modes`?

```python
def neutralize_zip_special_modes(src, dest_parent):
    fd, name = tempfile.mkstemp(
        prefix='mobsf-unzip-',
        suffix='.zip',
        dir=_patched_zip_dir(dest_parent))
    os.close(fd)
    try:
        shutil.copyfile(src, name)
        with open(name, 'r+b') as handle:
            _rewrite_special_central_directory(handle)
    except Exception:
        os.unlink(name)
        raise
    return name
```

При любой ошибке в процессе модификации временный файл удаляется (`os.unlink(name)`), исключение пробрасывается наверх, перехватывается в `os_unzip`, и системный распаковщик получает оригинальный файл с сохранением всех прав на симлинки (`0o120777`).

---

## 2. Корень проблемы: Теневой EOCD и парсерный дифференциал

Чтобы нейтрализатор выбросил исключение, достаточно заставить `_rewrite_special_central_directory` упасть на файле, который системный `unzip` спокойно распакует.

Структура ZIP-файла завершается блоком **End of Central Directory (EOCD)**:
- 4 байта: сигнатура `PK\x05\x06` (`0x06054b50`).
- 16 байт: метаданные (номера дисков, смещение и размер Central Directory).
- 2 байта: длина комментария архива ($n$).
- $n$ байт: произвольный комментарий (до 65 535 байт).

Для поиска EOCD в MobSF использовалась функция `_eocd_offset`:

```python
def _eocd_offset(handle, size):
    """Return the end-of-central-directory offset."""
    window = min(size, 65535 + 22)
    data = _read_at(handle, size - window, window)
    rel = data.rfind(_EOCD_SIG)
    if rel < 0 or window - rel < 22:
        raise ValueError('EOCD not found')
    return size - window + rel
```

### В чем уязвимость `data.rfind(_EOCD_SIG)`?

Метод `rfind` ищет подстроку справа налево (с конца буфера). 

Если мы создадим валидный ZIP-архив, но в конец комментария поместим байты `PK\x05\x06` так, чтобы они оказались в последних 21 байте файла:
1. `data.rfind(_EOCD_SIG)` найдет ложную сигнатуру внутри комментария, а не настоящий заголовок EOCD, расположенный левее.
2. Проверка `window - rel < 22` вернет `True`, так как от найденной сигнатуры до конца файла осталось меньше минимального размера заголовка EOCD (22 байта).
3. Функция выбросит `ValueError('EOCD not found')`!

Кроме того, если между последней записью Central Directory и началом EOCD есть байты выравнивания:
```python
marker = _read_at(handle, pos, 4) if pos + 4 <= size else b''
if marker not in (_EOCD_SIG, _ZIP64_EOCD_SIG):
    raise ValueError('central directory walk did not finish')
```
Код бросает `ValueError('central directory walk did not finish')`. Нейтрализатор удаляет модифицированный файл и активирует fail-open.

---

## 3. Почему уязвимость получила статус Low (Архитектура Info-ZIP 6.0)

Казалось бы: полный обход механизма защиты от симлинков в привилегированном сервисе анализа кода — это Critical RCE? 

Однако детальный аудит поведения утилиты Info-ZIP 6.0 и логики MobSF показал, что реальный риск существенно ниже:

1. **Отложенное создание симлинков в Info-ZIP 6.0:** В современных сборках `unzip` распаковка симлинков откладывается на завершающую фазу, а встроенный механизм `checkdir()` блокирует попытки распаковки файлов через непроверенные пути.
2. **Синхронная зачистка в том же потоке:** Сразу после возврата из `subprocess.call` MobSF выполняет:
```python
set_permissions(ext_path)
remove_external_symlinks(ext_path)
```
Функция `remove_external_symlinks` рекурсивно проверяет `os.path.realpath` каждого распакованного объекта и удаляет любые симлинки, указывающие за пределы директории анализа, *до* того, как к ним получит доступ анализатор.

Таким образом, окно атаки ограничено временем работы самого процесса `unzip`, что сделало уязвимость трудноэксплуатируемой и привело к консенсусной оценке **Low** (CVSS v3.1: 3.1).

---

## 4. Демонстрационный PoC

Сравнение наивного парсера и безопасного алгоритма на Python:

```python
import struct

_EOCD_SIG = b"PK\x05\x06"

def buggy_mobsf_eocd_offset(data: bytes) -> int:
    window = min(len(data), 65535 + 22)
    tail = data[len(data) - window:]
    rel = tail.rfind(_EOCD_SIG)
    if rel < 0 or window - rel < 22:
        raise ValueError("EOCD not found")
    return len(data) - window + rel

def fixed_mobsf_eocd_offset(data: bytes) -> int:
    window = min(len(data), 65535 + 22)
    tail = data[len(data) - window:]
    pos = window - 22
    while pos >= 0:
        if tail[pos:pos + 4] == _EOCD_SIG:
            comment_len = struct.unpack_from("<H", tail, pos + 20)[0]
            if pos + 22 + comment_len <= window:
                return len(data) - window + pos
        pos -= 1
    raise ValueError("EOCD not found")

# Создаем валидный EOCD с комментарием, оканчивающимся на PK\x05\x06
comment = b"safe_comment_" + _EOCD_SIG
eocd_record = struct.pack("<4sHHHHIIH", _EOCD_SIG, 0, 0, 0, 0, 0, 0, len(comment)) + comment

# Старый парсер выбрасывает исключение и запускает fail-open
try:
    buggy_mobsf_eocd_offset(eocd_record)
except ValueError as e:
    print(f"[!] Уязвимый парсер упал: {e}")

# Исправленный парсер находит настоящий заголовок
offset = fixed_mobsf_eocd_offset(eocd_record)
print(f"[+] Исправленный парсер успешно определил смещение: {offset}")
```

---

## 5. Исправление в MobSF 4.6.5

Мейнтейнер проекта Аджин Абрахам ([@ajinabraham](https://github.com/ajinabraham)) выпустил релиз **MobSF 4.6.5**, где применил два ключевых изменения:

1. **Переход на Fail-Closed:** при любой ошибке нейтрализатора `os_unzip` прерывает работу и возвращает пустой результат:
```python
except Exception:
    msg = 'Refusing OS unzip because special modes could not be stripped'
    logger.error(msg)
    append_scan_status(checksum, msg)
    return []
```
2. **Валидация длины комментария:** парсер сканирует буфер назад с проверкой соответствия поля `comment_len` реальному размеру хвоста.

---

## Главные выводы

1. **Никогда не используйте fail-open в защитных фильтрах.** Если компонент очистки входных данных упал — операция должна блокироваться полностью.
2. **Остерегайтесь наивных сигнатурных сканеров.** Форматы с переменными комментариями (ZIP, TAR, PDF) нельзя парсить через `rfind` без проверки длины полей.
3. **Эшелонированная оборона работает.** Поведение Info-ZIP 6.0 и синхронная зачистка симлинков предотвратили эскалацию уязвимости до критического RCE.
