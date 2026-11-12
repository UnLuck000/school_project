"""Проверка пароля по базе утечек Have I Been Pwned (Pwned Passwords).

Пароль не покидает компьютер: на сервер уходят только первые 5 символов его SHA-1
(k-анонимность), сервер возвращает все хэши с таким началом (сотни), сравнение — здесь.
Заголовок Add-Padding добавляет в ответ пустые записи, чтобы по размеру ответа нельзя было
ничего узнать.
"""
import hashlib
import urllib.request

API = "https://api.pwnedpasswords.com/range/"


def split_hash(password: str) -> tuple[str, str]:
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return digest[:5], digest[5:]


def count_in_response(text: str, suffix: str) -> int:
    for line in text.splitlines():
        found, _, count = line.strip().partition(":")
        if found.upper() == suffix:
            return int(count or 0)  # записи-заполнители приходят с числом 0
    return 0


def times_pwned(password: str, timeout: float = 15.0) -> int:
    """Сколько раз пароль встречался в утечках. OSError — нет связи."""
    prefix, suffix = split_hash(password)
    request = urllib.request.Request(API + prefix, headers={
        "User-Agent": "StretchBIT-pwned/1.0", "Add-Padding": "true"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        text = response.read().decode("utf-8", "replace")
    return count_in_response(text, suffix)
