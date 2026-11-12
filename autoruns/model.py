from dataclasses import dataclass, field

KIND_TITLES = {
    "run": "Реестр (Run)",
    "startup": "Папка автозагрузки",
    "service": "Служба",
    "task": "Планировщик заданий",
    "winlogon": "Winlogon",
    "wmi": "WMI",
}
LEVELS = ["pending", "normal", "check", "suspicious", "threat"]  # по возрастанию риска
LEVEL_TEXT = {"pending": "…", "normal": "Норма", "check": "Проверить",
              "suspicious": "Подозрительно", "threat": "Угроза"}


def raise_level(current: str, new: str) -> str:
    return new if LEVELS.index(new) > LEVELS.index(current) else current


@dataclass
class Entry:
    kind: str
    name: str
    location: str          # где найдено: ключ реестра, папка, служба...
    command: str           # строка запуска
    exe: str = ""          # путь к исполняемому файлу, если удалось определить
    enabled: bool = True
    extra: dict = field(default_factory=dict)  # данные для исправления и отката
    sig: str = ""
    sig_status: str = ""
    verdict: str = ""      # результат check_file (причина обнаружения)
    flags: list[str] = field(default_factory=list)
    level: str = "pending"
    assessed: bool = False

    @property
    def key(self) -> str:
        return f"{self.kind}|{self.location}|{self.name}"
