r"""Запуск исследовательского стенда (bench/stand.py):

    python tools/stand.py --malware D:\samples\mal --clean "C:\Program Files" --limit 5000

Нужен хотя бы один набор: только --clean даёт долю ложных срабатываний (FPR), только
--malware — полноту (TPR). Итог — reports/stand/<дата_время>/summary.md и files.csv.
"""
import argparse
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
os.chdir(ROOT)
sys.path.insert(0, str(ROOT))


def main() -> int:
    parser = argparse.ArgumentParser(description="TPR/FPR по слоям обнаружения")
    parser.add_argument("--malware", help="папка с заведомо вредоносными файлами")
    parser.add_argument("--clean", help="папка с заведомо чистыми файлами")
    parser.add_argument("--limit", type=int, default=0, help="не больше файлов из каждой папки")
    parser.add_argument("--out", help="куда сохранить (по умолчанию reports/stand/<дата>)")
    args = parser.parse_args()
    if not args.malware and not args.clean:
        parser.error("укажите --malware и/или --clean")

    from analyzer.folderview import rules_and_bases
    from bench import stand
    print("Загружаю базы и правила...")
    signatures, rules, _whitelist = rules_and_bases()
    malware = stand.collect(args.malware, args.limit or None) if args.malware else []
    clean = stand.collect(args.clean, args.limit or None) if args.clean else []
    print(f"Вредоносных: {len(malware)}, чистых: {len(clean)}")
    result = stand.run(malware, clean, stand.make_layers(signatures, rules),
                       progress=lambda done, total: print(f"  {done} из {total}", end="\r"))
    out = Path(args.out) if args.out else ROOT / "reports" / "stand" / time.strftime(
        "%Y-%m-%d_%H-%M-%S")
    note = f"Вредоносные: `{args.malware or '—'}`; чистые: `{args.clean or '—'}`."
    summary = stand.save(result, out, note)
    print("\n" + stand.table(result))
    print(f"\nСохранено: {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
