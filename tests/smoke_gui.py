# -*- coding: utf-8 -*-
"""GUI 冒烟测试：构建所有页面，验证无异常后自动关闭。
用法: python tests/smoke_gui.py
"""
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from ui.app import ShieldApp

app = ShieldApp()
app.update()

pages = ["dashboard", "quick", "full", "custom", "quarantine", "process", "settings", "logs"]
for key in pages:
    app.show_page(key)
    app.update()
    print(f"[OK] 页面构建成功: {key}")

# 模拟一次扫描（对测试样本目录）
app.show_page("custom")
scan_page = app._pages["custom"]
from core.config import BASE_DIR
scan_page.target_var.set(str(BASE_DIR / "tests" / "sample"))
scan_page.start()
import time
for _ in range(300):
    app.update()
    if not scan_page._scanning:
        break
    time.sleep(0.03)
print(f"[OK] 扫描完成，发现 {len(scan_page._pending_threats)} 项威胁")
for t in scan_page._pending_threats:
    print(f"     - {Path(t.path).name}: {t.detection}")

# 隔离第一个威胁
if scan_page._pending_threats:
    first = scan_page._pending_threats[0]
    from core.quarantine import quarantine
    ok, res = quarantine.quarantine_file(first.path, threat=first.threat,
                                         detection=first.detection, md5=first.md5)
    print(f"[OK] 隔离流程: {ok}")

app.destroy()
print("\n=== GUI 冒烟测试通过 ===")
