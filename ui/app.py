# -*- coding: utf-8 -*-
"""ShieldPy 主应用：侧边栏导航 + 多页面 + 通知。"""
import queue
import threading
import tkinter as tk
from tkinter import ttk

from core import __app_name__, __version__, logger
from core.config import config
from core.monitor import monitor

from .dashboard import DashboardPage
from .log_page import LogPage
from .process_page import ProcessPage
from .quarantine_page import QuarantinePage
from .scan_page import ScanPage
from .settings_page import SettingsPage
from .widgets import apply_theme, SidebarButton

NAV = [
    ("dashboard", "◈  仪表盘", "仪表盘"),
    ("quick", "⚡  快速扫描", "快速扫描"),
    ("full", "◉  全盘扫描", "全盘扫描"),
    ("custom", "▤  自定义扫描", "自定义扫描"),
    ("quarantine", "◇  隔离区", "隔离区"),
    ("process", "⚙  进程体检", "进程体检"),
    ("settings", "✦  设置", "设置"),
    ("logs", "☰  运行日志", "日志"),
]


class ShieldApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{__app_name__} v{__version__}")
        self.geometry("1280x800")
        self.minsize(1080, 700)
        self._theme_name = config.get("theme", "dark")
        self.theme = apply_theme(self, self._theme_name)
        self._notify_q = queue.Queue()
        self._nav_buttons = {}
        self._pages = {}
        self._current = None
        self._build_shell()
        self._poll_notify()
        logger.info(f"{__app_name__} v{__version__} 启动")
        self.after(500, self._auto_monitor)

    # ---------- 外壳 ----------
    def _build_shell(self):
        self.sidebar = tk.Frame(self, bg=self.theme["sidebar"], width=200)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        tk.Label(self.sidebar, text="◈ 玄盾卫士", bg=self.theme["sidebar"],
                 fg=self.theme["text"], font=("Microsoft YaHei UI", 14, "bold")).pack(
            anchor="w", padx=18, pady=(24, 4))
        tk.Label(self.sidebar, text="ShieldPy v" + __version__, bg=self.theme["sidebar"],
                 fg=self.theme["muted"], font=("Microsoft YaHei UI", 8)).pack(anchor="w", padx=18, pady=(0, 16))

        for key, label, _ in NAV:
            btn = SidebarButton(self.sidebar, text=label, command=lambda k=key: self.show_page(k),
                                theme=self.theme)
            btn.pack(fill="x", padx=8, pady=1)
            self._nav_buttons[key] = btn

        self.sidebar_status = tk.Label(self.sidebar, text="● 实时监控: 关", bg=self.theme["sidebar"],
                                       fg=self.theme["muted"], font=("Microsoft YaHei UI", 8),
                                       anchor="w")
        self.sidebar_status.pack(side="bottom", fill="x", padx=18, pady=16)

        # 内容区
        self.content = tk.Frame(self, bg=self.theme["bg"])
        self.content.pack(side="left", fill="both", expand=True)

        # 通知条（顶部）
        self.notify_frame = tk.Frame(self.content, bg=self.theme["warn"], height=0)
        self.notify_label = tk.Label(self.notify_frame, text="", bg=self.theme["warn"],
                                     fg="#1c1c1c", font=("Microsoft YaHei UI", 10, "bold"))
        self.notify_label.pack(fill="x", padx=20, pady=6)

        self.page_container = tk.Frame(self.content, bg=self.theme["bg"])
        self.page_container.pack(fill="both", expand=True)

        self.show_page("dashboard")

    def _auto_monitor(self):
        if config.get("realtime_monitor", False):
            dirs = config.get("realtime_dirs", [])
            if dirs:
                monitor.on_threat = self.monitor_threat_cb
                ok, _ = monitor.start(dirs)
                if ok:
                    self.show_notify("实时监控已恢复", f"监控 {len(dirs)} 个目录")
        self._update_sidebar_status()

    # ---------- 页面路由 ----------
    def show_page(self, key):
        if self._current:
            self._pages[self._current].pack_forget()
        if key not in self._pages:
            self._pages[key] = self._create_page(key)
        page = self._pages[key]
        page.pack(fill="both", expand=True)
        self._current = key
        for k, btn in self._nav_buttons.items():
            btn.set_active(k == key)
        if hasattr(page, "refresh"):
            try:
                page.refresh()
            except Exception:
                pass

    def _create_page(self, key):
        if key == "dashboard":
            return DashboardPage(self.page_container, self.theme, self)
        if key in ("quick", "full", "custom"):
            return ScanPage(self.page_container, self.theme, self, mode=key)
        if key == "quarantine":
            return QuarantinePage(self.page_container, self.theme, self)
        if key == "process":
            return ProcessPage(self.page_container, self.theme, self)
        if key == "settings":
            return SettingsPage(self.page_container, self.theme, self)
        if key == "logs":
            return LogPage(self.page_container, self.theme, self)
        raise ValueError(key)

    def start_scan(self, mode):
        self.show_page(mode)
        page = self._pages.get(mode)
        if isinstance(page, ScanPage):
            self.after(80, page.start)

    def scan_path(self, path):
        """对指定路径直接启动自定义查杀（右键菜单 / 命令行入口）。"""
        from core.config import config
        self.show_page("custom")
        page = self._pages.get("custom")
        if isinstance(page, ScanPage):
            page.target_var.set(path)
            config.set("last_custom_target", path)
            self.show_notify("自定义查杀", path)
            self.after(120, page.start)

    def refresh_dashboard(self):
        page = self._pages.get("dashboard")
        if page:
            try:
                page.refresh()
            except Exception:
                pass
        self._update_sidebar_status()

    def _update_sidebar_status(self):
        color = "#2e9e6b" if monitor.running else self.theme["muted"]
        txt = "● 实时监控: 开" if monitor.running else "● 实时监控: 关"
        self.sidebar_status.config(text=txt, fg=color)

    # ---------- 通知 ----------
    def show_notify(self, title, msg=""):
        self._notify_q.put((title, msg))

    def _poll_notify(self):
        try:
            while True:
                title, msg = self._notify_q.get_nowait()
                self._display_notify(title, msg)
        except queue.Empty:
            pass
        self.after(200, self._poll_notify)

    def _display_notify(self, title, msg):
        self.notify_label.config(text=f"{title}" + (f"  ·  {msg}" if msg else ""))
        self.notify_frame.config(height=30)
        self.notify_label.pack(fill="x", padx=20, pady=6)
        self.after(6000, self._hide_notify)

    def _hide_notify(self):
        self.notify_label.config(text="")
        self.notify_frame.config(height=0)
        self.notify_label.pack_forget()

    # ---------- 实时监控威胁回调（后台线程） ----------
    def monitor_threat_cb(self, item):
        logger.warning(f"[实时监控] 发现威胁: {item.threat} @ {item.path}")
        self._notify_q.put((f"⚠ 实时监控发现威胁: {item.threat[:60]}", item.path))

    # ---------- 主题 ----------
    def apply_theme(self, theme_name):
        self._theme_name = theme_name
        self.theme = apply_theme(self, theme_name)
        self.configure(bg=self.theme["bg"])
        for child in self.sidebar.winfo_children():
            child.destroy()
        for child in self.content.winfo_children():
            child.destroy()
        self._pages = {}
        self._current = None
        self._build_shell()
        self.show_notify("主题已切换", theme_name)


def run(scan_target=None):
    app = ShieldApp()
    if scan_target:
        app.after(350, lambda: app.scan_path(scan_target))
    app.mainloop()
