# -*- coding: utf-8 -*-
"""实时监控：监视指定目录的新增/修改文件并自动扫描。
优先使用 watchdog（若已安装），否则降级为低开销轮询。"""
import os
import threading
import time

from . import logger
from .config import config
from .scanner import engine
from .signature import file_hashes

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except Exception:
    HAS_WATCHDOG = False


class RealtimeMonitor:
    def __init__(self):
        self._observer = None
        self._poll_thread = None
        self._stop = threading.Event()
        self.on_threat = None      # callback(ThreatItem)
        self._seen = {}            # 轮询模式用：path -> (mtime, size)
        self.running = False

    def start(self, dirs):
        if self.running:
            return False, "监控已在运行"
        dirs = [d for d in dirs if os.path.isdir(d)]
        if not dirs:
            return False, "监控目录无效"
        self._stop.clear()
        if HAS_WATCHDOG:
            self._start_watchdog(dirs)
        else:
            self._start_poll(dirs)
        self.running = True
        logger.info(f"实时监控已启动: {dirs}（引擎: watchdog 或 poll）")
        return True, "实时监控已启动"

    def stop(self):
        if not self.running:
            return
        self._stop.set()
        if self._observer:
            try:
                self._observer.stop()
                self._observer.join(timeout=3)
            except Exception:
                pass
            self._observer = None
        if self._poll_thread:
            self._poll_thread.join(timeout=3)
            self._poll_thread = None
        self.running = False
        logger.info("实时监控已停止")

    # ---- watchdog 模式 ----
    def _start_watchdog(self, dirs):
        class _Handler(FileSystemEventHandler):
            def on_created(self, event):
                self._on_event(event)
            def on_modified(self, event):
                self._on_event(event)
        h = _Handler()
        h._parent = self
        self._observer = Observer()
        for d in dirs:
            self._observer.schedule(h, d, recursive=True)
        self._observer.daemon = True
        self._observer.start()

    def _on_event(self, event):
        try:
            if event.is_directory:
                return
            p = event.src_path
            # 忽略临时/锁文件
            base = os.path.basename(p).lower()
            if base.endswith((".tmp", ".temp", "~", ".lock", ".swp")):
                return
            if os.path.isfile(p):
                item = engine.scan_file(p)
                if item:
                    logger.warning(f"[实时监控] 发现威胁: {item.threat} @ {p}")
                    if self.on_threat:
                        self.on_threat(item)
        except Exception:
            pass

    # ---- 轮询模式 ----
    def _start_poll(self, dirs):
        self._dirs = dirs
        self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._poll_thread.start()

    def _poll_loop(self):
        interval = max(1.0, config.get("realtime_poll_interval", 2.0))
        while not self._stop.is_set():
            for d in self._dirs:
                if self._stop.is_set():
                    break
                try:
                    self._poll_dir(d)
                except Exception:
                    pass
            self._stop.wait(interval)

    def _poll_dir(self, root):
        for dirpath, dirnames, filenames in os.walk(root):
            if self._stop.is_set():
                break
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                try:
                    st = os.stat(full)
                    key = (st.st_mtime_ns, st.st_size)
                    prev = self._seen.get(full)
                    if prev != key:
                        self._seen[full] = key
                        # 只处理新增（之前未见过）或变化
                        if prev is not None or len(self._seen) < 50:
                            item = engine.scan_file(full)
                            if item and self.on_threat:
                                self.on_threat(item)
                except Exception:
                    continue
            if len(self._seen) > 50000:   # 防膨胀
                self._seen.clear()


# 全局单例
monitor = RealtimeMonitor()
