from __future__ import annotations

import logging
import queue
import signal
import sys
import threading
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    import tkinter as tk

from usb_guard.baiting_analyzer import BaitingAnalyzer, BaitingReport
from usb_guard.listener import UsbListener
from usb_guard.storage import get_removable_volume_paths, is_removable_storage_path

logger = logging.getLogger(__name__)


def create_listener() -> UsbListener:
    if sys.platform == "win32":
        from usb_guard.windows_listener import WindowsUsbListener

        return WindowsUsbListener()
    if sys.platform == "darwin":
        from usb_guard.macos_listener import MacOsUsbListener

        return MacOsUsbListener()
    raise RuntimeError("Solo se admite Windows y macOS.")


def _open_analyzing_popup(root: "tk.Tk", path: str) -> "tk.Toplevel":
    """Ventana breve, no modal: indica que el análisis está en curso."""
    import tkinter as tk
    from tkinter import ttk

    win = tk.Toplevel(root)
    win.title("Analizando USB")
    win.transient(root)
    win.resizable(False, False)
    try:
        win.attributes("-topmost", True)
    except tk.TclError:
        pass
    frm = ttk.Frame(win, padding=(20, 16))
    frm.pack(fill="both", expand=True)
    ttk.Label(
        frm,
        text="Analizando el dispositivo USB…",
        font=("", 13, "bold"),
    ).pack(anchor="center")
    ttk.Label(
        frm,
        text="No abras ni ejecutes archivos del volumen hasta finalizar.",
        wraplength=380,
        justify="center",
    ).pack(anchor="center", pady=(6, 0))
    short = path if len(path) < 72 else path[:36] + "…" + path[-32:]
    ttk.Label(frm,
              text=short,
              font=("TkFixedFont", 9)
              ).pack(anchor="center", pady=(10, 0))
    win.update_idletasks()
    w, h = win.winfo_reqwidth(), win.winfo_reqheight()
    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
    win.geometry(f"+{max(0, (sw - w) // 2)}+{max(0, (sh - h) // 3)}")
    return win


def _show_malicious_disclaimer(root: "tk.Tk", report: BaitingReport) -> None:
    from tkinter import ttk, scrolledtext
    import tkinter as tk

    win = tk.Toplevel(root)
    win.title("⚠️ USB potencialmente maliciosa")
    win.geometry("680x580")
    win.transient(root)
    win.configure(bg="#2b2b2b")
    try:
        win.attributes("-topmost", True)
    except tk.TclError:
        pass

    main_frame = tk.Frame(win, bg="#2b2b2b", padx=20, pady=15)
    main_frame.pack(fill="both", expand=True)

    header_frame = tk.Frame(main_frame, bg="#2b2b2b")
    header_frame.pack(fill="x", pady=(0, 15))

    warning_label = tk.Label(
        header_frame,
        text="⚠️",
        font=("", 48),
        bg="#2b2b2b",
        fg="#f0ad4e"
    )
    warning_label.pack(side="left", padx=(0, 15))

    header_text = tk.Frame(header_frame, bg="#2b2b2b")
    header_text.pack(side="left", fill="both", expand=True)

    tk.Label(
        header_text,
        text="USB potencialmente maliciosa",
        font=("", 16, "bold"),
        bg="#2b2b2b",
        fg="#ff6b6b",
        anchor="w"
    ).pack(fill="x")

    tk.Label(
        header_text,
        text="Se detectaron indicadores de posible USB baiting o contenido de alto riesgo.",
        font=("", 11),
        bg="#2b2b2b",
        fg="#cccccc",
        anchor="w",
        wraplength=480
    ).pack(fill="x", pady=(5, 0))

    info_frame = tk.Frame(main_frame, bg="#363636", padx=12, pady=10)
    info_frame.pack(fill="x", pady=(0, 12))

    tk.Label(
        info_frame,
        text=f"📂 Ruta: {report.path}",
        font=("", 11),
        bg="#363636",
        fg="#ffffff",
        anchor="w"
    ).pack(fill="x")

    risk_color = "#ff4444" if report.risk_score >= 70 else "#f0ad4e" if report.risk_score >= 40 else "#5cb85c"
    tk.Label(
        info_frame,
        text=f"🎯 Puntuación de riesgo: {report.risk_score}/100",
        font=("", 11, "bold"),
        bg="#363636",
        fg=risk_color,
        anchor="w"
    ).pack(fill="x", pady=(5, 0))

    tk.Label(
        main_frame,
        text="🔍 Motivos principales:",
        font=("", 12, "bold"),
        bg="#2b2b2b",
        fg="#ffffff",
        anchor="w"
    ).pack(fill="x", pady=(0, 5))

    reasons_frame = tk.Frame(main_frame, bg="#3a3a3a", padx=10, pady=8)
    reasons_frame.pack(fill="x", pady=(0, 12))

    for r in report.reasons[:8]:
        tk.Label(
            reasons_frame,
            text=f"• {r}",
            font=("", 10),
            bg="#3a3a3a",
            fg="#e0e0e0",
            anchor="w",
            wraplength=600
        ).pack(fill="x", pady=1)

    if report.social_engineering_analysis and "files" in report.social_engineering_analysis:
        social_items = report.social_engineering_analysis.get("files", [])
        if social_items:
            tk.Label(
                main_frame,
                text="Análisis de Ingeniería Social:",
                font=("", 12, "bold"),
                bg="#2b2b2b",
                fg="#f0ad4e",
                anchor="w"
            ).pack(fill="x", pady=(0, 5))

            social_frame = tk.Frame(main_frame, bg="#2d3748")
            social_frame.pack(fill="both", expand=True, pady=(0, 12))

            canvas = tk.Canvas(social_frame, bg="#2d3748",
                               highlightthickness=0)
            scrollbar = ttk.Scrollbar(
                social_frame, orient="vertical", command=canvas.yview)
            scrollable = tk.Frame(canvas, bg="#2d3748")

            scrollable.bind(
                "<Configure>",
                lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
            )

            canvas.create_window((0, 0), window=scrollable, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)

            for item in social_items:
                name = item.get("name", "Desconocido")
                analisys = item.get("analisys", "Sin análisis")
                score = item.get("score", 0)
                
                score_color = "#ff4444" if score >= 70 else "#f0ad4e" if score >= 40 else "#5cb85c"

                item_frame = tk.Frame(
                    scrollable, bg="#3d4a5c", padx=10, pady=8)
                item_frame.pack(fill="x", padx=5, pady=4)

                header_row = tk.Frame(item_frame, bg="#3d4a5c")
                header_row.pack(fill="x")

                tk.Label(
                    header_row,
                    text=f"📄 {name}",
                    font=("", 10, "bold"),
                    bg="#3d4a5c",
                    fg="#63b3ed",
                    anchor="w"
                ).pack(side="left", fill="x", expand=True)

                score_frame = tk.Frame(header_row, bg=score_color, padx=8, pady=2)
                score_frame.pack(side="right")

                tk.Label(
                    score_frame,
                    text=f"⚡ {score}/100",
                    font=("", 9, "bold"),
                    bg=score_color,
                    fg="white"
                ).pack()

                tk.Label(
                    item_frame,
                    text=analisys,
                    font=("", 9),
                    bg="#3d4a5c",
                    fg="#cbd5e0",
                    anchor="w",
                    wraplength=580,
                    justify="left"
                ).pack(fill="x", pady=(4, 0))

            canvas.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")

    warning_footer = tk.Label(
        main_frame,
        text="⛔ No ejecutes archivos de este volumen. Extrae el dispositivo de forma segura y consulta a tu equipo de seguridad.",
        font=("", 10, "bold"),
        bg="#5a2a2a",
        fg="#ff9999",
        anchor="w",
        wraplength=620,
        padx=10,
        pady=8
    )
    warning_footer.pack(fill="x", pady=(0, 10))

    btn = tk.Button(
        main_frame,
        text="Entendido",
        font=("", 11, "bold"),
        bg="#4a90d9",
        fg="white",
        padx=30,
        pady=8,
        command=win.destroy,
        cursor="hand2"
    )
    btn.pack(pady=(0, 5))

    win.update_idletasks()
    w, h = win.winfo_width(), win.winfo_height()
    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
    win.geometry(f"{w}x{h}+{max(0, (sw - w) // 2)}+{max(0, (sh - h) // 3)}")


def _analyze_and_notify(
    path: str,
    analyzer: BaitingAnalyzer,
    root: Optional["tk.Tk"],
) -> None:
    if not is_removable_storage_path(path):
        logger.info("Ignorado (no parece almacenamiento extraíble): %s", path)
        return

    logger.info("Analizando volumen extraíble: %s", path)
    analyzing: Optional["tk.Toplevel"] = None
    if root is not None:
        analyzing = _open_analyzing_popup(root, path)
        root.update_idletasks()

    if root is None:
        print(f"\n[Analizando USB] {path} …", flush=True)

    try:
        report = analyzer.analyze(path)
    except OSError as e:
        logger.error("Error al analizar %s: %s", path, e)
        return
    finally:
        if analyzing is not None:
            try:
                analyzing.destroy()
            except Exception:
                pass
        if root is not None:
            try:
                root.update_idletasks()
            except Exception:
                pass

    logger.info(
        "Resultado %s: riesgo=%s malicioso=%s",
        path,
        report.risk_score,
        report.is_potentially_malicious,
    )
    if report.is_potentially_malicious:
        logger.warning("Posible baiting: %s", report.reasons)
        if root is not None:
            _show_malicious_disclaimer(root, report)
        else:
            print("\n*** ADVERTENCIA: USB potencialmente maliciosa ***", flush=True)
            print(f"Ruta: {report.path}", flush=True)
            print(f"Puntuación de riesgo: {report.risk_score}/100", flush=True)
            print("\nMotivos principales:", flush=True)
            for r in report.reasons:
                print(f"  - {r}", flush=True)

            if report.social_engineering_analysis and "files" in report.social_engineering_analysis:
                print("\n═══ ANÁLISIS DE INGENIERÍA SOCIAL ═══", flush=True)
                for item in report.social_engineering_analysis.get("files", []):
                    name = item.get("name", "Desconocido")
                    analisys = item.get("analisys", "Sin análisis")
                    score = item.get("score", 0)
                    print(f"\n📄 {name} [Score: {score}/100]", flush=True)
                    print(f"   → {analisys}", flush=True)


def _run_headless_console(analyzer: BaitingAnalyzer, listener: UsbListener) -> None:
    mount_queue: "queue.Queue[str]" = queue.Queue()

    def on_volume(path: str) -> None:
        mount_queue.put(path)

    listener.set_on_volume_mounted(on_volume)
    listener.start()

    print(
        "Monitor USB activo. Conecta un dispositivo de almacenamiento extraíble.\n"
        "Ctrl+C para salir.",
        flush=True,
    )
    try:
        while True:
            try:
                path = mount_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            _analyze_and_notify(path, analyzer, None)
    except KeyboardInterrupt:
        pass
    finally:
        listener.stop()


def run() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    analyzer = BaitingAnalyzer()
    listener = create_listener()
    mount_queue: queue.Queue[str] = queue.Queue()

    try:
        import tkinter as tk
        from tkinter import messagebox, ttk
    except ImportError:
        logger.warning(
            "tkinter no está instalado; modo solo consola. "
        )
        _run_headless_console(analyzer, listener)
        return

    root = tk.Tk()
    root.title("USB Guard — almacenamiento extraíble")
    root.minsize(520, 380)
    root.geometry("640x420")

    def on_volume_from_listener(path: str) -> None:
        """Solo encola; Tk se actualiza en el hilo principal."""
        mount_queue.put(path)

    listener.set_on_volume_mounted(on_volume_from_listener)
    listener.start()

    main = ttk.Frame(root, padding=12)
    main.pack(fill="both", expand=True)

    ttk.Label(
        main,
        text="Volúmenes extraíbles detectados (selecciona uno o varios y pulsa Analizar).",
        wraplength=580,
    ).pack(anchor="w")

    list_frame = ttk.Frame(main)
    list_frame.pack(fill="both", expand=True, pady=(8, 8))

    scroll = ttk.Scrollbar(list_frame)
    scroll.pack(side="right", fill="y")

    listbox = tk.Listbox(
        list_frame,
        selectmode=tk.EXTENDED,
        yscrollcommand=scroll.set,
        font=("TkFixedFont", 11),
        height=12,
    )
    listbox.pack(side="left", fill="both", expand=True)
    scroll.config(command=listbox.yview)

    status = tk.StringVar(
        value="Monitor activo: se analizarán automáticamente los nuevos volúmenes.")

    def refresh_volume_list() -> None:
        listbox.delete(0, tk.END)
        for p in sorted(get_removable_volume_paths()):
            listbox.insert(tk.END, p)

    def analyze_paths(paths: list[str]) -> None:
        for path in paths:
            if not path.strip():
                continue
            _analyze_and_notify(path, analyzer, root)

    def on_analyze_selected() -> None:
        sel = listbox.curselection()
        if not sel:
            messagebox.showinfo(
                "Selección",
                "Selecciona al menos un volumen en la lista.",
                parent=root,
            )
            return
        paths = [listbox.get(i) for i in sel]
        analyze_paths(paths)

    btn_row = ttk.Frame(main)
    btn_row.pack(fill="x", pady=(0, 8))

    ttk.Button(btn_row, text="Actualizar lista", command=refresh_volume_list).pack(
        side="left", padx=(0, 8)
    )
    ttk.Button(btn_row, text="Analizar seleccionado(s)", command=on_analyze_selected).pack(
        side="left"
    )

    ttk.Label(main, textvariable=status, foreground="gray").pack(anchor="w")

    def poll_mount_queue() -> None:
        try:
            while True:
                path = mount_queue.get_nowait()
                refresh_volume_list()
                status.set(f"Nuevo volumen detectado; analizando: {path}")
                root.update_idletasks()
                _analyze_and_notify(path, analyzer, root)
                status.set("Monitor activo: listo para nuevos dispositivos.")
        except queue.Empty:
            pass
        root.after(120, poll_mount_queue)

    def on_close() -> None:
        listener.stop()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)

    def handle_sigint(_signum: int, _frame: object) -> None:
        root.after(0, on_close)

    try:
        signal.signal(signal.SIGINT, handle_sigint)
    except (ValueError, OSError):
        pass

    refresh_volume_list()
    root.after(120, poll_mount_queue)
    root.mainloop()


if __name__ == "__main__":
    run()
