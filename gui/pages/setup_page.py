"""Setup page — collects all user inputs before running the pipeline."""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDateEdit,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.investigation import list_profiles, get_profile


class SetupPage(QWidget):
    run_requested = Signal(dict)  # emits a config dict when Run is clicked

    def __init__(self, agents_manifest: list, parent=None):
        super().__init__(parent)
        self._agents_manifest = agents_manifest
        self._agent_checks: dict[str, QCheckBox] = {}
        self._profile_keyword_widgets: dict[str, QTextEdit | QLineEdit] = {}
        self._build_ui()

    def _build_ui(self):
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("QScrollArea{background:transparent;border:none}")

        content = QWidget()
        content.setStyleSheet("background:transparent")
        scroll.setWidget(content)

        main = QVBoxLayout(content)
        main.setContentsMargins(32, 24, 32, 32)
        main.setSpacing(20)

        # ── Case info ──────────────────────────────────────────────────
        case_group = self._group("Case Information")
        case_form = QFormLayout()
        case_form.setSpacing(10)
        self._customer = QLineEdit()
        self._customer.setPlaceholderText("e.g. Acme Corporation")
        self._date_edit = QDateEdit()
        self._date_edit.setCalendarPopup(True)
        from PySide6.QtCore import QDate
        self._date_edit.setDate(QDate.currentDate())
        self._case_ref = QLineEdit()
        self._case_ref.setPlaceholderText("Auto-generated if blank  (e.g. DFIR-2026-04-26-001)")
        case_form.addRow("Customer name:", self._customer)
        case_form.addRow("Investigation date:", self._date_edit)
        case_form.addRow("Case reference:", self._case_ref)
        case_group.setLayout(case_form)
        main.addWidget(case_group)

        # ── Inputs ────────────────────────────────────────────────────
        inputs_group = self._group("Inputs")
        inputs_form = QFormLayout()
        inputs_form.setSpacing(10)

        self._drive = QLineEdit()
        self._drive.setPlaceholderText("e.g. E:\\  or  /mnt/evidence")
        drive_row = self._browse_row(self._drive, directory=True)

        self._output = QLineEdit()
        self._output.setPlaceholderText("e.g. D:\\Cases\\Acme-2026-04-26")
        output_row = self._browse_row(self._output, directory=True)

        workers_label = QLabel("Auto (max CPU cores)")
        workers_label.setStyleSheet("color:#58a6ff;font-weight:600")

        inputs_form.addRow("Mounted drive:", drive_row)
        inputs_form.addRow("Output folder:", output_row)
        inputs_form.addRow("Workers:", workers_label)
        inputs_group.setLayout(inputs_form)
        main.addWidget(inputs_group)

        # ── AI augmentation (OPTIONAL) ────────────────────────────────────
        ai_group = self._group("AI Augmentation (Optional)")
        ai_layout = QVBoxLayout()

        self._ai_enabled = QCheckBox("Enable AI analysis  (slower, may hallucinate)")
        self._ai_enabled.setChecked(False)
        self._ai_enabled.setStyleSheet(
            "color:#e6edf3;font-weight:600;font-size:12px;padding:4px 0;"
        )
        ai_layout.addWidget(self._ai_enabled)

        ai_hint = QLabel(
            "<b>By default, this tool runs in fully-deterministic automation mode.</b><br/>"
            "The Formal Investigation Report is built from curated indicator lists and "
            "evidence-cited rules — no AI inference, no hallucinations, fully reproducible.<br/><br/>"
            "Enable AI only when you want an additional <i>narrative-style</i> report on top "
            "of the deterministic one. AI analysis can take 30–60+ minutes on CPU and may "
            "produce false positives. The deterministic report is always generated regardless."
        )
        ai_hint.setStyleSheet("color:#8b949e;font-size:10px;padding:4px 8px;")
        ai_hint.setWordWrap(True)
        ai_layout.addWidget(ai_hint)

        self._model = QLineEdit()
        self._model.setPlaceholderText(
            "ollama:phi3:mini   (or ollama:llama3:8b, ollama:qwen2.5:7b, …)"
        )
        self._model.setEnabled(False)
        self._model_status = QLabel("")
        self._model_status.setStyleSheet("font-size:10px;")

        self._check_btn = QPushButton("Check")
        self._check_btn.setFixedWidth(54)
        self._check_btn.setEnabled(False)
        self._check_btn.setStyleSheet("""
            QPushButton{background:#1f2937;color:#58a6ff;border:1px solid #30363d;
                        border-radius:4px;padding:2px 6px;font-size:11px;}
            QPushButton:hover{background:#252b3b}
            QPushButton:disabled{background:#161b22;color:#444d56;border-color:#21262d;}
        """)
        self._check_btn.clicked.connect(self._check_model_now)

        model_row = QWidget()
        model_hl = QHBoxLayout(model_row)
        model_hl.setContentsMargins(8, 0, 0, 0)
        model_hl.setSpacing(6)
        model_lbl = QLabel("Model:")
        model_lbl.setStyleSheet("color:#8b949e;font-size:11px;")
        model_lbl.setFixedWidth(50)
        model_hl.addWidget(model_lbl)
        model_hl.addWidget(self._model)
        model_hl.addWidget(self._check_btn)
        model_hl.addWidget(self._model_status)
        ai_layout.addWidget(model_row)

        # ── Report output + malware-analysis options ──────────────────────
        self._pdf_enabled = QCheckBox(
            "Generate PDF report with evidence-exhibit screenshots  (requires Chromium)")
        self._pdf_enabled.setChecked(False)
        self._pdf_enabled.setStyleSheet("color:#e6edf3;font-size:11px;padding:2px 0;")
        ai_layout.addWidget(self._pdf_enabled)

        self._run_capa = QCheckBox("Run capa capability analysis on located binaries (malware profile)")
        self._run_capa.setChecked(True)
        self._run_capa.setStyleSheet("color:#8b949e;font-size:11px;padding:2px 0;")
        ai_layout.addWidget(self._run_capa)

        self._run_yara = QCheckBox("Run YARA signature scan on located binaries (malware profile)")
        self._run_yara.setChecked(True)
        self._run_yara.setStyleSheet("color:#8b949e;font-size:11px;padding:2px 0;")
        ai_layout.addWidget(self._run_yara)

        # Toggle field enable state with checkbox
        def _toggle_ai(checked: bool):
            self._model.setEnabled(checked)
            self._check_btn.setEnabled(checked)
            self._model_status.setText("" if not checked else self._model_status.text())
        self._ai_enabled.toggled.connect(_toggle_ai)

        ai_group.setLayout(ai_layout)
        main.addWidget(ai_group)

        # ── Investigation prompt ───────────────────────────────────────
        prompt_group = self._group("Investigation Prompt")
        prompt_layout = QVBoxLayout()
        hint = QLabel(
            "Describe the case background and what angles to investigate. "
            "Keywords drive the deterministic engine's focus areas (USB, cloud, "
            "credentials, lateral movement, etc.) and — if enabled — the AI prompt."
        )
        hint.setStyleSheet("color:#8b949e;font-size:11px;")
        hint.setWordWrap(True)
        self._prompt = QTextEdit()
        self._prompt.setPlaceholderText(
            "Case background: Laptop seized on 2026-04-25 from a departing employee at Acme Corp.\n"
            "Suspected activity: Data exfiltration via USB drive before resignation.\n\n"
            "Investigate the following angles:\n"
            "  • USB device connection history and file access timestamps\n"
            "  • Recently accessed documents, archives (.zip, .7z, .rar) and large file operations\n"
            "  • Browser history for uploads, cloud storage, Dropbox, Google Drive, OneDrive\n"
            "  • LNK / Recent files pointing to external drive paths\n"
            "  • Prefetch entries for archive tools (7-Zip, WinRAR, robocopy, xcopy)\n"
            "  • Any persistence mechanisms or unusual scheduled tasks added recently\n"
            "  • RDP / remote access indicators"
        )
        self._prompt.setMinimumHeight(180)
        prompt_layout.addWidget(hint)
        prompt_layout.addWidget(self._prompt)
        prompt_group.setLayout(prompt_layout)
        main.addWidget(prompt_group)

        # ── Case Profile + dynamic keyword prompts ────────────────────────
        profile_group = self._group("Case Profile (Determines What to Investigate)")
        profile_outer = QVBoxLayout()
        profile_outer.setSpacing(8)

        profile_hint = QLabel(
            "Pick the kind of case you're investigating. Each profile runs a tailored "
            "set of detection modules and asks for case-specific keywords (sensitive "
            "filenames for DLP, malware names for compromise cases, etc.). The "
            "deterministic engine then searches every parsed artefact for matches."
        )
        profile_hint.setStyleSheet("color:#8b949e;font-size:11px;padding:0 0 4px 0;")
        profile_hint.setWordWrap(True)
        profile_outer.addWidget(profile_hint)

        self._profile_combo = QComboBox()
        self._profile_combo.setStyleSheet("""
            QComboBox{background:#0d1117;color:#e6edf3;border:1px solid #30363d;
                      border-radius:4px;padding:6px 10px;font-size:12px;font-weight:600}
            QComboBox QAbstractItemView{background:#161b22;color:#e6edf3;
                                        border:1px solid #30363d;
                                        selection-background-color:#1f6feb}
        """)
        self._all_profiles = list_profiles()
        for p in self._all_profiles:
            self._profile_combo.addItem(p.display_name, p.key)
        profile_outer.addWidget(self._profile_combo)

        self._profile_descr = QLabel("")
        self._profile_descr.setStyleSheet(
            "color:#79c0ff;font-size:10px;background:#0d1117;"
            "border:1px solid #21262d;border-radius:4px;padding:8px 10px;"
            "font-style:italic;"
        )
        self._profile_descr.setWordWrap(True)
        profile_outer.addWidget(self._profile_descr)

        # Container for dynamic keyword fields
        self._keywords_container = QFrame()
        self._keywords_container.setStyleSheet("background:transparent;")
        self._keywords_layout = QVBoxLayout(self._keywords_container)
        self._keywords_layout.setContentsMargins(0, 8, 0, 0)
        self._keywords_layout.setSpacing(8)
        profile_outer.addWidget(self._keywords_container)

        self._profile_combo.currentIndexChanged.connect(self._on_profile_changed)
        profile_group.setLayout(profile_outer)
        main.addWidget(profile_group)

        # Trigger initial profile render
        self._on_profile_changed()

        # ── Agents ────────────────────────────────────────────────────
        agents_group = self._group("Forensic Agents")
        agents_layout = QVBoxLayout()
        for agent in self._agents_manifest:
            row = QHBoxLayout()
            cb = QCheckBox(agent["display_name"])
            cb.setChecked(agent.get("enabled_by_default", True))
            cb.setStyleSheet("color:#e6edf3;font-weight:500;")
            self._agent_checks[agent["name"]] = cb
            desc = QLabel(agent.get("description", "")[:90])
            desc.setStyleSheet("color:#8b949e;font-size:10px;")
            row.addWidget(cb)
            row.addWidget(desc)
            row.addStretch()
            agents_layout.addLayout(row)
        agents_group.setLayout(agents_layout)
        main.addWidget(agents_group)

        # ── Run button ────────────────────────────────────────────────
        run_row = QHBoxLayout()
        run_row.addStretch()
        self._run_btn = QPushButton("▶  Run Forensics")
        self._run_btn.setFixedHeight(44)
        self._run_btn.setMinimumWidth(200)
        self._run_btn.setStyleSheet("""
            QPushButton {
                background: #1f6feb;
                color: white;
                border: none;
                border-radius: 6px;
                font-size: 14px;
                font-weight: 700;
                letter-spacing: 1px;
            }
            QPushButton:hover { background: #388bfd; }
            QPushButton:pressed { background: #1158c7; }
            QPushButton:disabled { background: #30363d; color: #8b949e; }
        """)
        self._run_btn.clicked.connect(self._on_run)
        run_row.addWidget(self._run_btn)
        main.addLayout(run_row)
        main.addStretch()

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

    def _group(self, title: str) -> QGroupBox:
        g = QGroupBox(title)
        g.setStyleSheet("""
            QGroupBox {
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                margin-top: 8px;
                padding: 12px;
                font-weight: 600;
                color: #58a6ff;
                font-size: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 8px;
                left: 12px;
                top: -2px;
            }
        """)
        return g

    def _browse_row(self, line_edit: QLineEdit, directory: bool = True) -> QWidget:
        w = QWidget()
        row = QHBoxLayout(w)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(6)
        row.addWidget(line_edit)
        btn = QPushButton("Browse…")
        btn.setFixedWidth(80)
        btn.setStyleSheet("""
            QPushButton {
                background:#1f2937;color:#58a6ff;border:1px solid #30363d;
                border-radius:4px;padding:4px 8px;font-size:11px;
            }
            QPushButton:hover{background:#252b3b}
        """)

        def browse():
            if directory:
                path = QFileDialog.getExistingDirectory(self, "Select folder")
            else:
                path, _ = QFileDialog.getOpenFileName(self, "Select file")
            if path:
                line_edit.setText(path)

        btn.clicked.connect(browse)
        row.addWidget(btn)
        return w

    def _on_run(self):
        # Validate required fields
        errors = []
        if not self._drive.text().strip():
            errors.append("Mounted drive path is required.")
        if not self._output.text().strip():
            errors.append("Output folder is required.")
        if not self._customer.text().strip():
            errors.append("Customer name is required.")
        # LLM model is only required when AI is enabled
        if self._ai_enabled.isChecked() and not self._model.text().strip():
            errors.append("LLM model is required when AI analysis is enabled "
                          "(e.g. ollama:phi3:mini), or uncheck 'Enable AI analysis'.")

        if errors:
            QMessageBox.warning(self, "Missing Input", "\n".join(errors))
            return

        enabled_agents = [name for name, cb in self._agent_checks.items() if cb.isChecked()]
        if not enabled_agents:
            QMessageBox.warning(self, "No Agents", "Select at least one agent to run.")
            return

        # If AI is disabled, skip validation and start immediately
        if not self._ai_enabled.isChecked():
            self._emit_run_config(skip_llm=True)
            return

        # Validate LLM model before starting (async so UI stays responsive)
        self._run_btn.setEnabled(False)
        self._run_btn.setText("Validating model...")
        model_spec = self._model.text().strip()

        class _LLMCheckThread(QThread):
            result = Signal(bool, str)
            def __init__(self, spec, parent=None):
                super().__init__(parent)
                self._spec = spec
            def run(self):
                from core.llm_client import LLMClient
                ok, msg = LLMClient.validate_model_spec(self._spec)
                self.result.emit(ok, msg)

        self._llm_check = _LLMCheckThread(model_spec, self)
        self._llm_check.result.connect(self._on_llm_check_done)
        self._llm_check.start()

    def _on_llm_check_done(self, ok: bool, err: str):
        if not ok:
            self._run_btn.setEnabled(True)
            self._run_btn.setText("▶  Run Forensics")
            choice = QMessageBox.question(
                self, "LLM Model Unavailable",
                f"{err}\n\nDo you want to continue in automation-only mode "
                f"(deterministic engine, no AI)?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes,
            )
            if choice == QMessageBox.StandardButton.Yes:
                self._emit_run_config(skip_llm=True)
            return
        self._emit_run_config(skip_llm=False)

    def _emit_run_config(self, skip_llm: bool):
        q_date = self._date_edit.date()
        # Collect profile keyword values
        profile_keywords: dict[str, str] = {}
        for pk_key, widget in self._profile_keyword_widgets.items():
            if isinstance(widget, QTextEdit):
                profile_keywords[pk_key] = widget.toPlainText().strip()
            elif isinstance(widget, QLineEdit):
                profile_keywords[pk_key] = widget.text().strip()
        config = {
            "mount_point": self._drive.text().strip(),
            "output_dir": self._output.text().strip(),
            "llm_model": self._model.text().strip() if not skip_llm else "",
            "customer_name": self._customer.text().strip(),
            "investigation_date": date(q_date.year(), q_date.month(), q_date.day()),
            "case_reference": self._case_ref.text().strip(),
            "investigation_prompt": self._prompt.toPlainText().strip(),
            "enabled_agents": [name for name, cb in self._agent_checks.items() if cb.isChecked()],
            "case_profile": self._profile_combo.currentData() or "generic",
            "profile_keywords": profile_keywords,
            "report_formats": ["html", "pdf"] if self._pdf_enabled.isChecked() else ["html"],
            "malware_opts": {
                "run_capa": self._run_capa.isChecked(),
                "run_yara": self._run_yara.isChecked(),
            },
            "_skip_llm": skip_llm,  # consumed by main_window before CaseContext
        }
        self.run_requested.emit(config)

    def _on_profile_changed(self):
        """Re-render the dynamic keyword fields for the currently-selected profile."""
        # Clear old widgets
        while self._keywords_layout.count():
            item = self._keywords_layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.setParent(None)
                w.deleteLater()
        self._profile_keyword_widgets.clear()

        key = self._profile_combo.currentData()
        profile = get_profile(key) if key else None
        if not profile:
            return

        # Description block
        wf_lines = "<br/>".join(f"&nbsp;&nbsp;• {line}" for line in profile.workflow_summary)
        self._profile_descr.setText(
            f"<b>{profile.short_description}</b><br/><br/>"
            f"{profile.long_description}<br/><br/>"
            f"<b>What this profile checks:</b><br/>{wf_lines}"
        )
        self._profile_descr.setTextFormat(Qt.TextFormat.RichText)

        # Keyword input fields
        for kp in profile.keyword_prompts:
            field_frame = QFrame()
            field_frame.setStyleSheet(
                "background:#0d1117;border:1px solid #21262d;border-radius:4px;"
            )
            field_layout = QVBoxLayout(field_frame)
            field_layout.setContentsMargins(10, 8, 10, 10)
            field_layout.setSpacing(4)

            label = QLabel(kp.label + (" *" if kp.required else ""))
            label.setStyleSheet("color:#e6edf3;font-weight:600;font-size:11px;")
            field_layout.addWidget(label)

            if kp.description:
                desc = QLabel(kp.description)
                desc.setStyleSheet("color:#8b949e;font-size:10px;")
                desc.setWordWrap(True)
                field_layout.addWidget(desc)

            if kp.multiline:
                widget = QTextEdit()
                widget.setMinimumHeight(70)
                widget.setMaximumHeight(140)
                widget.setPlaceholderText(kp.placeholder)
                widget.setStyleSheet(
                    "QTextEdit{background:#161b22;color:#e6edf3;"
                    "border:1px solid #30363d;border-radius:4px;"
                    "padding:6px 8px;font-family:Consolas,monospace;font-size:11px;}"
                )
            else:
                widget = QLineEdit()
                widget.setPlaceholderText(kp.placeholder)
                widget.setStyleSheet(
                    "QLineEdit{background:#161b22;color:#e6edf3;"
                    "border:1px solid #30363d;border-radius:4px;"
                    "padding:6px 8px;font-size:11px;}"
                )
            self._profile_keyword_widgets[kp.key] = widget
            field_layout.addWidget(widget)
            self._keywords_layout.addWidget(field_frame)

    def _check_model_now(self):
        spec = self._model.text().strip()
        if not spec:
            self._model_status.setText("Enter a model first")
            self._model_status.setStyleSheet("color:#f85149;font-size:10px;")
            return
        self._model_status.setText("Checking...")
        self._model_status.setStyleSheet("color:#8b949e;font-size:10px;")

        class _Check(QThread):
            done = Signal(bool, str)
            def __init__(self, s, p=None): super().__init__(p); self._s = s
            def run(self):
                from core.llm_client import LLMClient
                self.done.emit(*LLMClient.validate_model_spec(self._s))

        t = _Check(spec, self)
        def _show(ok, msg):
            if ok:
                self._model_status.setText("Ready")
                self._model_status.setStyleSheet("color:#3fb950;font-size:10px;font-weight:600;")
            else:
                short = msg.split("\n")[0][:60]
                self._model_status.setText(short)
                self._model_status.setStyleSheet("color:#f85149;font-size:10px;")
        t.done.connect(_show)
        t.start()
        self._model_check_thread = t  # keep reference

    def set_running(self, running: bool):
        self._run_btn.setEnabled(not running)
        self._run_btn.setText("Running..." if running else "▶  Run Forensics")
