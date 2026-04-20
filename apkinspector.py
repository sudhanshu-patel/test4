from __future__ import annotations

import json
import re
import shutil
import sqlite3
import traceback
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog
import tkinter as tk
from tkinter import ttk

try:
    from androguard.core.apk import APK
except Exception:  # pragma: no cover - shown in UI at runtime
    APK = None


APP_NAME = "APKinspector"
DB_NAME = "apkinspector.db"
SCAN_FOLDER = "apk_scans"

ANDROID_VERSIONS = {
    21: "Android 5.0 Lollipop",
    22: "Android 5.1 Lollipop",
    23: "Android 6.0 Marshmallow",
    24: "Android 7.0 Nougat",
    25: "Android 7.1 Nougat",
    26: "Android 8.0 Oreo",
    27: "Android 8.1 Oreo",
    28: "Android 9 Pie",
    29: "Android 10",
    30: "Android 11",
    31: "Android 12",
    32: "Android 12L",
    33: "Android 13",
    34: "Android 14",
    35: "Android 15",
    36: "Android 16",
}

RISK_WEIGHTS = {
    "high": 85,
    "medium": 55,
    "low": 25,
    "none": 0,
}


@dataclass
class ActivityRecord:
    name: str
    exported: bool
    launchable: bool
    launch_mode: str
    task_affinity: str
    allow_reparenting: bool


@dataclass
class ApkAnalysis:
    pss_id: str
    file_name: str
    file_path: str
    original_file_path: str
    package_name: str
    app_label: str
    version_name: str
    version_code: str
    min_sdk: int | None
    target_sdk: int | None
    android_version: str
    risk_level: str
    risk_score: int
    vulnerable: bool
    findings: list[str]
    test_cases: list[str]
    activities: list[ActivityRecord]


class ApkDatabase:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.connection = sqlite3.connect(db_path)
        self.connection.row_factory = sqlite3.Row
        self._create_schema()

    def _create_schema(self) -> None:
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS apk_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analyzed_at TEXT NOT NULL,
                pss_id TEXT NOT NULL DEFAULT '',
                file_name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                original_file_path TEXT NOT NULL DEFAULT '',
                package_name TEXT NOT NULL,
                app_label TEXT,
                version_name TEXT,
                version_code TEXT,
                min_sdk INTEGER,
                target_sdk INTEGER,
                android_version TEXT,
                risk_level TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                vulnerable INTEGER NOT NULL,
                findings_json TEXT NOT NULL,
                test_cases_json TEXT NOT NULL DEFAULT '[]',
                activities_json TEXT NOT NULL
            )
            """
        )
        self._migrate_schema()
        self.connection.commit()

    def _migrate_schema(self) -> None:
        columns = {
            row["name"]
            for row in self.connection.execute("PRAGMA table_info(apk_records)").fetchall()
        }
        migrations = {
            "pss_id": "ALTER TABLE apk_records ADD COLUMN pss_id TEXT NOT NULL DEFAULT ''",
            "original_file_path": "ALTER TABLE apk_records ADD COLUMN original_file_path TEXT NOT NULL DEFAULT ''",
            "test_cases_json": "ALTER TABLE apk_records ADD COLUMN test_cases_json TEXT NOT NULL DEFAULT '[]'",
        }
        for column, statement in migrations.items():
            if column not in columns:
                self.connection.execute(statement)

    def save_analysis(self, analysis: ApkAnalysis) -> None:
        self.connection.execute(
            """
            INSERT INTO apk_records (
                analyzed_at, pss_id, file_name, file_path, original_file_path, package_name, app_label,
                version_name, version_code, min_sdk, target_sdk, android_version,
                risk_level, risk_score, vulnerable, findings_json, test_cases_json, activities_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                analysis.pss_id,
                analysis.file_name,
                analysis.file_path,
                analysis.original_file_path,
                analysis.package_name,
                analysis.app_label,
                analysis.version_name,
                analysis.version_code,
                analysis.min_sdk,
                analysis.target_sdk,
                analysis.android_version,
                analysis.risk_level,
                analysis.risk_score,
                1 if analysis.vulnerable else 0,
                json.dumps(analysis.findings),
                json.dumps(analysis.test_cases),
                json.dumps([activity.__dict__ for activity in analysis.activities]),
            ),
        )
        self.connection.commit()

    def list_records(self, filters: dict[str, str]) -> list[sqlite3.Row]:
        clauses: list[str] = []
        values: list[str | int] = []

        package_query = filters.get("package", "").strip()
        if package_query:
            clauses.append(
                "(package_name LIKE ? OR app_label LIKE ? OR file_name LIKE ? OR pss_id LIKE ?)"
            )
            query = f"%{package_query}%"
            values.extend([query, query, query, query])

        android_version = filters.get("android_version", "All")
        if android_version and android_version != "All":
            clauses.append("android_version = ?")
            values.append(android_version)

        risk = filters.get("risk", "All")
        if risk and risk != "All":
            clauses.append("risk_level = ?")
            values.append(risk.lower())

        min_sdk = filters.get("min_sdk", "").strip()
        if min_sdk:
            clauses.append("min_sdk = ?")
            values.append(int(min_sdk))

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return list(
            self.connection.execute(
                f"""
                SELECT * FROM apk_records
                {where_sql}
                ORDER BY analyzed_at DESC, id DESC
                """,
                values,
            )
        )

    def get_record(self, record_id: int) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM apk_records WHERE id = ?",
            (record_id,),
        ).fetchone()

    def delete_record(self, record_id: int) -> None:
        self.connection.execute("DELETE FROM apk_records WHERE id = ?", (record_id,))
        self.connection.commit()

    def android_versions(self) -> list[str]:
        rows = self.connection.execute(
            """
            SELECT DISTINCT android_version
            FROM apk_records
            WHERE android_version IS NOT NULL AND android_version != ''
            ORDER BY android_version
            """
        ).fetchall()
        return [row["android_version"] for row in rows]


class ApkAnalyzer:
    def analyze(self, apk_path: Path) -> ApkAnalysis:
        if APK is None:
            raise RuntimeError(
                "androguard is not installed. Run: pip install -r requirements.txt"
            )

        apk = APK(str(apk_path))
        package_name = apk.get_package() or "Unknown"
        app_label = apk.get_app_name() or "Unknown"
        version_name = apk.get_androidversion_name() or "Unknown"
        version_code = apk.get_androidversion_code() or "Unknown"
        min_sdk = self._safe_int(apk.get_min_sdk_version())
        target_sdk = self._safe_int(apk.get_target_sdk_version())
        if target_sdk is None:
            target_sdk = self._safe_int(apk.get_effective_target_sdk_version())
        android_version = self._android_version_label(min_sdk)
        activities = self._activities(apk, package_name)
        code_indicators = self._code_indicators(apk_path)
        risk_level, findings, test_cases = self._strandhogg_findings(
            package_name, activities, min_sdk, target_sdk, code_indicators
        )
        risk_score = RISK_WEIGHTS[risk_level]

        return ApkAnalysis(
            pss_id="",
            file_name=apk_path.name,
            file_path=str(apk_path),
            original_file_path=str(apk_path),
            package_name=package_name,
            app_label=app_label,
            version_name=version_name,
            version_code=str(version_code),
            min_sdk=min_sdk,
            target_sdk=target_sdk,
            android_version=android_version,
            risk_level=risk_level,
            risk_score=risk_score,
            vulnerable=risk_level in {"high", "medium"},
            findings=findings,
            test_cases=test_cases,
            activities=activities,
        )

    def _activities(self, apk: APK, package_name: str) -> list[ActivityRecord]:
        activities: list[ActivityRecord] = []
        launchable_activities = set(apk.get_main_activities() or [])
        launchable_normalized = {
            self._normalize_activity_name(activity, package_name)
            for activity in launchable_activities
        }
        manifest = apk.get_android_manifest_xml()

        for activity_name in apk.get_activities() or []:
            activity_node = self._find_activity_node(manifest, activity_name, package_name)
            intent_filters = apk.get_intent_filters("activity", activity_name) or {}
            has_intent_filter = bool(intent_filters.get("action") or intent_filters.get("category"))

            exported_attr = self._manifest_attr(activity_node, "exported")
            exported = (
                str(exported_attr).lower() == "true"
                if exported_attr is not None
                else has_intent_filter
            )
            launch_mode = self._normalize_launch_mode(
                self._manifest_attr(activity_node, "launchMode") or "standard"
            )
            task_affinity = self._manifest_attr(activity_node, "taskAffinity") or ""
            allow_reparenting = (
                str(self._manifest_attr(activity_node, "allowTaskReparenting")).lower()
                == "true"
            )
            normalized_name = self._normalize_activity_name(activity_name, package_name)

            activities.append(
                ActivityRecord(
                    name=normalized_name,
                    exported=exported,
                    launchable=(
                        activity_name in launchable_activities
                        or normalized_name in launchable_normalized
                    ),
                    launch_mode=launch_mode,
                    task_affinity=task_affinity,
                    allow_reparenting=allow_reparenting,
                )
            )

        return activities

    def _strandhogg_findings(
        self,
        package_name: str,
        activities: list[ActivityRecord],
        min_sdk: int | None,
        target_sdk: int | None,
        code_indicators: list[str],
    ) -> tuple[str, list[str], list[str]]:
        findings: list[str] = []
        test_cases: list[str] = []
        high_signal = 0
        medium_signal = 0
        manifest_signal = False

        for activity in activities:
            risky_launch_mode = activity.launch_mode in {
                "singleTask",
                "singleInstance",
                "singleInstancePerTask",
            }
            has_custom_affinity = bool(activity.task_affinity)
            foreign_affinity = has_custom_affinity and activity.task_affinity != package_name
            exported_entry = activity.exported and activity.launchable
            reparenting = activity.allow_reparenting

            if foreign_affinity and reparenting:
                high_signal += 1
                manifest_signal = True
                findings.append(
                    f"High-confidence task-affinity hijacking pattern: {activity.name} declares "
                    f'android:taskAffinity="{activity.task_affinity}" outside its own package '
                    f'("{package_name}") and enables android:allowTaskReparenting.'
                )
                test_cases.append(
                    f"SH-01 foreign affinity reparenting: confirm {activity.name} cannot be "
                    "reparented into the spoofed task."
                )
            elif has_custom_affinity and risky_launch_mode and reparenting:
                high_signal += 1
                manifest_signal = True
                findings.append(
                    f"High-confidence StrandHogg 1.0 pattern: {activity.name} declares "
                    f"android:taskAffinity, uses launchMode={activity.launch_mode}, and enables "
                    "android:allowTaskReparenting."
                )
                test_cases.append(
                    f"SH-02 manifest triad: confirm {activity.name} taskAffinity, launchMode, "
                    "and allowTaskReparenting are intentional."
                )
            elif exported_entry and risky_launch_mode and has_custom_affinity:
                high_signal += 1
                manifest_signal = True
                findings.append(
                    f"StrandHogg/task-affinity indicator: {activity.name} is exported, "
                    f"launchable, uses launchMode={activity.launch_mode}, and declares "
                    "android:taskAffinity."
                )
                test_cases.append(
                    f"SH-03 exported launcher: dynamically launch {activity.name} and inspect "
                    "whether it can be placed in another app's task."
                )
            elif foreign_affinity and (exported_entry or risky_launch_mode):
                medium_signal += 1
                manifest_signal = True
                findings.append(
                    f"Task-affinity hijacking chance: {activity.name} declares foreign "
                    f'android:taskAffinity="{activity.task_affinity}" and has '
                    f"{'exported launcher exposure' if exported_entry else f'launchMode={activity.launch_mode}'}."
                )
                test_cases.append(
                    f"SH-04 foreign affinity exposure: verify {activity.name} cannot spoof or join "
                    f"the {activity.task_affinity} task."
                )
            elif exported_entry and has_custom_affinity:
                findings.append(
                    f"Informational manifest note: {activity.name} is exported and launchable "
                    "with a custom android:taskAffinity, but no risky singleTask/singleInstance "
                    "launchMode was found for this activity."
                )
            elif exported_entry and risky_launch_mode:
                medium_signal += 1
                manifest_signal = True
                findings.append(
                    f"Task stack exposure: {activity.name} is exported and launchable "
                    f"with launchMode={activity.launch_mode}."
                )
                test_cases.append(
                    f"SH-05 launch mode: verify {activity.name} cannot be abused through "
                    "singleTask/singleInstance task reuse."
                )

            if activity.allow_reparenting and risky_launch_mode:
                medium_signal += 1
                manifest_signal = True
                findings.append(
                    f"StrandHogg-related behavior: {activity.name} enables "
                    "android:allowTaskReparenting, which can move activities between tasks."
                )
                test_cases.append(
                    f"SH-06 reparenting: use dumpsys activity to confirm {activity.name} "
                    "does not move into a foreign task."
                )

        if manifest_signal and min_sdk and min_sdk < 28:
            findings.append(
                f"Minimum supported SDK {min_sdk} includes older Android versions; "
                "verify task-affinity behavior dynamically on affected devices."
            )
            test_cases.append(
                "SH-07 legacy device coverage: run dynamic testing on Android 8.1 or 9.0 lab devices."
            )

        if (manifest_signal or code_indicators) and target_sdk and target_sdk < 29:
            findings.append(
                f"Target SDK {target_sdk} is below Android 10 background-launch hardening; "
                "include background activity launch checks in dynamic testing."
            )
            test_cases.append(
                "SH-08 background launch controls: test whether background components can start UI unexpectedly."
            )

        if code_indicators:
            medium_signal += 1
            findings.append(
                "Runtime StrandHogg 2.0 review needed: DEX strings reference "
                + ", ".join(code_indicators)
                + "."
            )
            test_cases.append(
                "SH-09 runtime chain: review DEX/code paths for crafted Intent arrays, startActivities(), "
                "foreground-app monitoring, and overlay launch timing."
            )

        if high_signal:
            return "high", findings, self._dedupe(test_cases)
        if medium_signal >= 2:
            return "medium", findings, self._dedupe(test_cases)
        if medium_signal == 1:
            return "low", findings, self._dedupe(test_cases)

        return (
            "none",
            ["No StrandHogg 1.0 manifest evidence was found, and no StrandHogg 2.0 runtime string indicators were found."],
            [
                "SH-00 baseline: no static StrandHogg indicators found; dynamic testing is not required by this scan unless separate business or threat-model reasons exist."
            ],
        )

    @staticmethod
    def _code_indicators(apk_path: Path) -> list[str]:
        patterns = {
            b"startActivities": "startActivities()",
            b"getRunningTasks": "getRunningTasks()",
            b"UsageStatsManager": "UsageStatsManager",
            b"AccessibilityService": "AccessibilityService",
            b"JobScheduler": "JobScheduler",
            b"FLAG_ACTIVITY_NEW_TASK": "FLAG_ACTIVITY_NEW_TASK",
            b"FLAG_ACTIVITY_TASK_ON_HOME": "FLAG_ACTIVITY_TASK_ON_HOME",
        }
        found: list[str] = []
        try:
            with zipfile.ZipFile(apk_path) as apk_zip:
                dex_names = [
                    name
                    for name in apk_zip.namelist()
                    if name.startswith("classes") and name.endswith(".dex")
                ]
                for dex_name in dex_names:
                    dex_data = apk_zip.read(dex_name)
                    for pattern, label in patterns.items():
                        if pattern in dex_data and label not in found:
                            found.append(label)
        except (OSError, zipfile.BadZipFile):
            return []
        return found

    @staticmethod
    def _dedupe(values: list[str]) -> list[str]:
        deduped: list[str] = []
        for value in values:
            if value not in deduped:
                deduped.append(value)
        return deduped

    @staticmethod
    def _safe_int(value: object) -> int | None:
        try:
            return int(value) if value not in (None, "") else None
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _android_version_label(sdk: int | None) -> str:
        if sdk is None:
            return "Unknown"
        return ANDROID_VERSIONS.get(sdk, f"Unknown SDK {sdk}")

    @staticmethod
    def _normalize_activity_name(name: str, package_name: str) -> str:
        if name.startswith("."):
            return f"{package_name}{name}"
        if "." not in name:
            return f"{package_name}.{name}"
        return name

    @staticmethod
    def _normalize_launch_mode(value: str) -> str:
        launch_mode = str(value).strip()
        return {
            "0": "standard",
            "1": "singleTop",
            "2": "singleTask",
            "3": "singleInstance",
            "4": "singleInstancePerTask",
        }.get(launch_mode, launch_mode)

    def _find_activity_node(self, manifest: object, activity_name: str, package_name: str) -> object | None:
        normalized = self._normalize_activity_name(activity_name, package_name)
        for node in manifest.iter():
            if self._strip_namespace(str(getattr(node, "tag", ""))) != "activity":
                continue
            node_name = self._manifest_attr(node, "name")
            if not node_name:
                continue
            if node_name == activity_name or self._normalize_activity_name(node_name, package_name) == normalized:
                return node
        return None

    @staticmethod
    def _manifest_attr(node: object | None, attr_name: str) -> str | None:
        if node is None:
            return None
        android_attr = f"{{http://schemas.android.com/apk/res/android}}{attr_name}"
        value = node.attrib.get(android_attr)
        if value is None:
            value = node.attrib.get(attr_name)
        return value

    @staticmethod
    def _strip_namespace(tag_name: str) -> str:
        return tag_name.rsplit("}", 1)[-1]


class APKinspectorApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1240x790")
        self.minsize(1040, 680)

        base_dir = Path(__file__).resolve().parent
        self.db = ApkDatabase(base_dir / DB_NAME)
        self.scan_root = base_dir / SCAN_FOLDER
        self.scan_root.mkdir(exist_ok=True)
        self.analyzer = ApkAnalyzer()
        self.current_records: list[sqlite3.Row] = []
        self.current_records_by_id: dict[int, sqlite3.Row] = {}
        self.dark_mode = False

        self._set_theme(False)
        self._configure_styles()
        self._build_layout()
        self.refresh_records()

    def _set_theme(self, dark_mode: bool) -> None:
        self.dark_mode = dark_mode
        if dark_mode:
            self.colors = {
                "bg": "#101418",
                "surface": "#171d23",
                "surface_alt": "#202832",
                "line": "#313b47",
                "text": "#edf2f7",
                "muted": "#a3afbd",
                "primary": "#14b8a6",
                "primary_dark": "#0f766e",
                "accent": "#f97316",
                "danger": "#fb7185",
                "warning": "#fbbf24",
                "success": "#4ade80",
                "input": "#111827",
                "select": "#134e4a",
            }
        else:
            self.colors = {
                "bg": "#eef3f8",
                "surface": "#ffffff",
                "surface_alt": "#f6f8fb",
                "line": "#d3dbe6",
                "text": "#111827",
                "muted": "#607086",
                "primary": "#0f766e",
                "primary_dark": "#115e59",
                "accent": "#c2410c",
                "danger": "#b91c1c",
                "warning": "#b45309",
                "success": "#15803d",
                "input": "#ffffff",
                "select": "#ccfbf1",
            }
        self.configure(bg=self.colors["bg"])

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        default_font = ("Segoe UI", 10)
        title_font = ("Segoe UI Semibold", 24)
        small_bold = ("Segoe UI Semibold", 10)

        style.configure(".", font=default_font, background=self.colors["bg"])
        style.configure("Root.TFrame", background=self.colors["bg"])
        style.configure("Surface.TFrame", background=self.colors["surface"])
        style.configure("AltSurface.TFrame", background=self.colors["surface_alt"])
        style.configure("Title.TLabel", font=title_font, foreground=self.colors["text"], background=self.colors["surface"])
        style.configure("Subtitle.TLabel", foreground=self.colors["muted"], background=self.colors["surface"])
        style.configure("Kicker.TLabel", font=("Segoe UI Semibold", 9), foreground=self.colors["primary"], background=self.colors["surface"])
        style.configure("Metric.TLabel", font=("Segoe UI Semibold", 20), foreground=self.colors["text"], background=self.colors["surface"])
        style.configure("MetricText.TLabel", foreground=self.colors["muted"], background=self.colors["surface"])
        style.configure("Section.TLabel", font=("Segoe UI Semibold", 12), foreground=self.colors["text"], background=self.colors["surface"])
        style.configure("Muted.TLabel", foreground=self.colors["muted"], background=self.colors["surface"])
        style.configure("Primary.TButton", font=small_bold, foreground="#ffffff", background=self.colors["primary"], borderwidth=0, padding=(16, 10))
        style.map("Primary.TButton", background=[("active", self.colors["primary_dark"])])
        style.configure("Secondary.TButton", font=small_bold, foreground=self.colors["text"], background=self.colors["surface_alt"], borderwidth=0, padding=(12, 8))
        style.map("Secondary.TButton", background=[("active", self.colors["line"])])
        style.configure("Treeview", rowheight=36, borderwidth=0, background=self.colors["surface"], fieldbackground=self.colors["surface"], foreground=self.colors["text"])
        style.configure("Treeview.Heading", font=small_bold, background=self.colors["surface_alt"], foreground=self.colors["text"], borderwidth=0)
        style.map("Treeview", background=[("selected", self.colors["select"])], foreground=[("selected", self.colors["text"])])
        style.configure("TCombobox", padding=7, fieldbackground=self.colors["input"], background=self.colors["input"], foreground=self.colors["text"], arrowcolor=self.colors["text"])
        style.configure("TEntry", padding=7, fieldbackground=self.colors["input"], foreground=self.colors["text"], insertcolor=self.colors["text"])

    def _build_layout(self) -> None:
        root = ttk.Frame(self, style="Root.TFrame", padding=18)
        root.pack(fill=tk.BOTH, expand=True)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(2, weight=1)

        header = ttk.Frame(root, style="Surface.TFrame", padding=20)
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)

        ttk.Label(header, text="SECURITY TESTING CONSOLE", style="Kicker.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(header, text=APP_NAME, style="Title.TLabel").grid(row=1, column=0, sticky="w")
        ttk.Label(
            header,
            text="Windows APK lab for PSS-tracked scans, minimum Android support, and StrandHogg task-affinity review.",
            style="Subtitle.TLabel",
        ).grid(row=2, column=0, sticky="w", pady=(4, 0))

        actions = ttk.Frame(header, style="Surface.TFrame")
        actions.grid(row=0, column=1, rowspan=3, sticky="e", padx=(18, 0))
        ttk.Button(actions, text=self._theme_button_text(), style="Secondary.TButton", command=self.toggle_theme).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(actions, text="Upload APK", style="Primary.TButton", command=self.upload_apk).pack(side=tk.LEFT)

        filters = ttk.Frame(root, style="Surface.TFrame", padding=14)
        filters.grid(row=1, column=0, sticky="ew", pady=(14, 14))
        filters.columnconfigure(1, weight=2)
        filters.columnconfigure(3, weight=1)
        filters.columnconfigure(5, weight=1)
        filters.columnconfigure(7, weight=1)

        ttk.Label(filters, text="Search / PSS ID", style="Muted.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 8))
        self.package_filter = ttk.Entry(filters)
        self.package_filter.grid(row=0, column=1, sticky="ew", padx=(0, 14))

        ttk.Label(filters, text="Min Android", style="Muted.TLabel").grid(row=0, column=2, sticky="w", padx=(0, 8))
        self.android_filter = ttk.Combobox(filters, state="readonly", values=["All"])
        self.android_filter.set("All")
        self.android_filter.grid(row=0, column=3, sticky="ew", padx=(0, 14))

        ttk.Label(filters, text="Risk", style="Muted.TLabel").grid(row=0, column=4, sticky="w", padx=(0, 8))
        self.risk_filter = ttk.Combobox(filters, state="readonly", values=["All", "High", "Medium", "Low", "None"])
        self.risk_filter.set("All")
        self.risk_filter.grid(row=0, column=5, sticky="ew", padx=(0, 14))

        ttk.Label(filters, text="Min SDK", style="Muted.TLabel").grid(row=0, column=6, sticky="w", padx=(0, 8))
        self.min_sdk_filter = ttk.Entry(filters)
        self.min_sdk_filter.grid(row=0, column=7, sticky="ew", padx=(0, 14))

        ttk.Button(filters, text="Apply", style="Secondary.TButton", command=self.refresh_records).grid(row=0, column=8, padx=(0, 8))
        ttk.Button(filters, text="Clear", style="Secondary.TButton", command=self.clear_filters).grid(row=0, column=9)

        content = ttk.Frame(root, style="Root.TFrame")
        content.grid(row=2, column=0, sticky="nsew")
        content.columnconfigure(0, weight=3)
        content.columnconfigure(1, weight=2)
        content.rowconfigure(0, weight=1)

        table_frame = ttk.Frame(content, style="Surface.TFrame", padding=12)
        table_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 14))
        table_frame.rowconfigure(1, weight=1)
        table_frame.columnconfigure(0, weight=1)

        table_header = ttk.Frame(table_frame, style="Surface.TFrame")
        table_header.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        table_header.columnconfigure(0, weight=1)
        ttk.Label(table_header, text="APK Database", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Button(table_header, text="Delete Scan", style="Secondary.TButton", command=self.delete_selected_scan).grid(row=0, column=1, sticky="e")

        columns = ("pss", "file_name", "version", "android", "min_sdk", "risk", "analyzed")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="tree headings", selectmode="browse")
        self.tree.heading("#0", text="Package Folder")
        self.tree.heading("pss", text="PSS ID")
        self.tree.heading("file_name", text="APK")
        self.tree.heading("version", text="Version")
        self.tree.heading("android", text="Min Android")
        self.tree.heading("min_sdk", text="Min SDK")
        self.tree.heading("risk", text="StrandHogg")
        self.tree.heading("analyzed", text="Analyzed")
        self.tree.column("#0", width=230, minwidth=180)
        self.tree.column("pss", width=105, minwidth=90)
        self.tree.column("file_name", width=165, minwidth=130)
        self.tree.column("version", width=105, minwidth=90)
        self.tree.column("android", width=150, minwidth=120)
        self.tree.column("min_sdk", width=75, minwidth=65, anchor=tk.CENTER)
        self.tree.column("risk", width=100, minwidth=90, anchor=tk.CENTER)
        self.tree.column("analyzed", width=145, minwidth=130)
        self.tree.grid(row=1, column=0, sticky="nsew")
        self.tree.bind("<<TreeviewSelect>>", self.show_selected_record)

        table_scroll = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        table_scroll.grid(row=1, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=table_scroll.set)

        detail = ttk.Frame(content, style="Surface.TFrame", padding=16)
        detail.grid(row=0, column=1, sticky="nsew")
        detail.columnconfigure(0, weight=1)
        detail.rowconfigure(5, weight=1)

        ttk.Label(detail, text="Security Summary", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        self.summary_title = ttk.Label(detail, text="No APK selected", style="Metric.TLabel")
        self.summary_title.grid(row=1, column=0, sticky="w", pady=(14, 0))
        self.summary_subtitle = ttk.Label(detail, text="Upload or select an APK to inspect StrandHogg indicators.", style="MetricText.TLabel")
        self.summary_subtitle.grid(row=2, column=0, sticky="w", pady=(2, 14))

        metrics = ttk.Frame(detail, style="Surface.TFrame")
        metrics.grid(row=3, column=0, sticky="ew", pady=(0, 14))
        metrics.columnconfigure((0, 1, 2), weight=1)
        self.metric_sdk = self._metric(metrics, "Min SDK", "-")
        self.metric_sdk.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.metric_activities = self._metric(metrics, "Activities", "-")
        self.metric_activities.grid(row=0, column=1, sticky="ew", padx=8)
        self.metric_vulnerable = self._metric(metrics, "StrandHogg", "-")
        self.metric_vulnerable.grid(row=0, column=2, sticky="ew", padx=(8, 0))

        ttk.Label(detail, text="Findings", style="Section.TLabel").grid(row=4, column=0, sticky="w")
        self.findings_text = tk.Text(
            detail,
            height=12,
            wrap=tk.WORD,
            borderwidth=0,
            bg=self.colors["surface_alt"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            font=("Segoe UI", 10),
            padx=12,
            pady=12,
        )
        self.findings_text.grid(row=5, column=0, sticky="nsew", pady=(8, 0))
        self.findings_text.configure(state=tk.DISABLED)

        self.status_var = tk.StringVar(value="Ready")
        status = ttk.Label(root, textvariable=self.status_var, foreground=self.colors["muted"], background=self.colors["bg"])
        status.grid(row=3, column=0, sticky="w", pady=(10, 0))

    def _metric(self, parent: ttk.Frame, label: str, value: str) -> ttk.Frame:
        frame = ttk.Frame(parent, style="Surface.TFrame", padding=10)
        frame.configure(relief=tk.SOLID)
        ttk.Label(frame, text=value, style="Metric.TLabel").pack(anchor="w")
        ttk.Label(frame, text=label, style="MetricText.TLabel").pack(anchor="w")
        return frame

    def toggle_theme(self) -> None:
        filter_state = self._current_filter_state()
        selected = self.tree.selection()[0] if hasattr(self, "tree") and self.tree.selection() else None
        self._set_theme(not self.dark_mode)
        self._configure_styles()
        for child in self.winfo_children():
            child.destroy()
        self._build_layout()
        self._restore_filter_state(filter_state)
        self.refresh_records()
        if selected and self.tree.exists(selected):
            self.tree.selection_set(selected)
            self.tree.focus(selected)
            self.show_selected_record()

    def _theme_button_text(self) -> str:
        return "Light Mode" if self.dark_mode else "Dark Mode"

    def upload_apk(self) -> None:
        apk_file = filedialog.askopenfilename(
            title="Choose Android APK",
            filetypes=[("Android APK", "*.apk"), ("All files", "*.*")],
        )
        if not apk_file:
            return

        apk_path = Path(apk_file)
        pss_id = self._ask_pss_id(apk_path.name)
        if not pss_id:
            self.status_var.set("Upload cancelled: PSS ID is required")
            return

        self.status_var.set(f"Analyzing {apk_path.name}...")
        self.update_idletasks()

        try:
            analysis = self.analyzer.analyze(apk_path)
            stored_path = self._archive_apk(apk_path, pss_id, analysis)
            analysis.pss_id = pss_id
            analysis.original_file_path = str(apk_path)
            analysis.file_path = str(stored_path)
            self.db.save_analysis(analysis)
            self.status_var.set(f"Imported {apk_path.name} under PSS ID {pss_id}")
            self.refresh_records()
            self.select_latest()
        except Exception as exc:
            traceback.print_exc()
            self.status_var.set("Analysis failed")
            messagebox.showerror(APP_NAME, f"Could not analyze APK:\n\n{exc}")

    def _ask_pss_id(self, apk_name: str) -> str:
        while True:
            pss_id = simpledialog.askstring(
                APP_NAME,
                f"Enter PSS ID for this APK scan:\n\n{apk_name}",
                parent=self,
            )
            if pss_id is None:
                return ""
            pss_id = pss_id.strip()
            if pss_id:
                return pss_id
            messagebox.showwarning(APP_NAME, "PSS ID is required for every APK upload.")

    def _archive_apk(self, apk_path: Path, pss_id: str, analysis: ApkAnalysis) -> Path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_pss = self._safe_folder_name(pss_id)
        safe_package = self._safe_folder_name(analysis.package_name)
        scan_dir = self.scan_root / safe_package / safe_pss / timestamp
        scan_dir.mkdir(parents=True, exist_ok=True)
        destination = scan_dir / apk_path.name
        if destination.exists():
            destination = scan_dir / f"{apk_path.stem}_{timestamp}{apk_path.suffix}"
        shutil.copy2(apk_path, destination)
        return destination

    @staticmethod
    def _safe_folder_name(value: str) -> str:
        safe_value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
        return safe_value.strip("._") or "scan"

    @staticmethod
    def _version_label(record: sqlite3.Row) -> str:
        version_name = record["version_name"] or "Unknown"
        version_code = record["version_code"] or "Unknown"
        return f"{version_name} ({version_code})"

    def refresh_records(self) -> None:
        filters = self._current_filter_state()
        if filters["min_sdk"]:
            try:
                int(filters["min_sdk"])
            except ValueError:
                messagebox.showwarning(APP_NAME, "Minimum SDK filter must be a number.")
                return

        self.current_records = self.db.list_records(filters)
        self.current_records_by_id = {int(record["id"]): record for record in self.current_records}
        self.tree.delete(*self.tree.get_children())
        package_nodes: dict[str, str] = {}

        for record in self.current_records:
            risk = str(record["risk_level"]).upper()
            package_name = record["package_name"] or "Unknown Package"
            package_iid = f"pkg::{self._safe_folder_name(package_name)}"
            if package_iid not in package_nodes:
                scan_count = sum(
                    1 for row in self.current_records if row["package_name"] == record["package_name"]
                )
                package_nodes[package_iid] = package_iid
                self.tree.insert(
                    "",
                    tk.END,
                    iid=package_iid,
                    text=f"{package_name} ({scan_count} scan{'s' if scan_count != 1 else ''})",
                    values=("", "", "", "", "", "", ""),
                    open=True,
                )

            self.tree.insert(
                package_iid,
                tk.END,
                iid=f"scan::{record['id']}",
                text="",
                values=(
                    record["pss_id"] or "-",
                    record["file_name"],
                    self._version_label(record),
                    record["android_version"],
                    record["min_sdk"] or "-",
                    risk,
                    record["analyzed_at"],
                ),
            )

        versions = ["All"] + self.db.android_versions()
        current_android = self.android_filter.get()
        self.android_filter.configure(values=versions)
        self.android_filter.set(current_android if current_android in versions else "All")
        self.status_var.set(f"{len(self.current_records)} record(s) shown")

    def clear_filters(self) -> None:
        self.package_filter.delete(0, tk.END)
        self.min_sdk_filter.delete(0, tk.END)
        self.android_filter.set("All")
        self.risk_filter.set("All")
        self.refresh_records()

    def delete_selected_scan(self) -> None:
        record = self._selected_scan_record()
        if record is None:
            messagebox.showinfo(APP_NAME, "Select a scan row under a package folder to delete.")
            return

        confirmed = messagebox.askyesno(
            APP_NAME,
            "Delete this scan?\n\n"
            f"PSS ID: {record['pss_id'] or '-'}\n"
            f"Package: {record['package_name']}\n"
            f"Version: {self._version_label(record)}\n"
            f"Scanned: {record['analyzed_at']}",
        )
        if not confirmed:
            return

        self._delete_archived_scan_files(record)
        self.db.delete_record(int(record["id"]))
        self.status_var.set(f"Deleted scan for {record['package_name']} ({self._version_label(record)})")
        self.refresh_records()
        self._show_package_folder_summary("No scan selected")

    def _delete_archived_scan_files(self, record: sqlite3.Row) -> None:
        archived_file = Path(record["file_path"])
        try:
            scan_root = self.scan_root.resolve()
            archived_file_resolved = archived_file.resolve()
        except OSError:
            return

        if not archived_file_resolved.is_file():
            return

        try:
            archived_file_resolved.relative_to(scan_root)
        except ValueError:
            return

        scan_folder = archived_file_resolved.parent
        try:
            scan_folder.relative_to(scan_root)
        except ValueError:
            return

        shutil.rmtree(scan_folder, ignore_errors=True)

    def _current_filter_state(self) -> dict[str, str]:
        return {
            "package": self.package_filter.get(),
            "android_version": self.android_filter.get(),
            "risk": self.risk_filter.get(),
            "min_sdk": self.min_sdk_filter.get(),
        }

    def _restore_filter_state(self, filters: dict[str, str]) -> None:
        self.package_filter.insert(0, filters.get("package", ""))
        self.min_sdk_filter.insert(0, filters.get("min_sdk", ""))
        self.android_filter.set(filters.get("android_version") or "All")
        self.risk_filter.set(filters.get("risk") or "All")

    def select_latest(self) -> None:
        children = self.tree.get_children()
        if children and self.tree.get_children(children[0]):
            first_scan = self.tree.get_children(children[0])[0]
            self.tree.selection_set(first_scan)
            self.tree.focus(first_scan)
            self.show_selected_record()

    def show_selected_record(self, _event: object | None = None) -> None:
        record = self._selected_scan_record()
        if record is None:
            selected = self.tree.selection()
            if selected and str(selected[0]).startswith("pkg::"):
                package_text = self.tree.item(selected[0], "text")
                self._show_package_folder_summary(package_text)
            return

        findings = json.loads(record["findings_json"])
        test_cases = json.loads(record["test_cases_json"])
        activities = json.loads(record["activities_json"])
        risk = str(record["risk_level"]).upper()
        vulnerable = "Likely" if record["vulnerable"] else "No"

        self.summary_title.configure(text=f"{risk} StrandHogg risk")
        self.summary_subtitle.configure(
            text=f"PSS {record['pss_id'] or '-'} - {record['app_label']} - {record['package_name']}"
        )
        self._set_metric(self.metric_sdk, str(record["min_sdk"] or "-"))
        self._set_metric(self.metric_activities, str(len(activities)))
        self._set_metric(self.metric_vulnerable, vulnerable)

        lines = [
            f"PSS ID: {record['pss_id'] or '-'}",
            f"Scanned at: {record['analyzed_at']} | Current time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"File: {record['file_name']}",
            f"Archived APK: {record['file_path']}",
            f"Version: {record['version_name']} ({record['version_code']})",
            f"Minimum Android supported: {record['android_version']} (SDK {record['min_sdk'] or 'unknown'})",
            f"Target SDK: {record['target_sdk'] or 'unknown'}",
            "",
            "Manifest proof:",
        ]
        lines.extend(self._manifest_proof_lines(record, activities))
        lines.extend([
            "",
            "StrandHogg Attack / Task Affinity Vulnerability review:",
        ])
        lines.extend(f"- {finding}" for finding in findings)
        lines.extend(["", "Covered test cases:"])
        lines.extend(f"- {test_case}" for test_case in test_cases)

        self.findings_text.configure(state=tk.NORMAL)
        self.findings_text.delete("1.0", tk.END)
        self.findings_text.insert("1.0", "\n".join(lines))
        self._highlight_task_affinity()
        self.findings_text.configure(state=tk.DISABLED)

    def _selected_scan_record(self) -> sqlite3.Row | None:
        selected = self.tree.selection()
        if not selected:
            return None
        item_id = str(selected[0])
        if not item_id.startswith("scan::"):
            return None
        try:
            record_id = int(item_id.split("::", 1)[1])
        except ValueError:
            return None
        return self.current_records_by_id.get(record_id)

    def _show_package_folder_summary(self, package_text: str) -> None:
        self.summary_title.configure(text="Package folder")
        self.summary_subtitle.configure(text=package_text)
        self._set_metric(self.metric_sdk, "-")
        self._set_metric(self.metric_activities, "-")
        self._set_metric(self.metric_vulnerable, "-")
        self.findings_text.configure(state=tk.NORMAL)
        self.findings_text.delete("1.0", tk.END)
        self.findings_text.insert(
            "1.0",
            "Select a scan under this package folder to view its security details.\n\n"
            "New scans with the same package name are automatically grouped here.",
        )
        self.findings_text.configure(state=tk.DISABLED)

    def _manifest_proof_lines(
        self, record: sqlite3.Row, activities: list[dict[str, object]]
    ) -> list[str]:
        proof_lines: list[str] = []
        suspicious_snippets: list[str] = []

        if not activities:
            return [
                "- AndroidManifest.xml did not expose any activity entries through the parser.",
                "- Result proof: no activity-level taskAffinity, launchMode, exported launcher, or allowTaskReparenting evidence was available to flag.",
            ]

        for activity in activities:
            name = str(activity.get("name") or "Unknown")
            exported = bool(activity.get("exported"))
            launchable = bool(activity.get("launchable"))
            launch_mode = str(activity.get("launch_mode") or "standard")
            task_affinity = str(activity.get("task_affinity") or "")
            allow_reparenting = bool(activity.get("allow_reparenting"))
            task_affinity_value = task_affinity if task_affinity else "(default / not declared)"

            risky_launch_mode = launch_mode in {
                "singleTask",
                "singleInstance",
                "singleInstancePerTask",
            }
            has_custom_affinity = bool(task_affinity)
            foreign_affinity = has_custom_affinity and task_affinity != record["package_name"]
            exported_launcher = exported and launchable

            if foreign_affinity and allow_reparenting:
                suspicious_snippets.append(
                    self._activity_manifest_snippet(
                        name, exported, launchable, launch_mode, task_affinity_value, allow_reparenting
                    )
                    + "\n  Why flagged: foreign/custom taskAffinity points outside this APK package "
                    "+ allowTaskReparenting=true."
                )
            elif has_custom_affinity and risky_launch_mode and allow_reparenting:
                suspicious_snippets.append(
                    self._activity_manifest_snippet(
                        name, exported, launchable, launch_mode, task_affinity_value, allow_reparenting
                    )
                    + "\n  Why flagged: custom taskAffinity + "
                    f"{launch_mode} + allowTaskReparenting=true."
                )
            elif exported_launcher and has_custom_affinity and risky_launch_mode:
                suspicious_snippets.append(
                    self._activity_manifest_snippet(
                        name, exported, launchable, launch_mode, task_affinity_value, allow_reparenting
                    )
                    + "\n  Why flagged: exported launcher activity + custom taskAffinity + "
                    f"{launch_mode}."
                )
            elif foreign_affinity and (exported_launcher or risky_launch_mode):
                suspicious_snippets.append(
                    self._activity_manifest_snippet(
                        name, exported, launchable, launch_mode, task_affinity_value, allow_reparenting
                    )
                    + "\n  Why flagged: foreign/custom taskAffinity plus "
                    f"{'exported launcher exposure' if exported_launcher else f'launchMode={launch_mode}'}."
                )

        min_sdk = record["min_sdk"] or "unknown"
        target_sdk = record["target_sdk"] or "unknown"
        proof_lines.append(f"- SDK proof: minSdk={min_sdk}, targetSdk={target_sdk}.")

        if suspicious_snippets:
            proof_lines.append("- Specific suspicious manifest activity:")
            proof_lines.extend(suspicious_snippets)
        else:
            proof_lines.append(
                "- No specific vulnerable manifest activity was found: no activity had foreign/custom taskAffinity with allowTaskReparenting, custom taskAffinity with singleTask/singleInstance plus allowTaskReparenting, or exported launcher exposure with both custom taskAffinity and risky launchMode."
            )

        return proof_lines

    @staticmethod
    def _activity_manifest_snippet(
        name: str,
        exported: bool,
        launchable: bool,
        launch_mode: str,
        task_affinity: str,
        allow_reparenting: bool,
    ) -> str:
        return "\n".join(
            [
                "  <activity",
                f'      android:name="{name}"',
                f'      android:exported="{str(exported).lower()}"',
                f'      launcher="{str(launchable).lower()}"',
                f'      android:launchMode="{launch_mode}"',
                f'      android:taskAffinity="{task_affinity}"',
                f'      android:allowTaskReparenting="{str(allow_reparenting).lower()}" />',
            ]
        )

    def _highlight_task_affinity(self) -> None:
        self.findings_text.tag_configure(
            "task_affinity",
            background=self.colors["warning"],
            foreground="#111827",
            font=("Segoe UI Semibold", 10),
        )
        start = "1.0"
        while True:
            index = self.findings_text.search("android:taskAffinity", start, tk.END)
            if not index:
                break
            line_end = self.findings_text.index(f"{index} lineend")
            self.findings_text.tag_add("task_affinity", index, line_end)
            start = line_end

    @staticmethod
    def _set_metric(metric_frame: ttk.Frame, value: str) -> None:
        first_label = metric_frame.winfo_children()[0]
        first_label.configure(text=value)


def main() -> int:
    app = APKinspectorApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
