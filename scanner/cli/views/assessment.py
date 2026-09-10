"""
NayVista Shield - Live Assessment Dashboard
Renders real-time assessment progress: active metadata, 10-step pipeline, real activity feed, and progress bar.
Avoids flickering and excessive redrawing.
"""

import sys
import time
from typing import Dict, Any, List, Optional
from scanner.cli.theme import (
    COLOR_BRAND_YELLOW, COLOR_WHITE, COLOR_MUTED_GRAY, COLOR_GREEN, COLOR_RED, COLOR_RESET, colorize,
    BOX_HORIZ, GLYPH_CHECK, GLYPH_RUNNING, GLYPH_WAITING, PROGRESS_FULL, PROGRESS_EMPTY
)
from scanner.cli.terminal import clear_screen, get_terminal_width

PIPELINE_STAGES = [
    (1,  "TARGET VALIDATION"),
    (2,  "DNS RESOLUTION"),
    (3,  "SCOPE VALIDATION"),
    (4,  "IP EXPOSURE"),
    (5,  "PORT EXPOSURE"),
    (6,  "HTTP SECURITY"),
    (7,  "TLS ANALYSIS"),
    (8,  "COOKIE SECURITY"),
    (9,  "WEB CRAWLING"),
    (10, "INFORMATION EXPOSURE"),
    (11, "INFRASTRUCTURE EXPOSURE"),
    (12, "FINDING CORRELATION"),
    (13, "SECURITY POSTURE"),
    (14, "REPORT GENERATION"),
]

class LiveAssessmentRenderer:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.start_time = time.time()
        self.current_step = 1
        self.total_steps = 14
        self.pages_discovered = 0
        self.findings_count = 0
        self.activities: List[str] = []
        self.max_activities = 4

    def on_activity(self, message: str):
        """Records a real scanner event and updates display."""
        if not message:
            return
        self.activities.append(message)
        if len(self.activities) > self.max_activities:
            self.activities.pop(0)
        self.render()

    def on_progress(self, phase: str, message: str, step: int, total_steps: int, stats: Optional[Dict[str, Any]] = None):
        """Updates pipeline state and re-renders."""
        self.current_step = step
        self.total_steps = total_steps
        if stats:
            if "pages_discovered" in stats:
                self.pages_discovered = stats["pages_discovered"]
        self.render()

    def render(self):
        """Renders the clean assessment dashboard."""
        clear_screen()
        width = min(72, get_terminal_width())
        elapsed = int(time.time() - self.start_time)
        mins, secs = divmod(elapsed, 60)
        time_str = f"{mins:02d}:{secs:02d}"

        # Header metadata
        print()
        print(f"{COLOR_BRAND_YELLOW}NAYVISTA SHIELD :: ACTIVE ASSESSMENT{COLOR_RESET}")
        print()
        print(f"  {COLOR_MUTED_GRAY}TARGET    {COLOR_RESET} {COLOR_WHITE}{self.target_url}{COLOR_RESET}")
        print(f"  {COLOR_MUTED_GRAY}SCOPE     {COLOR_RESET} {COLOR_BRAND_YELLOW}SAME-ORIGIN{COLOR_RESET}")
        print(f"  {COLOR_MUTED_GRAY}MODE      {COLOR_RESET} {COLOR_WHITE}DEFENSIVE / SAFE{COLOR_RESET}")
        print(f"  {COLOR_MUTED_GRAY}TIME      {COLOR_RESET} {COLOR_WHITE}{time_str}{COLOR_RESET}")
        print(f"  {COLOR_MUTED_GRAY}PAGES     {COLOR_RESET} {COLOR_WHITE}{self.pages_discovered}{COLOR_RESET}")
        print()
        print(f"{COLOR_MUTED_GRAY}{BOX_HORIZ * width}{COLOR_RESET}")
        print()
        print(f"{COLOR_BRAND_YELLOW}ASSESSMENT PIPELINE{COLOR_RESET}")
        print()

        # 10 Stages
        for step_num, label in PIPELINE_STAGES:
            if step_num < self.current_step:
                status_icon = f"{COLOR_GREEN}{GLYPH_CHECK} COMPLETE{COLOR_RESET}"
            elif step_num == self.current_step:
                status_icon = f"{COLOR_BRAND_YELLOW}{GLYPH_RUNNING} RUNNING{COLOR_RESET}"
            else:
                status_icon = f"{COLOR_MUTED_GRAY}{GLYPH_WAITING} WAITING{COLOR_RESET}"

            print(f"  {COLOR_MUTED_GRAY}{step_num:02d}{COLOR_RESET}  {COLOR_WHITE}{label:<32}{COLOR_RESET} {status_icon}")

        print()
        print(f"{COLOR_MUTED_GRAY}{BOX_HORIZ * width}{COLOR_RESET}")
        print()

        # Real Live Activity Log
        print(f"{COLOR_BRAND_YELLOW}LIVE ACTIVITY{COLOR_RESET}")
        print()
        if self.activities:
            for act in self.activities:
                print(f"  {COLOR_MUTED_GRAY}> {COLOR_WHITE}{act[:width-6]}{COLOR_RESET}")
        else:
            print(f"  {COLOR_MUTED_GRAY}> Initializing security assessment engine...{COLOR_RESET}")

        print()
        # Progress Bar
        pct = int((self.current_step / self.total_steps) * 100)
        bar_len = 24
        filled = int((pct / 100) * bar_len)
        bar_str = (PROGRESS_FULL * filled) + (PROGRESS_EMPTY * (bar_len - filled))

        print(f"  {COLOR_MUTED_GRAY}SCAN PROGRESS  {COLOR_BRAND_YELLOW}{bar_str}{COLOR_RESET}  {COLOR_WHITE}{pct}%{COLOR_RESET}")
        print()
        sys.stdout.flush()
