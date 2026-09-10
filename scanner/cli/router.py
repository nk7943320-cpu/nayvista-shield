"""
NayVista Shield - Main CLI State Machine & Router
Orchestrates Mode A (Interactive Console) and Mode B (Direct Target),
manages screen transitions, exit codes, and automation modes.
"""

import sys
import os
import json
import argparse
from typing import Optional, Dict, Any

from scanner.config import APP_NAME, APP_TAGLINE, APP_COMPANY, APP_VERSION
from scanner.scope import (
    ScopeViolationError,
    TargetSSRFBlockedError,
    TargetInvalidSchemeError,
    TargetUnavailableError,
)
from scanner.engine import ScannerEngine, ScanExecutionError
from scanner.report import generate_json_report, generate_html_report
from scanner.cli.terminal import clear_screen, prompt_choice, prompt_input
from scanner.cli.theme import COLOR_BRAND_YELLOW, COLOR_WHITE, COLOR_MUTED_GRAY, COLOR_RESET
from scanner.cli.history import save_scan
from scanner.cli.views.startup import render_startup_screen
from scanner.cli.views.menu import render_main_menu
from scanner.cli.views.mode_select import prompt_assessment_mode
from scanner.cli.views.target_review import prompt_target_url, render_target_review
from scanner.cli.views.assessment import LiveAssessmentRenderer
from scanner.cli.views.posture import render_security_posture
from scanner.cli.views.findings import browse_findings, render_findings_list
from scanner.cli.views.history_view import render_scan_history_menu, render_target_history_menu, _export_scan_report
from scanner.cli.views.reports_view import render_reports_menu
from scanner.cli.views.settings_view import render_settings_menu
from scanner.cli.views.help_about import render_help, render_about
from scanner.cli.views.error_view import render_error_panel, render_interrupted_panel

def parse_arguments() -> argparse.Namespace:
    """Parses command-line arguments preserving full backward compatibility."""
    parser = argparse.ArgumentParser(
        prog="shield",
        description=f"{APP_NAME} - {APP_TAGLINE}\nDeveloped by {APP_COMPANY}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  shield                                 # Launch interactive terminal security console
  shield https://example.com             # Direct assessment of authorized target
  shield https://example.com --details   # Detailed finding breakdowns
  shield https://example.com --json      # Machine-readable pure JSON output
  shield https://example.com --html-report audit.html
"""
    )
    parser.add_argument("target", nargs="?", help="Target URL to assess (e.g. https://example.com)")
    parser.add_argument("--target", "-t", dest="target_flag", help="Target URL (alternative to positional argument)")
    parser.add_argument("--details", action="store_true", help="Display detailed findings immediately after assessment")
    parser.add_argument("--mode", choices=["defensive", "safe", "active", "authorized", "attack", "simulation"], default="defensive", help="Assessment mode: 'defensive' (default), 'active' (authorized validation), or 'attack' (disabled)")
    parser.add_argument("--json", action="store_true", help="Output pure JSON report to stdout (automation/pipeline)")
    parser.add_argument("--html-report", metavar="FILE", help="Save print-ready HTML audit report to FILE")
    parser.add_argument("--allow-local", action="store_true", help="Permit assessing local mock targets (for testing)")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress non-essential output and banners")
    parser.add_argument("--json-stream", action="store_true", help="Stream JSON-lines progress events to stdout (backend IPC)")
    parser.add_argument("--debug", action="store_true", help="Enable verbose diagnostics and sanitized stack traces")
    parser.add_argument("--yes", "-y", action="store_true", help="Bypass interactive authorization confirmation")
    parser.add_argument("--version", "-v", action="version", version=f"{APP_NAME} v{APP_VERSION} - {APP_TAGLINE} ({APP_COMPANY})")

    return parser.parse_args()

def run_direct_mode(args: argparse.Namespace, target_url: str):
    """Executes Mode B: Direct Target Workflow."""
    # Enforce defensive and active modes only
    req_mode = getattr(args, "mode", "defensive").lower()
    if req_mode in ("attack", "simulation"):
        sys.stderr.write("Error: ATTACK SIMULATION mode is disabled in this release (coming in a future authorized-testing phase). Only DEFENSIVE and ACTIVE modes are supported.\n")
        sys.exit(1)

    is_active = req_mode in ("active", "authorized")
    mode_val = "ACTIVE / AUTHORIZED TESTING" if is_active else "DEFENSIVE / SAFE"

    # JSON Mode: STRICT GUARANTEE - stdout must contain ONLY pure valid JSON!
    if args.json:
        if is_active and not args.yes:
            sys.stderr.write("Authorization Required: Explicit authorization confirmation (--yes) is required for active assessments.\n")
            sys.exit(1)
        try:
            engine = ScannerEngine(
                target_url=target_url,
                allow_local=args.allow_local,
                mode=mode_val,
                authorized=True if (is_active and args.yes) or not is_active else False,
            )
            result = engine.scan()
            sys.stdout.write(generate_json_report(result) + "\n")
            sys.stdout.flush()
            sys.exit(0)
        except TargetSSRFBlockedError as e:
            sys.stderr.write(f"SSRF Protection Blocked: {e}\n")
            sys.exit(2)
        except TargetUnavailableError as e:
            sys.stderr.write(f"Target Unavailable: {e}\n")
            sys.exit(3)
        except ScanExecutionError as e:
            sys.stderr.write(f"Execution Error: {e.message}\n")
            sys.exit(3)
        except (TargetInvalidSchemeError, ScopeViolationError) as e:
            sys.stderr.write(f"Scope Violation: {e}\n")
            sys.exit(1)
        except Exception as e:
            sys.stderr.write(f"Error: {e}\n")
            sys.exit(5)

    # Backend IPC JSON-Stream Mode
    if args.json_stream:
        _run_json_stream_mode(args, target_url)
        return

    # Direct Terminal Mode
    # Authorization prompt unless --yes or quiet
    if not (args.yes or args.quiet):
        auth_choice = render_target_review(target_url, is_direct=True, mode=req_mode)
        if auth_choice != "1":
            print(f"  {COLOR_MUTED_GRAY}Assessment cancelled by user.{COLOR_RESET}")
            sys.exit(0)

    # Execute assessment
    _execute_assessment_with_ui(
        target_url,
        allow_local=args.allow_local,
        show_details=args.details,
        html_report_path=args.html_report,
        is_interactive=False,
        debug=args.debug,
        mode=mode_val,
        authorized=True,
    )

def _run_json_stream_mode(args: argparse.Namespace, target_url: str):
    """Handles IPC JSON streaming for backend subprocess integration."""
    import time
    def on_progress(phase: str, message: str, step: int, total_steps: int, stats: Optional[Dict[str, Any]] = None):
        event = {
            "type": "progress",
            "phase": phase,
            "message": message,
            "step": step,
            "total_steps": total_steps,
            "stats": stats or {},
            "timestamp": time.time(),
        }
        sys.stdout.write(json.dumps(event) + "\n")
        sys.stdout.flush()

    is_active = getattr(args, "mode", "defensive").lower() in ("active", "authorized")
    mode_val = "ACTIVE / AUTHORIZED TESTING" if is_active else "DEFENSIVE / SAFE"

    try:
        engine = ScannerEngine(
            target_url=target_url,
            allow_local=args.allow_local,
            on_progress=on_progress,
            mode=mode_val,
            authorized=True,
        )
        result = engine.scan()
        sys.stdout.write("\n===SENTINELSCAN_RESULT===\n")
        sys.stdout.write(json.dumps(result, indent=2))
        sys.stdout.write("\n")
        sys.stdout.flush()
        sys.exit(0)
    except KeyboardInterrupt:
        sys.stderr.write(json.dumps({"type": "error", "code": "USER_INTERRUPTED", "error": "Scan cancelled by user"}) + "\n")
        sys.exit(4)
    except TargetSSRFBlockedError as e:
        sys.stderr.write(json.dumps({"type": "error", "code": "SSRF_BLOCKED", "error": str(e)}) + "\n")
        sys.exit(2)
    except TargetUnavailableError as e:
        sys.stderr.write(json.dumps({"type": "error", "code": "DNS_RESOLUTION_FAILED", "error": str(e)}) + "\n")
        sys.exit(3)
    except ScanExecutionError as e:
        sys.stderr.write(json.dumps({"type": "error", "code": e.code, "error": e.message}) + "\n")
        sys.exit(3)
    except (TargetInvalidSchemeError, ScopeViolationError) as e:
        sys.stderr.write(json.dumps({"type": "error", "code": "SCOPE_VIOLATION", "error": str(e)}) + "\n")
        sys.exit(1)
    except Exception as e:
        sys.stderr.write(json.dumps({"type": "error", "code": "INTERNAL_ERROR", "error": str(e)}) + "\n")
        sys.exit(5)

def _execute_assessment_with_ui(
    target_url: str,
    allow_local: bool = False,
    show_details: bool = False,
    html_report_path: Optional[str] = None,
    is_interactive: bool = False,
    debug: bool = False,
    mode: str = "DEFENSIVE / SAFE",
    authorized: bool = True,
):
    """Executes the scanner engine with real-time UI dashboard and handles post-scan results."""
    renderer = LiveAssessmentRenderer(target_url)

    try:
        engine = ScannerEngine(
            target_url=target_url,
            allow_local=allow_local,
            on_progress=renderer.on_progress,
            on_activity=renderer.on_activity,
            mode=mode,
            authorized=authorized,
        )
        result = engine.scan()

        # Save to persistent history
        save_scan(result)

        # Handle --html-report export
        if html_report_path:
            html = generate_html_report(result)
            with open(html_report_path, "w", encoding="utf-8") as f:
                f.write(html)
            print(f"  {COLOR_BRAND_YELLOW}[OK] HTML audit report saved to: {html_report_path}{COLOR_RESET}")

        # Render Posture
        clear_screen()
        render_security_posture(result)

        findings = result.get("findings", [])
        if show_details:
            render_findings_list(findings)

        # Post-scan navigation menu
        if is_interactive:
            _post_scan_loop(result)
        else:
            print(f"  {COLOR_MUTED_GRAY}Assessment complete. Stored in history.{COLOR_RESET}")
            sys.exit(0)

    except KeyboardInterrupt:
        if is_interactive:
            choice = render_interrupted_panel(target_url, renderer.current_step, renderer.total_steps, renderer.findings_count)
            if choice == "1":
                return
            sys.exit(4)
        else:
            print(f"\n{COLOR_BRAND_YELLOW}ASSESSMENT INTERRUPTED (Ctrl+C){COLOR_RESET}")
            sys.exit(4)

    except TargetSSRFBlockedError as e:
        if is_interactive:
            choice = render_error_panel("SSRF PROTECTION BLOCKED", str(e), code="SSRF_BLOCKED")
            if choice == "1":
                run_interactive_new_assessment(allow_local=allow_local, debug=debug)
            return
        else:
            print(f"\n{COLOR_BRAND_YELLOW}[ERROR] SSRF PROTECTION BLOCKED: {e}{COLOR_RESET}")
            sys.exit(2)

    except TargetUnavailableError as e:
        if is_interactive:
            choice = render_error_panel("TARGET UNAVAILABLE", str(e), code="DNS_RESOLUTION_FAILED")
            if choice == "1":
                run_interactive_new_assessment(allow_local=allow_local, debug=debug)
            return
        else:
            print(f"\n{COLOR_BRAND_YELLOW}[ERROR] TARGET UNAVAILABLE: {e}{COLOR_RESET}")
            sys.exit(3)

    except ScanExecutionError as e:
        if is_interactive:
            choice = render_error_panel("TARGET CONNECTION FAILED", e.message, code=e.code)
            if choice == "1":
                run_interactive_new_assessment(allow_local=allow_local, debug=debug)
            return
        else:
            print(f"\n{COLOR_BRAND_YELLOW}[ERROR] TARGET CONNECTION FAILED [{e.code}]: {e.message}{COLOR_RESET}")
            sys.exit(3)

    except (TargetInvalidSchemeError, ScopeViolationError) as e:
        if is_interactive:
            choice = render_error_panel("SCOPE VIOLATION", str(e), code="SCOPE_ERROR")
            if choice == "1":
                run_interactive_new_assessment(allow_local=allow_local, debug=debug)
            return
        else:
            print(f"\n{COLOR_BRAND_YELLOW}[ERROR] SCOPE VIOLATION: {e}{COLOR_RESET}")
            sys.exit(1)

    except Exception as e:
        if is_interactive:
            choice = render_error_panel("INTERNAL ERROR", str(e), code="INTERNAL_ERROR")
            if debug:
                import traceback
                traceback.print_exc()
            if choice == "1":
                run_interactive_new_assessment(allow_local=allow_local, debug=debug)
            return
        else:
            print(f"\n{COLOR_BRAND_YELLOW}[ERROR] INTERNAL ERROR: {e}{COLOR_RESET}")
            if debug:
                import traceback
                traceback.print_exc()
            sys.exit(5)

def _post_scan_loop(result: Dict[str, Any]):
    """Handles options after an interactive scan completes."""
    findings = result.get("findings", [])
    while True:
        print(f"  {COLOR_BRAND_YELLOW}[1]{COLOR_RESET} {COLOR_WHITE}VIEW FINDINGS ({len(findings)}){COLOR_RESET}")
        print(f"  {COLOR_BRAND_YELLOW}[2]{COLOR_RESET} {COLOR_WHITE}VIEW DETAILED REPORT{COLOR_RESET}")
        print(f"  {COLOR_BRAND_YELLOW}[3]{COLOR_RESET} {COLOR_WHITE}EXPORT JSON REPORT{COLOR_RESET}")
        print(f"  {COLOR_BRAND_YELLOW}[4]{COLOR_RESET} {COLOR_WHITE}VIEW SUMMARY{COLOR_RESET}")
        print(f"  {COLOR_BRAND_YELLOW}[5]{COLOR_RESET} {COLOR_WHITE}RETURN TO MAIN MENU{COLOR_RESET}")
        print(f"  {COLOR_BRAND_YELLOW}[6]{COLOR_RESET} {COLOR_MUTED_GRAY}EXIT{COLOR_RESET}")
        print()

        choice = prompt_choice({"1", "2", "3", "4", "5", "6"}, prompt_label="NAYVISTA-SHIELD > ", default="1")
        if choice == "1":
            browse_findings(findings)
        elif choice == "2":
            _export_scan_report(result)
        elif choice == "3":
            default_name = f"nayvista_report_{result.get('hostname')}.json"
            fname = prompt_input(f"Output file [{default_name}] > ").strip() or default_name
            with open(fname, "w", encoding="utf-8") as f:
                f.write(generate_json_report(result))
            print(f"  {COLOR_BRAND_YELLOW}[OK] Exported to {fname}{COLOR_RESET}\n")
        elif choice == "4":
            clear_screen()
            render_security_posture(result)
        elif choice == "5":
            return
        elif choice == "6":
            sys.exit(0)

def run_interactive_new_assessment(allow_local: bool = False, debug: bool = False):
    """Handles option 01: New Security Assessment."""
    target_url = prompt_target_url()
    if not target_url:
        return

    # Assessment Mode Selection
    mode = prompt_assessment_mode()
    if mode == "cancel":
        return

    # Target review and authorization
    is_active = mode in ("active", "authorized")
    mode_val = "ACTIVE / AUTHORIZED TESTING" if is_active else "DEFENSIVE / SAFE"

    choice = render_target_review(target_url, is_direct=False, mode=mode)
    if choice == "1":
        _execute_assessment_with_ui(
            target_url,
            allow_local=allow_local,
            is_interactive=True,
            debug=debug,
            mode=mode_val,
            authorized=True,
        )
    elif choice == "2":
        run_interactive_new_assessment(allow_local=allow_local, debug=debug)
    else:
        return

def run_interactive_mode(allow_local: bool = False, debug: bool = False):
    """Executes Mode A: Interactive Console."""
    clear_screen()
    render_startup_screen()

    while True:
        choice = render_main_menu()
        if choice == "01":
            run_interactive_new_assessment(allow_local=allow_local, debug=debug)
            clear_screen()
        elif choice == "02":
            render_scan_history_menu()
            clear_screen()
        elif choice == "03":
            render_target_history_menu()
            clear_screen()
        elif choice == "04":
            render_reports_menu()
            clear_screen()
        elif choice == "05":
            render_settings_menu()
            clear_screen()
        elif choice == "06":
            render_help()
            clear_screen()
        elif choice == "07":
            render_about()
            clear_screen()
        elif choice == "08":
            print(f"\n  {COLOR_BRAND_YELLOW}Exiting NayVista Shield Console. Stay secure.{COLOR_RESET}\n")
            sys.exit(0)

def main():
    """Primary entry point for shield and all backward-compatible aliases."""
    # Ensure stdout handles UTF-8 where supported
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    args = parse_arguments()
    target = args.target or args.target_flag

    # Check ALLOW_LOCAL_TARGETS env var
    allow_local = args.allow_local or os.environ.get("ALLOW_LOCAL_TARGETS", "").lower() in ("1", "true", "yes")

    if target:
        # Mode B: Direct Target
        run_direct_mode(args, target)
    else:
        # Mode A: Interactive Console
        run_interactive_mode(allow_local=allow_local, debug=args.debug)

if __name__ == "__main__":
    main()
