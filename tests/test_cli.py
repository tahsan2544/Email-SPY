import json
import subprocess
import sys
from pathlib import Path

from rich.console import Console

from emailscope.cli import _shortcuts_menu, build_parser, main, resolve_options
from emailscope.models import Case, Finding
from emailscope.theme import get_theme


def test_parser_exposes_every_module_toggle():
    parser = build_parser()
    args = parser.parse_args(["user@example.com", "--no-smtp", "--no-accounts"])
    options = resolve_options(args)
    assert options.smtp is False
    assert options.accounts is False
    assert options.dns is True


def test_only_runs_the_listed_modules():
    args = build_parser().parse_args(["user@example.com", "--only", "dns,smtp"])
    options = resolve_options(args)
    assert options.dns is True
    assert options.smtp is True
    assert options.identity is False
    assert options.gravatar is False
    assert options.accounts is False


def test_only_accepts_dashes_and_rejects_unknown_modules(capsys):
    args = build_parser().parse_args(["user@example.com", "--only", "dns"])
    assert resolve_options(args).dns is True

    assert main(["user@example.com", "--only", "dns,telepathy"]) == 1
    assert "unknown module" in capsys.readouterr().err


def test_explicit_no_flag_still_wins_over_only():
    args = build_parser().parse_args(["user@example.com", "--only", "dns", "--no-dns"])
    assert resolve_options(args).dns is False


def test_proxy_is_kept_when_the_scheme_is_known():
    args = build_parser().parse_args(["user@example.com", "--proxy", "socks5h://127.0.0.1:9150"])
    assert resolve_options(args).proxy == "socks5h://127.0.0.1:9150"


def test_proxy_with_an_unknown_scheme_is_a_usage_error(capsys):
    assert main(["user@example.com", "--proxy", "ftp://example.com:21"]) == 1
    assert "unsupported proxy scheme" in capsys.readouterr().err


def test_list_modules_exits_zero(capsys):
    assert main(["--list-modules"]) == 0
    out = capsys.readouterr().out
    assert "gravatar" in out
    assert "smtp" in out


def test_missing_email_is_a_usage_error(capsys):
    assert main([]) == 1
    assert "no email address" in capsys.readouterr().err


def test_invalid_email_is_rejected_before_any_lookup(capsys):
    assert main(["not-an-email"]) == 1
    assert "not a valid email address" in capsys.readouterr().err


def test_conflicting_output_flags(capsys):
    assert main(["user@example.com", "--json", "--markdown"]) == 1
    assert main(["user@example.com", "--json", "--csv"]) == 1
    assert main(["user@example.com", "--json", "--html"]) == 1
    assert "only one of --json" in capsys.readouterr().err


def test_html_output_written_to_file(tmp_path, capsys):
    target = tmp_path / "report.html"
    code = main(["john.doe@example.com", "-o", str(target), "--only", "identity"])
    assert code == 0
    html = target.read_text()
    assert html.startswith("<!DOCTYPE html>")
    assert "john.doe@example.com" in html
    assert "written" in capsys.readouterr().out


def test_html_flag_prints_one_document_for_a_batch(capsys):
    code = main(["john.doe@example.com", "jane@example.org", "--only", "identity", "--html"])
    assert code == 0
    html = capsys.readouterr().out
    assert html.count("<!DOCTYPE html>") == 1
    assert "john.doe@example.com" in html and "jane@example.org" in html


def test_csv_output_written_to_file(tmp_path, capsys):
    target = tmp_path / "triage.csv"
    code = main(["john.doe@example.com", "-o", str(target), "--only", "identity"])
    assert code == 0
    rows = target.read_text().splitlines()
    assert rows[0] == "email,module,status,title,summary,source,links"
    assert any(row.startswith("john.doe@example.com,identity,info,") for row in rows)
    assert "written" in capsys.readouterr().out


def test_multiple_addresses_emit_a_json_array(capsys):
    code = main(["john.doe@example.com", "jane@example.org", "--only", "identity", "--json"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert [case["email"] for case in payload] == ["john.doe@example.com", "jane@example.org"]
    assert all(case["findings"][0]["module"] == "identity" for case in payload)


def test_batch_file_supplies_addresses_and_skips_comments(tmp_path, capsys):
    batch = tmp_path / "roster.txt"
    batch.write_text("# targets for this run\njane@example.org\n\n# end\n")
    code = main(["john.doe@example.com", "--batch", str(batch), "--only", "identity", "--json"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert [case["email"] for case in payload] == ["john.doe@example.com", "jane@example.org"]


def test_invalid_address_in_a_batch_is_reported(capsys):
    assert main(["john.doe@example.com", "not-an-email", "--json"]) == 1
    assert "not a valid email address: not-an-email" in capsys.readouterr().err


def test_missing_batch_file_is_a_usage_error(capsys):
    assert main(["--batch", "/nonexistent/roster.txt"]) == 1
    assert "cannot read --batch file" in capsys.readouterr().err


def test_version_flag():
    try:
        main(["--version"])
    except SystemExit as exc:
        assert exc.code == 0


def test_subprocess_help_and_version():
    root = Path(__file__).resolve().parents[1]
    env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(root / "src")}
    for flag in ("--help", "--version"):
        result = subprocess.run(
            [sys.executable, "-m", "emailscope", flag],
            capture_output=True,
            text=True,
            env=env,
            cwd=root,
        )
        assert result.returncode == 0
        assert "emailscope" in (result.stdout + result.stderr).lower()


def test_json_output_written_to_file(tmp_path, capsys):
    target = tmp_path / "out" / "report.json"
    # Offline module only, so the test never touches the network.
    code = main(["john.doe@example.com", "--json", "-o", str(target), "--only", "identity"])
    assert code == 0
    payload = json.loads(target.read_text())
    assert payload["email"] == "john.doe@example.com"
    assert any(f["module"] == "identity" for f in payload["findings"])


def test_shortcuts_menu_never_runs_without_a_tty(monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    # Piped or scripted sessions must not block waiting for a keypress.
    _shortcuts_menu(Console(), get_theme("spy"), [Case(email="a@example.com")], proxy=None)


def test_shortcuts_menu_saves_json_and_finishes(monkeypatch, tmp_path):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    keys = iter(["j", "q"])
    monkeypatch.setattr("emailscope.cli._read_key", lambda: next(keys))
    monkeypatch.chdir(tmp_path)

    case = Case(email="john.doe@example.com")
    case.add(
        Finding(
            module="identity",
            title="Address",
            status="info",
            summary="Custom domain.",
            data={"email": "john.doe@example.com", "valid": True},
        )
    )
    _shortcuts_menu(Console(), get_theme("spy"), [case], proxy=None)

    saved = tmp_path / "john.doe@example.com.json"
    assert saved.exists()
    payload = json.loads(saved.read_text())
    assert payload["email"] == "john.doe@example.com"
