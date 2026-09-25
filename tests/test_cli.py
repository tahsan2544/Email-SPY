import json
import subprocess
import sys
from pathlib import Path

from emailscope.cli import build_parser, main, resolve_options


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
    assert "only one of --json" in capsys.readouterr().err


def test_csv_output_written_to_file(tmp_path, capsys):
    target = tmp_path / "triage.csv"
    code = main(["john.doe@example.com", "-o", str(target), "--only", "identity"])
    assert code == 0
    rows = target.read_text().splitlines()
    assert rows[0] == "module,status,title,summary,source,links"
    assert any(row.startswith("identity,info,") for row in rows)
    assert "written" in capsys.readouterr().out


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
