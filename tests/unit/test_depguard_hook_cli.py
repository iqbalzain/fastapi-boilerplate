from depguard.cli import build_parser
from depguard.hook import extract_install_specs
from depguard.pypi import package_info_from_json
from depguard.report import render_table, render_vet_json, render_vet_markdown


def test_hook_extracts_specs_from_shell_commands():
    specs, reasons = extract_install_specs("cd app && uv add --group dev 'rich>=13' httpx; echo ok")
    assert specs == ["rich>=13", "httpx"]
    assert reasons == []

    specs, reasons = extract_install_specs(
        "pip install -r requirements.txt git+https://x/y.git ./local"
    )
    assert specs == []
    assert len(reasons) == 3

    assert extract_install_specs("ls -la && pytest") == ([], [])
    assert extract_install_specs("python -m pip install --index-url https://x numpy")[0] == [
        "numpy"
    ]


def test_parser_subcommands():
    args = build_parser().parse_args(["vet", "httpx", "--offline", "--format", "json"])
    assert args.command == "vet" and args.offline and args.format == "json"
    args = build_parser().parse_args(["outdated", "--apply", "--security-only"])
    assert args.apply and args.security_only


def test_pypi_json_parsing():
    data = {
        "info": {
            "name": "x",
            "version": "1.1",
            "license": "MIT",
            "classifiers": [],
            "project_urls": None,
        },
        "releases": {
            "1.0": [
                {
                    "upload_time_iso_8601": "2025-01-01T00:00:00Z",
                    "packagetype": "sdist",
                    "yanked": False,
                    "filename": "x-1.0.tar.gz",
                }
            ],
            "1.1": [
                {
                    "upload_time_iso_8601": "2025-06-01T00:00:00Z",
                    "packagetype": "bdist_wheel",
                    "yanked": True,
                    "filename": "x-1.1.whl",
                },
            ],
            "1.2": [],
        },
    }
    info = package_info_from_json(data)
    assert {r.version for r in info.releases} == {"1.0", "1.1"}
    assert info.release("1.0").has_wheel is False
    assert info.release("1.1").yanked is True
    assert info.stable_releases()[0].version == "1.0"
    assert info.first_upload.year == 2025


def test_renderers(settings=None):
    from depguard.checks import Finding, Level, VetResult

    result = VetResult("pkg", None, "1.0", (Finding("license", Level.WARN, "unknown"),))
    assert "pkg" in render_vet_markdown([result])
    assert '"worst": "WARN"' in render_vet_json([result])
    table = render_table(["a", "b"], [["1", "2"]], markdown=False)
    assert "a  b" in table
    assert render_table(["a"], [["1"]], markdown=True).startswith("| a |")
