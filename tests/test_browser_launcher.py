import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from core.browser_launcher import (
    BrowserExecutable,
    browser_not_found_message,
    build_browser_command,
    default_profile_dir,
    discover_browser,
    normalize_start_url,
    prepare_browser_launch,
    resolve_profile_dir,
)


class BrowserLauncherTests(unittest.TestCase):
    def test_build_browser_command_includes_proxy_profile_and_url(self):
        executable = BrowserExecutable(kind="chrome", path="chrome")

        command = build_browser_command(
            executable,
            proxy_host="127.0.0.1",
            proxy_port=8085,
            profile_dir=".mhr-browser-profile",
            url="https://example.com/",
        )

        self.assertEqual(command[0], "chrome")
        self.assertIn("--proxy-server=http://127.0.0.1:8085", command)
        self.assertIn("--user-data-dir=.mhr-browser-profile", command)
        self.assertIn("--disable-background-networking", command)
        self.assertEqual(command[-1], "https://example.com/")
        self.assertNotIn("--ignore-certificate-errors", command)

    def test_build_browser_command_adds_insecure_flag_only_when_requested(self):
        executable = BrowserExecutable(kind="edge", path="msedge")

        command = build_browser_command(
            executable,
            proxy_host="127.0.0.1",
            proxy_port=8085,
            profile_dir="profile",
            url="example.com",
            insecure_ignore_cert_errors=True,
        )

        self.assertIn("--ignore-certificate-errors", command)
        self.assertEqual(command[-1], "https://example.com")

    def test_resolve_profile_dir_supports_default_explicit_and_temporary(self):
        self.assertEqual(
            default_profile_dir("repo"),
            str(pathlib.Path("repo") / ".mhr-browser-profile"),
        )
        self.assertEqual(
            resolve_profile_dir(profile="custom-profile", cwd="repo"),
            ("custom-profile", False),
        )
        self.assertEqual(
            resolve_profile_dir(
                temporary_profile=True,
                temp_factory=lambda prefix: prefix + "abc",
            ),
            ("mhr-browser-abc", True),
        )

    def test_normalize_start_url_defaults_and_adds_https(self):
        self.assertEqual(normalize_start_url(None), "https://example.com/")
        self.assertEqual(normalize_start_url("github.com"), "https://github.com")
        self.assertEqual(normalize_start_url("http://example.com"), "http://example.com")

    def test_discover_browser_auto_uses_mocked_path_lookup(self):
        def fake_which(name):
            if name in {"chrome", "chrome.exe"}:
                return "/bin/chrome"
            return None

        result = discover_browser(
            "auto",
            platform="linux",
            path_exists=lambda _path: False,
            which=fake_which,
        )

        self.assertEqual(result, BrowserExecutable(kind="chrome", path="/bin/chrome"))

    def test_discover_browser_windows_program_files_candidate(self):
        env = {
            "PROGRAMFILES": r"C:\Program Files",
            "PROGRAMFILES(X86)": r"C:\Program Files (x86)",
            "LOCALAPPDATA": r"C:\Users\tester\AppData\Local",
        }
        expected = str(
            pathlib.Path(env["PROGRAMFILES"])
            / r"Microsoft\Edge\Application\msedge.exe"
        )

        result = discover_browser(
            "edge",
            platform="win32",
            env=env,
            path_exists=lambda path: path == expected,
            which=lambda _name: None,
        )

        self.assertEqual(result, BrowserExecutable(kind="edge", path=expected))

    def test_prepare_browser_launch_returns_full_model(self):
        launch = prepare_browser_launch(
            requested_browser="chrome",
            proxy_host="127.0.0.1",
            proxy_port=8085,
            url="example.com",
            profile=None,
            temporary_profile=True,
            insecure_ignore_cert_errors=False,
            temp_factory=lambda prefix: prefix + "xyz",
            platform="linux",
            path_exists=lambda _path: False,
            which=lambda name: "/usr/bin/google-chrome" if name == "google-chrome" else None,
        )

        self.assertIsNotNone(launch)
        self.assertEqual(launch.executable.kind, "chrome")
        self.assertEqual(launch.profile_dir, "mhr-browser-xyz")
        self.assertEqual(launch.url, "https://example.com")
        self.assertTrue(launch.temporary_profile)
        self.assertFalse(launch.insecure_ignore_cert_errors)
        self.assertIn("--proxy-server=http://127.0.0.1:8085", launch.command)

    def test_browser_not_found_message_mentions_manual_proxy(self):
        message = browser_not_found_message("auto", "127.0.0.1", 8085)

        self.assertIn("Chrome, Edge, or Chromium", message)
        self.assertIn("127.0.0.1:8085", message)


if __name__ == "__main__":
    unittest.main()
