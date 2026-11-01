import unittest
from unittest.mock import patch

from updater import catalog, security, winget
from updater.models import Software

UPGRADE_OUTPUT = (
    "   - \r   \\ \r"
    "Name                                               Id                                Version            Available          Source\r\n"
    "---------------------------------------------------------------------------------------------------------------------------------\r\n"
    "Battle.net                                         Blizzard.BattleNet                Unknown            2.0.0.4232         winget\r\n"
    "foobar2000 v2.26.1 (x64)                           PeterPawlowski.foobar2000         2.26.1             2.26.2             winget\r\n"
    "Mozilla Thunderbird (x64 pl)                       Mozilla.Thunderbird.pl            155.0.1            159.0              winget\r\n"
    "3 upgrades available.\r\n"
)

LIST_OUTPUT = (
    "Name                     Id                                                       Version     Available Source\r\n"
    "--------------------------------------------------------------------------------------------------------------\r\n"
    "7-Zip 26.05 (x64)        7zip.7zip                                                26.05                 winget\r\n"
    "Adobe Acrobat (64-bit)   ARP\\Machine\\X64\\{AC76BA86-1033-1033-7760-BC15014EA700}   26.002.22031\r\n"
    "Zegar Windows            MSIX\\Microsoft.WindowsAlarms_1.1.158.0_x64__8wekyb3d8bbwe 1.1.158.0\r\n"
)

SHOW_OUTPUT = """Found OBS Studio [OBSProject.OBSStudio]
Version: 33.0.0
Publisher: OBS Project
Publisher Url: https://obsproject.com/
Homepage: https://obsproject.com/
License: GPL-2.0
Release Notes:
  Bug Fixes
  - Note: this is not a key
Installer:
  Installer Type: nullsoft
  Installer Url: https://cdn-fastly.obsproject.com/downloads/OBS-Studio-33.0-Windows-x64-Installer.exe
  Installer SHA256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  Offline Distribution Supported: true
"""


class WingetParsingTests(unittest.TestCase):
    def test_parse_upgrade_table(self):
        rows = winget.parse_table(UPGRADE_OUTPUT)
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[1], ["foobar2000 v2.26.1 (x64)", "PeterPawlowski.foobar2000", "2.26.1", "2.26.2", "winget"])
        self.assertEqual(rows[0][2], "Unknown")

    def test_parse_list_with_local_ids(self):
        pkgs = winget._rows_to_packages(winget.parse_table(LIST_OUTPUT))
        self.assertEqual([p.id for p in pkgs][0], "7zip.7zip")
        self.assertTrue(pkgs[1].is_local_only)
        self.assertEqual(pkgs[1].version, "26.002.22031")
        self.assertEqual(pkgs[2].source, "")

    def test_parse_show(self):
        info = winget.parse_show(SHOW_OUTPUT)
        self.assertEqual(info["id"], "OBSProject.OBSStudio")
        self.assertEqual(info["name"], "OBS Studio")
        self.assertEqual(info["Publisher"], "OBS Project")
        self.assertTrue(winget.installer_url(info).startswith("https://cdn-fastly.obsproject.com/"))
        self.assertEqual(len(winget.installer_sha256(info)), 64)
        self.assertEqual(winget.installer_type(info), "nullsoft")
        self.assertNotIn("Installer.Note", info)

    def test_merge_matches_by_name_and_registry_key(self):
        sw = [
            Software(name="7-Zip 26.05 (x64)", version="26.05", origin="HKLM"),
            Software(name="Adobe Acrobat (64-bit)", version="26.002.22031", origin="HKLM",
                     reg_key="{AC76BA86-1033-1033-7760-BC15014EA700}"),
            Software(name="foobar2000 v2.26.1 (x64)", version="2.26.1", origin="HKLM"),
        ]
        pkgs = winget._rows_to_packages(winget.parse_table(LIST_OUTPUT))
        pkgs += [p for p in winget._rows_to_packages(winget.parse_table(UPGRADE_OUTPUT)) if "foobar" in p.id]
        merged = winget.merge(sw, pkgs)
        by_name = {s.name: s for s in merged}
        self.assertEqual(by_name["7-Zip 26.05 (x64)"].winget_id, "7zip.7zip")
        self.assertFalse(by_name["7-Zip 26.05 (x64)"].has_update)
        self.assertIsNone(by_name["Adobe Acrobat (64-bit)"].winget_id)
        self.assertTrue(by_name["Adobe Acrobat (64-bit)"].winget_detected)
        self.assertTrue(by_name["foobar2000 v2.26.1 (x64)"].can_upgrade)
        self.assertIn("Zegar Windows", by_name)

    def test_merge_local_duplicate_does_not_override_repo_match(self):
        sw = [Software(name="Microsoft Edge", version="156.0.4314.50", origin="HKLM", reg_key="Microsoft Edge")]
        pkgs = [
            winget.WingetPackage("Microsoft Edge", "Microsoft.Edge", "156.0.4314.50", "156.0.4314.56", "winget"),
            winget.WingetPackage("Microsoft Edge", "MSIX\\Microsoft.MicrosoftEdge.Stable_154.0_neutral__8wekyb3d8bbwe",
                                 "154.0"),
        ]
        merged = winget.merge(sw, pkgs)
        edge = next(s for s in merged if s.origin == "HKLM")
        self.assertEqual(edge.winget_id, "Microsoft.Edge")
        self.assertTrue(edge.can_upgrade)
        self.assertEqual(len(merged), 2)


class SecurityTests(unittest.TestCase):
    def test_registrable_domain(self):
        self.assertEqual(security.registrable_domain("https://cdn-fastly.obsproject.com/x.exe"), "obsproject.com")
        self.assertEqual(security.registrable_domain("https://www.example.co.uk/"), "example.co.uk")

    def test_publishers_match(self):
        self.assertTrue(security.publishers_match("Mozilla", "Mozilla Foundation"))
        self.assertTrue(security.publishers_match("OBS Project", "OBS Project"))
        self.assertFalse(security.publishers_match("Evil Corp", "OBS Project"))

    def test_assess_winget_high(self):
        info = winget.parse_show(SHOW_OUTPUT)
        a = security.assess_winget(info, "winget", "OBS Project", verify_tls=False)
        self.assertEqual(a.level, security.LEVEL_HIGH, a.report())

    def test_assess_winget_http_is_low(self):
        info = winget.parse_show(SHOW_OUTPUT.replace("https://cdn-fastly", "http://cdn-fastly"))
        a = security.assess_winget(info, "winget", "OBS Project", verify_tls=False)
        self.assertEqual(a.level, security.LEVEL_LOW)

    def test_assess_winget_missing_hash_is_low(self):
        info = winget.parse_show(SHOW_OUTPUT.replace("Installer SHA256", "Something"))
        a = security.assess_winget(info, "winget", verify_tls=False)
        self.assertEqual(a.level, security.LEVEL_LOW)

    def test_assess_vendor(self):
        self.assertEqual(security.assess_vendor(Software(name="x"), verify_tls=False).level, security.LEVEL_NONE)
        s = Software(name="x", url_info="https://example.com")
        self.assertEqual(security.assess_vendor(s, verify_tls=False).level, security.LEVEL_MEDIUM)
        s = Software(name="x", url_info="http://example.com")
        self.assertEqual(security.assess_vendor(s, verify_tls=False).level, security.LEVEL_LOW)


class AdditionalCatalogTests(unittest.TestCase):
    CHOCO_FEED = b"""<?xml version="1.0"?>
    <feed xmlns="http://www.w3.org/2005/Atom"
          xmlns:d="http://schemas.microsoft.com/ado/2007/08/dataservices"
          xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata">
      <entry>
        <id>https://community.chocolatey.org/api/v2/Packages(Id='notepadplusplus',Version='8.8.5')</id>
        <title>notepadplusplus</title>
        <m:properties>
          <d:Version>8.8.5</d:Version>
          <d:Title>Notepad++</d:Title>
          <d:ProjectUrl>https://notepad-plus-plus.org/</d:ProjectUrl>
          <d:GalleryDetailsUrl>https://community.chocolatey.org/packages/notepadplusplus/8.8.5</d:GalleryDetailsUrl>
        </m:properties>
      </entry>
      <entry>
        <id>https://community.chocolatey.org/api/v2/Packages(Id='notepadplusplus',Version='8.8.4')</id>
        <title>notepadplusplus</title>
        <m:properties><d:Version>8.8.4</d:Version></m:properties>
      </entry>
    </feed>"""

    def test_scoop_filename_search_ranks_exact_match(self):
        paths = ["bucket/7zip.json", "bucket/7zip-extra.json", "bucket/notepadplusplus.json"]
        self.assertEqual(catalog._scoop_slugs("7zip", paths), ["7zip", "7zip-extra"])
        self.assertEqual(catalog._scoop_slugs("7-Zip", paths), ["7zip"])

    def test_scoop_manifest_requires_https_and_sha256(self):
        package = catalog.CatalogPackage(
            manager="scoop", name="demo", id="demo", version="1.0", source="Scoop Main",
            manifest={"version": "1.0", "url": "https://example.com/demo.zip", "hash": "a" * 64},
        )
        assessment = catalog.assess_scoop(package, verify_tls=False)
        self.assertEqual(assessment.level, security.LEVEL_MEDIUM)
        self.assertTrue(any("SHA256" in check.label for check in assessment.checks))

    def test_scoop_script_or_missing_hash_is_low(self):
        script_package = catalog.CatalogPackage(
            manager="scoop", name="demo", id="demo", version="1.0", source="Scoop Main",
            manifest={"version": "1.0", "url": "https://example.com/demo.zip", "hash": "a" * 64,
                      "post_install": ["Write-Host installed"]},
        )
        no_hash = catalog.CatalogPackage(
            manager="scoop", name="demo", id="demo", version="1.0", source="Scoop Main",
            manifest={"version": "1.0", "url": "https://example.com/demo.zip"},
        )
        self.assertEqual(catalog.assess_scoop(script_package, verify_tls=False).level, security.LEVEL_LOW)
        self.assertEqual(catalog.assess_scoop(no_hash, verify_tls=False).level, security.LEVEL_LOW)

    @patch("updater.catalog._read_url", return_value=CHOCO_FEED)
    def test_chocolatey_search_deduplicates_versions(self, _read_url):
        packages = catalog.search_chocolatey("notepadplusplus")
        self.assertEqual(len(packages), 1)
        self.assertEqual(packages[0].id, "notepadplusplus")
        self.assertEqual(packages[0].version, "8.8.5")
        self.assertEqual(packages[0].name, "Notepad++")
        self.assertIn("community.chocolatey.org/packages", packages[0].details_url)

    def test_chocolatey_is_always_low_trust(self):
        package = catalog.CatalogPackage(
            manager="chocolatey", name="Notepad++", id="notepadplusplus",
            version="8.8.5", source="Chocolatey Community",
        )
        assessment = catalog.assess_chocolatey(package)
        self.assertEqual(assessment.level, security.LEVEL_LOW)
        self.assertTrue(any("PowerShell" in check.label for check in assessment.checks))


if __name__ == "__main__":
    unittest.main()
