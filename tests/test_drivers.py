import unittest
from unittest.mock import patch

from updater import drivers, security

INVENTORY_ROWS = [
    {"DeviceName": "Intel(R) UHD Graphics", "DeviceID": "PCI\\VEN_8086&DEV_9A49\\3&11583659&0&10",
     "DriverVersion": "30.0.101.1191", "DriverDate": "2021-11-10", "DriverProviderName": "Intel Corporation",
     "Manufacturer": "Intel Corporation", "InfName": "oem12.inf", "DeviceClass": "DISPLAY", "IsSigned": True,
     "Signer": "Microsoft Windows Hardware Compatibility Publisher",
     "HardwareID": ["PCI\\VEN_8086&DEV_9A49&SUBSYS_0A6D1028", "PCI\\VEN_8086&DEV_9A49"],
     "CompatibleID": ["PCI\\CC_030000"], "ErrorCode": 0},
    {"DeviceName": "Stary skaner", "DeviceID": "USB\\VID_04A9&PID_1909\\5", "DriverVersion": "1.0.0.0",
     "DriverDate": "2009-01-01", "DriverProviderName": "Acme", "DeviceClass": "IMAGE", "IsSigned": False,
     "HardwareID": "USB\\VID_04A9&PID_1909", "ErrorCode": 0},
    {"DeviceName": "Nieznane urządzenie", "DeviceID": "ACPI\\FOO0001\\0", "DeviceClass": "",
     "HardwareID": ["ACPI\\FOO0001"], "CompatibleID": None, "ErrorCode": 28},
]

UPDATE_ROWS = [
    {"UpdateID": "6b1e5a2c-1111-4c3e-9a0b-0123456789ab", "Title": "Intel Corporation - Display - 31.0.101.5186",
     "DriverModel": "Intel(R) UHD Graphics", "DriverManufacturer": "Intel Corporation",
     "DriverProvider": "Intel Corporation", "DriverClass": "Display",
     "DriverHardwareID": "pci\\ven_8086&dev_9a49&subsys_0a6d1028", "DriverVerDate": "2024-01-15",
     "MaxDownloadSize": 524288000, "EulaAccepted": True},
    {"UpdateID": "aaaaaaaa-2222-4c3e-9a0b-0123456789ab", "Title": "Contoso - System - 2.0.0.0",
     "DriverModel": "Contoso ACPI", "DriverProvider": "Contoso", "DriverHardwareID": "ACPI\\FOO0001",
     "DriverVerDate": "2023-05-01", "EulaAccepted": False},
    {"UpdateID": "bbbbbbbb-3333-4c3e-9a0b-0123456789ab", "Title": "Fabrikam - Net - 5.1",
     "DriverModel": "Fabrikam NIC", "DriverHardwareID": "PCI\\VEN_FFFF&DEV_0001"},
    {"Title": "bez identyfikatora"},
]


class DriverTests(unittest.TestCase):
    def setUp(self):
        self.drivers = drivers.parse_inventory(INVENTORY_ROWS)
        self.updates = drivers.parse_updates(UPDATE_ROWS)

    def by_name(self, items, name):
        return next(d for d in items if d.device_name == name)

    def test_parse_inventory(self):
        self.assertEqual(len(self.drivers), 3)
        gpu = self.by_name(self.drivers, "Intel(R) UHD Graphics")
        self.assertEqual(gpu.signature_text, "Microsoft (WHQL)")
        self.assertEqual(len(gpu.hardware_ids), 2)
        scanner = self.by_name(self.drivers, "Stary skaner")
        self.assertEqual(scanner.hardware_ids, ["USB\\VID_04A9&PID_1909"])
        self.assertEqual(scanner.signature_text, "NIEPODPISANY")
        unknown = self.by_name(self.drivers, "Nieznane urządzenie")
        self.assertTrue(unknown.missing_driver)
        self.assertEqual(unknown.status, "Brak sterownika")
        self.assertIn("ACPI%5CFOO0001", unknown.catalog_url())
        self.assertTrue(unknown.catalog_url().startswith("https://www.catalog.update.microsoft.com/"))

    def test_parse_updates_and_version(self):
        self.assertEqual(len(self.updates), 3)
        self.assertEqual(self.updates[0].version, "31.0.101.5186")
        self.assertEqual(self.updates[2].version, "5.1")
        self.assertEqual(drivers.DriverUpdate("x", "Bez wersji").version, "")

    def test_is_newer(self):
        d = drivers.Driver("x", version="30.0.101.1191", date="2021-11-10")
        self.assertTrue(drivers.is_newer(drivers.DriverUpdate("u", "A - B - 31.0.101.5186"), d))
        self.assertFalse(drivers.is_newer(drivers.DriverUpdate("u", "A - B - 30.0.9.1"), d))
        self.assertTrue(drivers.is_newer(drivers.DriverUpdate("u", "Bez wersji", date="2022-01-01"),
                                         drivers.Driver("x", date="2021-11-10")))

    def test_match_updates(self):
        merged = drivers.match_updates(self.drivers, self.updates)
        self.assertEqual(len(merged), 4)  # niedopasowana karta sieciowa jako nowy wiersz
        gpu = self.by_name(merged, "Intel(R) UHD Graphics")
        self.assertEqual(gpu.update.update_id, UPDATE_ROWS[0]["UpdateID"])
        self.assertEqual(gpu.status, "Aktualizacja dostępna")
        self.assertEqual(self.by_name(merged, "Nieznane urządzenie").status, "Sterownik dostępny")
        self.assertIsNone(self.by_name(merged, "Stary skaner").update)
        self.assertEqual(self.by_name(merged, "Fabrikam NIC").update.title, "Fabrikam - Net - 5.1")
        # ponowne dopasowanie czyści poprzednie przypisania
        again = drivers.match_updates(self.drivers, [])
        self.assertIsNone(self.by_name(again, "Intel(R) UHD Graphics").update)

    def test_assessments(self):
        merged = drivers.match_updates(self.drivers, self.updates)
        gpu = drivers.assess(self.by_name(merged, "Intel(R) UHD Graphics"))
        self.assertEqual(gpu.level, security.LEVEL_HIGH)
        unsigned = drivers.assess(self.by_name(merged, "Stary skaner"))
        self.assertEqual(unsigned.level, security.LEVEL_LOW)
        self.assertIn("Katalogu Microsoft Update", unsigned.report())
        missing = drivers.assess(self.by_name(merged, "Nieznane urządzenie"))
        self.assertEqual(missing.level, security.LEVEL_MEDIUM)  # brak sterownika + licencja
        older = drivers.Driver("x", version="99.0", provider="Intel", hardware_ids=["HW"],
                               update=drivers.DriverUpdate("u", "Intel - D - 1.0", provider="AMD",
                                                           hardware_id="HW"))
        self.assertEqual(drivers.assess(older).level, security.LEVEL_MEDIUM)

    def test_install_rejects_invalid_ids(self):
        with self.assertRaises(drivers.DriverError):
            drivers.install_updates(["abc; Remove-Item C:\\"], lambda _l: None)
        self.assertEqual(drivers.install_updates([], lambda _l: None), [])

    def test_json_list(self):
        self.assertEqual(drivers._json_list(""), [])
        self.assertEqual(drivers._json_list('\ufeff{"a": 1}'), [{"a": 1}])
        self.assertEqual(drivers._json_list('[{"a": 1}, null]'), [{"a": 1}])

    @patch("updater.drivers.run_powershell", return_value="[]")
    def test_search_updates_empty(self, _run):
        self.assertEqual(drivers.search_updates(), [])


if __name__ == "__main__":
    unittest.main()
