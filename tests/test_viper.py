import importlib.util
import pathlib
import unittest

MODULE_PATH = pathlib.Path(__file__).parents[1] / "viper.py"
spec = importlib.util.spec_from_file_location("viper", MODULE_PATH)
viper = importlib.util.module_from_spec(spec)
assert spec.loader is not None
import sys
sys.modules[spec.name] = viper
spec.loader.exec_module(viper)


class ViperHelpersTest(unittest.TestCase):
    def test_partition_paths(self):
        self.assertEqual(viper.partition_path("/dev/sdb"), "/dev/sdb1")
        self.assertEqual(viper.partition_path("/dev/nvme0n1"), "/dev/nvme0n1p1")
        self.assertEqual(viper.partition_path("/dev/mmcblk0"), "/dev/mmcblk0p1")

    def test_recommended_wipe(self):
        self.assertEqual(viper.recommended_wipe("hdd"), "zero")
        self.assertEqual(viper.recommended_wipe("usb"), "zero")
        self.assertEqual(viper.recommended_wipe("ssd"), "discard")
        self.assertEqual(viper.recommended_wipe("nvme"), "discard")

    def test_label_sanitizing(self):
        self.assertEqual(viper.sanitize_label("Mein*Stick", "fat32"), "MEINSTICK")
        self.assertEqual(viper.sanitize_label("", "ext4"), "VIPER")
        self.assertEqual(viper.sanitize_label("a/b", "ext4"), "a_b")

    def test_kind_detection(self):
        self.assertEqual(viper.detect_kind({"path": "/dev/nvme0n1", "tran": "nvme", "rota": 0}), "nvme")
        self.assertEqual(viper.detect_kind({"path": "/dev/sdb", "tran": "usb", "rota": 0}), "usb")
        self.assertEqual(viper.detect_kind({"path": "/dev/sda", "tran": "sata", "rota": 1}), "hdd")
        self.assertEqual(viper.detect_kind({"path": "/dev/sda", "tran": "sata", "rota": "0"}), "ssd")


if __name__ == "__main__":
    unittest.main()
