import os
import tempfile
import types
import unittest

from nfc_wifi_writer import writer


class DummyImage:
    def __init__(self, collector):
        self.collector = collector

    def save(self, path):
        # Write identifiable content so tests can assert the file was created.
        with open(path, "wb") as f:
            f.write(self.collector.get("payload", b""))


class DummyQRCode:
    def __init__(self, collector, *_, **__):
        self.collector = collector

    def add_data(self, payload):
        self.collector["payload"] = payload.encode()

    def make(self, fit=True):  # noqa: ARG002
        self.collector["made"] = True

    def make_image(self, *_, **__):
        self.collector["image_created"] = True
        return DummyImage(self.collector)


class DummyQRModule(types.SimpleNamespace):
    def __init__(self, collector):
        super().__init__(QRCode=lambda *args, **kwargs: DummyQRCode(collector, *args, **kwargs))


class GenerateQrTests(unittest.TestCase):
    def test_generate_qr_creates_file_with_stub(self):
        collector = {}
        qr_module = DummyQRModule(collector)
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "qr.png")
            writer.generate_qr("TESTPAYLOAD", output_path, qr_module=qr_module)
            self.assertTrue(os.path.exists(output_path))
            self.assertEqual(collector.get("payload"), b"TESTPAYLOAD")
            self.assertTrue(collector.get("made"))
            self.assertTrue(collector.get("image_created"))

    def test_generate_qr_skips_when_no_output_path(self):
        collector = {}
        qr_module = DummyQRModule(collector)
        writer.generate_qr("TESTPAYLOAD", "", qr_module=qr_module)
        self.assertEqual(collector, {})


if __name__ == "__main__":
    unittest.main()
