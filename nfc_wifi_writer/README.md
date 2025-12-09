# NFC Wi-Fi Tag Writer

This folder contains a simple Python script for encoding NFC tags so that scanning the tag prompts iPhones to join your Wi-Fi network automatically.

## Requirements
- Python 3.8+
- An NFC reader/writer compatible with [nfcpy](https://nfcpy.readthedocs.io/)
- The `nfcpy` and `ndeflib` packages:
  ```bash
  pip install nfcpy ndeflib
  ```
- Optional (for QR export that NFC Tools can import): `qrcode[pil]`
  ```bash
  pip install "qrcode[pil]"
  ```

## Usage
1. Connect your NFC writer to the machine running the script.
2. Run the writer with your network details:
   ```bash
   python writer.py --ssid "YourNetwork" --password "SuperSecret" --auth WPA2
   ```
   - `--auth` can be `WPA`, `WPA2`, or `nopass`.
   - Use `--hidden` if your SSID is hidden.
3. When prompted, tap a blank NFC tag to the writer. The tag will be encoded with a Wi-Fi payload that iOS can read to join your network.

## Using NFC Tools on iOS
If you prefer to program tags with the NFC Tools app instead of a USB writer:

1. Generate a Wi-Fi payload and QR code PNG:
   ```bash
   python writer.py --ssid "YourNetwork" --password "SuperSecret" --auth WPA2 --qr-path wifi.png --dry-run
   ```
   - The console prints the exact Wi-Fi payload string the app expects.
   - The `wifi.png` QR encodes the same payload; NFC Tools can import it directly.
2. In NFC Tools on iOS, go to **More > Import from QR Code** and scan `wifi.png` to prefill a Wi-Fi record.
3. Write the record to your tag from the app. iPhones scanning the tag will be prompted to join the Wi-Fi network.

## Notes
- The script writes a standard Wi-Fi configuration string (`WIFI:T:<auth>;S:<ssid>;P:<password>;H:<hidden>;`) into an NDEF URI record, which iPhones can scan to join the network.
- If the tag is not yet formatted for NDEF, the script attempts to format it when supported by the tag and reader.
