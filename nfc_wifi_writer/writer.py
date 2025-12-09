"""Write Wi-Fi credentials to an NFC tag as a URI record compatible with iOS.

Usage example:
    python writer.py --ssid "MyNetwork" --password "TopSecret" --auth WPA2
"""

import argparse
import importlib
import sys


VALID_AUTH_TYPES = {"WPA", "WPA2", "nopass"}


def build_wifi_payload(ssid: str, password: str, auth: str, hidden: bool) -> str:
    """Create the Wi-Fi payload string used by iOS when scanning NFC/QR codes."""
    if ";" in ssid:
        raise ValueError("SSID must not contain semicolons for the WIFI payload format.")
    if password and ";" in password:
        raise ValueError("Password must not contain semicolons for the WIFI payload format.")

    auth_upper = auth.upper()
    if auth_upper not in VALID_AUTH_TYPES:
        raise ValueError(f"auth must be one of {', '.join(sorted(VALID_AUTH_TYPES))}")

    hidden_value = "true" if hidden else "false"
    # Format per Wi-Fi Alliance payload understood by iOS and Android.
    return f"WIFI:T:{auth_upper};S:{ssid};P:{password};H:{hidden_value};"


def write_tag(message) -> bool:
    """Write the provided NDEF message to the first NFC tag presented.

    Returns True on success, False otherwise.
    """

    import nfc

    def on_connect(tag):
        print(f"Tag detected: {tag}")

        if getattr(tag, "ndef", None):
            try:
                tag.ndef.message = message
                print("Tag written successfully.")
                return False  # Disconnect after writing.
            except Exception as exc:  # noqa: BLE001
                print(f"Failed to write NDEF message: {exc}")
                return False

        formatter = getattr(tag, "formatter", None)
        if formatter and formatter.is_formattable():
            try:
                formatter.format(message)
                print("Tag formatted and written successfully.")
            except Exception as exc:  # noqa: BLE001
                print(f"Failed to format and write tag: {exc}")
        else:
            print("Tag is not NDEF formatted and cannot be formatted by this reader.")
        return False

    try:
        with nfc.ContactlessFrontend("usb") as clf:
            print("Tap an NFC tag to the reader...")
            clf.connect(rdwr={"on-connect": on_connect})
            return True
    except IOError:
        print("No NFC reader found. Ensure your reader is connected and supported by nfcpy.")
    except Exception as exc:  # noqa: BLE001
        print(f"Unexpected error interacting with the NFC reader: {exc}")
    return False


def generate_qr(payload: str, output_path: str) -> None:
    """Generate a QR code image that NFC Tools can import as a Wi-Fi record."""

    if not output_path:
        return

    if importlib.util.find_spec("qrcode") is None:
        raise RuntimeError(
            "Install the optional 'qrcode[pil]' package to enable QR code generation."
        )

    qrcode = importlib.import_module("qrcode")
    qr = qrcode.QRCode(version=None, box_size=10, border=4)
    qr.add_data(payload)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(output_path)
    print(
        "Saved QR code to {path}. Scan it in NFC Tools (More > Import from QR Code) "
        "to prefill the Wi-Fi record before writing a tag.".format(path=output_path)
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Write Wi-Fi credentials to an NFC tag.")
    parser.add_argument("--ssid", required=True, help="Wi-Fi network name.")
    parser.add_argument("--password", default="", help="Wi-Fi password (omit if open network).")
    parser.add_argument("--auth", default="WPA2", help="Authentication type: WPA, WPA2, or nopass.")
    parser.add_argument("--hidden", action="store_true", help="Mark the network as hidden.")
    parser.add_argument("--dry-run", action="store_true", help="Print the payload without writing to a tag.")
    parser.add_argument(
        "--qr-path",
        help=(
            "Write a QR code PNG to this path. NFC Tools can import it to prefill the Wi-Fi record."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        payload = build_wifi_payload(args.ssid, args.password, args.auth, args.hidden)
    except ValueError as err:
        print(f"Error: {err}")
        return 1

    try:
        generate_qr(payload, args.qr_path or "")
    except RuntimeError as err:
        print(f"QR generation skipped: {err}")

    if args.dry_run:
        print(f"Payload: {payload}")
        return 0

    import ndef

    uri_record = ndef.UriRecord(payload)
    message = ndef.Message(uri_record)

    success = write_tag(message)
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
