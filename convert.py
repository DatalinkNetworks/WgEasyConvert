from base64 import b64decode, b64encode
from argparse import ArgumentParser
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from dataclasses import dataclass, asdict
from datetime import datetime as dt, timezone as tz
import humps
import json
import os
import uuid


class ParseError(Exception):
    """Error Parsing the conf File"""

    pass


@dataclass
class WgEasy:
    id: str
    name: str
    address: str
    private_key: str
    public_key: str
    pre_shared_key: str
    created_at: str
    updated_at: str
    enabled: bool

    def dict(self) -> dict:
        return dict(humps.camelize(asdict(self)))


def convert_key(secret_key: str) -> str:
    # retrieve a public key from a secret key
    secret_key_raw = X25519PrivateKey.from_private_bytes(b64decode(secret_key + "=="))
    public_key_raw = secret_key_raw.public_key()
    public_key = (
        b64encode(public_key_raw.public_bytes_raw()).decode("utf-8").rstrip("=")
    )
    return public_key.ljust(44, "=")


def convert_file(filename: str) -> WgEasy:
    # Get the current timestamp in ISO UTC frmat
    now = dt.now(tz.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

    # Craft an empty/default WgEasy object
    wg = WgEasy(
        id=str(uuid.uuid4()),
        name="",
        address="",
        private_key="",
        public_key="",
        pre_shared_key="",
        created_at=now,
        updated_at=now,
        enabled=True,
    )

    # Read the conf file into lines
    with open(filename, "r") as fin:
        lines = [line for line in map(str.strip, fin) if line]

    # Comin gfrom WS4W, the name starts the file
    if not lines[0].startswith("# "):
        raise ParseError(f"'{filename}' first line does not start with '#'")

    wg.name = lines[0].split(" ")[-1]

    val = lambda s: s.split("=", 1)[-1]

    # Extract the information from the config files
    for line in lines:
        if line.startswith("Address="):
            wg.address = val(line)
        elif line.startswith("PrivateKey="):
            wg.private_key = val(line)
            wg.public_key = convert_key(wg.private_key)
        elif line.startswith("PresharedKey="):
            wg.pre_shared_key = val(line)

    required = ("name", "address", "private_key", "public_key", "pre_shared_key")
    for req in required:
        if not getattr(wg, req):
            raise ParseError(f"'{filename}' Missing {req}")
    return wg


def main():
    ap = ArgumentParser()
    ap.add_argument(
        "--dir",
        "-d",
        help="Directory containing wireguard 4 windows .conf files",
        required=True,
    )
    args = ap.parse_args()

    files = list(os.scandir(args.dir))
    total, success = 0, 0
    wgs = []

    for file in files:
        if not file.path.endswith(".conf"):
            continue
        try:
            wg = convert_file(file.path)
            wgs.append(wg)
            success += 1
        except Exception as e:
            print(e)
        finally:
            total += 1
    print(f"Converted {success} / {total} ({100*success/total:.2f}%)")
    config = {"clients": {wg.id: wg.dict() for wg in wgs}}
    print(json.dumps(config, indent=2))


if __name__ == "__main__":
    main()
