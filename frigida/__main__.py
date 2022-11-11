#!/usr/bin/env python3
import argparse
import logging
import os
from pathlib import Path

from frigida import (
    get_package_name, decompress_apk, inject_frida_gadget, rebuild_apk,
    resign_apk, prepare_gadget_script
)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser()
    parser.add_argument("apk", help="Path to the original APK file.")
    parser.add_argument("arch", help="Architecture to target (e.g. arm64).")
    args = parser.parse_args()

    package_name = get_package_name(args.apk)

    uncompressed_apk_path = os.path.splitext(os.path.basename(args.apk))[0]

    decompress_apk(args.apk)
    inject_frida_gadget(uncompressed_apk_path, args.arch)
    rebuild_apk(uncompressed_apk_path)

    rebuilt_apk_path = Path(uncompressed_apk_path) / 'dist' / os.path.basename(args.apk)
    resign_apk(rebuilt_apk_path)

    prepare_gadget_script(args.apk, package_name)
