#!/usr/bin/env python3

import argparse
import configparser
import sys
from urllib import parse

from rs2webadmin import RS2WebAdmin
from yaadiscord import YaaDiscord


def read_config(config_file: str) -> dict:
    config = configparser.ConfigParser()
    return config.read(config_file)


def validate_address(address: str) -> str:
    try:
        address = parse.urlparse(address)
        return parse.urlunparse((address.scheme, address.netloc, "", "", "", ""))
    except Exception as e:
        print(f"Invalid address: {e}")
        raise ValueError(e)


def parse_args():
    ap = argparse.ArgumentParser()
    ccfg = ap.add_argument_group("clicfg")
    fcfg = ap.add_argument_group("filecfg")
    ccfg.add_argument("-a", "--address")
    ccfg.add_argument("-u", "--username")
    ccfg.add_argument("-p", "--password")
    ccfg.add_argument("-w", "--webhook")
    fcfg.add_argument("-c", "--config")
    return ap.parse_args()


def main():
    args = parse_args()
    cfg = read_config(args.config)

    try:
        cfg["RS2_WEBADMIN"]["ADDRESS"] = validate_address(cfg["RS2_WEBADMIN"]["ADDRESS"])
    except ValueError:
        sys.exit(1)

    rs2wa = RS2WebAdmin(cfg["RS2_WEBADMIN"])
    yd = YaaDiscord(cfg["DISCORD"])

    rs2wa.login(args.username, args.password)
    rs2wa.navigate_to_chat()

    while True:
        cms = rs2wa.get_chat_messages()
        print(cms)
        # TODO: Add this if deemed necessary.
        #  cns = rs2wa.get_chat_notices()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
