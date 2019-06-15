#!/usr/bin/env python3

import argparse
import configparser as cp
import sys
import time
from urllib import parse

from chatlog import ChatEntry
from chatlog import ChatLog
from chatlog import to_pretty_str
from rs2webadmin import RS2WebAdmin
from yaadiscord import YaaDiscord


def read_config(config_file: str) -> cp.ConfigParser:
    config = cp.ConfigParser()
    config.read(config_file)
    return config


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
    ccfg.add_argument("-g", "--geckodriver")
    fcfg.add_argument("-c", "--config")
    return ap.parse_args()


def main():
    args = parse_args()
    cfg = read_config(args.config)

    try:
        cfg["RS2_WEBADMIN"]["ADDRESS"] = validate_address(cfg["RS2_WEBADMIN"]["ADDRESS"])
    except ValueError:
        sys.exit(1)

    if args.geckodriver:
        sys.path.append(args.geckodriver)

    rs2wa = RS2WebAdmin(cfg["RS2_WEBADMIN"])
    yaa = YaaDiscord(cfg["DISCORD"])
    chatlog = ChatLog()

    rs2wa.login()
    rs2wa.navigate_to_chat()

    while True:
        cms = rs2wa.get_chat_messages()
        # TODO: Add this if deemed necessary.
        #  cns = rs2wa.get_chat_notices()
        if cms:
            print(f"Got {len(cms)} messages from RS2 WebAdmin")
            for chat_msg in cms:
                chatlog.add(ChatEntry(chat_msg))

        posted = 0
        for chat_entry in chatlog:
            hash(chat_entry)
            if not chat_entry.sent:
                yaa.post_chat_message(to_pretty_str(chat_entry))
                chat_entry.sent = True
                posted += 1
            time.sleep(0.1)

        print(f"Posted {posted} messages to Discord")
        time.sleep(2)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
