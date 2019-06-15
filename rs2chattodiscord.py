#!/usr/bin/env python3

import argparse
import configparser as cp
import logging
import os
import sys
import time
from urllib import parse

from chatlog import ChatEntry
from chatlog import ChatLog
from chatlog import to_pretty_str
from rs2webadmin import RS2WebAdmin
from yaadiscord import YaaDiscord

logger = logging.getLogger(__name__)


def read_config(config_file: str) -> cp.ConfigParser:
    config = cp.ConfigParser()
    config.read(config_file)
    return config


def validate_address(address: str) -> str:
    try:
        address = parse.urlparse(address)
        return parse.urlunparse((address.scheme, address.netloc, "", "", "", ""))
    except Exception as e:
        logging.error("Invalid address: %s", e)
        raise ValueError(e)


def parse_args():
    ap = argparse.ArgumentParser()

    fcfg = ap.add_argument_group("filecfg")
    fcfg.add_argument("-c", "--config")

    ccfg = ap.add_argument_group("clicfg")
    ccfg.add_argument("-a", "--address")
    ccfg.add_argument("-u", "--username")
    ccfg.add_argument("-p", "--password")
    ccfg.add_argument("-w", "--webhook")
    ccfg.add_argument("--heroku", action="store_true")

    return ap.parse_args()


def main():
    args = parse_args()

    if args.heroku:
        cfg = {}
        cfg["RS2_WEBADMIN"]["ADDRESS"] = os.environ["RS2_WEBADMIN_ADDRESS"]
        cfg["RS2_WEBADMIN"]["USERNAME"] = os.environ["RS2_WEBADMIN_USERNAME"]
        cfg["RS2_WEBADMIN"]["PASSWORD"] = os.environ["RS2_WEBADMIN_PASSWORD"]
        cfg["RS2_WEBADMIN"]["CHAT_PATH"] = os.environ["RS2_WEBADMIN_CHAT_PATH"]
        cfg["RS2_WEBADMIN"]["LOGIN_PATH"] = os.environ["RS2_WEBADMIN_LOGIN_PATH"]
        cfg["DISCORD"]["USERNAME"] = os.environ["DISCORD_USERNAME"]
        cfg["DISCORD"]["WEBHOOK_URL"] = os.environ["DISCORD_WEBHOOK_URL"]
        cfg["DISCORD"]["AVATAR_URL"] = os.environ["DISCORD_AVATAR_URL"]
        cfg["DISCORD"]["USER_AGENT"] = os.environ["DISCORD_USER_AGENT"]
    else:
        cfg = read_config(args.config)

    try:
        cfg["RS2_WEBADMIN"]["ADDRESS"] = validate_address(cfg["RS2_WEBADMIN"]["ADDRESS"])
    except ValueError:
        sys.exit(1)

    logger.info("Running with config: %s", cfg)

    rs2wa = RS2WebAdmin(cfg["RS2_WEBADMIN"])
    yaa = YaaDiscord(cfg["DISCORD"])
    chatlog = ChatLog()

    rs2wa.login()

    while True:
        rs2wa.navigate_to_chat()

        cms = rs2wa.get_chat_messages()
        # TODO: Add this if deemed necessary.
        #  cns = rs2wa.get_chat_notices()
        if cms:
            logging.info("Got %s messages from RS2 WebAdmin", len(cms))
            for chat_msg in cms:
                chatlog.add(ChatEntry(chat_msg))

        posted = 0
        for chat_entry in chatlog:
            if not chat_entry.sent:
                yaa.post_chat_message(to_pretty_str(chat_entry))
                chat_entry.sent = True
                posted += 1
            time.sleep(0.1)

        logging.info("Posted %s messages to Discord", posted)
        time.sleep(2)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
