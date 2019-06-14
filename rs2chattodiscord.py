#!/usr/bin/env python3

import argparse
import sys
import os

from selenium import webdriver
from urllib import request
from urllib import parse


RS2_CHAT_PATH = "/ServerAdmin/current/chat"
RS2_LOGIN_PATH = "/ServerAdmin/"


class RS2WebAdmin(object):
    def __init__(self, address):
        proxy = os.environ.get("http_proxy")
        if proxy:
            print(f"Using proxy: {proxy}")
            webdriver.DesiredCapabilities.FIREFOX["proxy"] = {"httpProxy": proxy}
        self.driver = webdriver.Firefox()
        self.login_url = parse.urljoin(address, RS2_LOGIN_PATH)
        self.chat_url = parse.urljoin(address, RS2_CHAT_PATH)

    def login(self, username, password):
        self.driver.get(self.login_url)
        assert "Login" in self.driver.title

        uname = self.driver.find_element_by_id("username")
        uname.clear()
        uname.send_keys(username)

        passw = self.driver.find_element_by_id("password")
        passw.clear()
        passw.send_keys(password)

        self.driver.find_element_by_css_selector("input.button").click()

    # TODO:
    def get_chat(self):
        return {}


class YaaDiscord(object):
    def __init__(self, webhook):
        self.webhook = webhook

    def post_chat(self, chat_messages):
        pass


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("-a", "--host")
    ap.add_argument("-p", "--port")
    ap.add_argument("-u", "--username")
    ap.add_argument("-s", "--password")
    ap.add_argument("-w", "--webhook")
    return ap.parse_args()


def main():
    args = parse_args()
    addr = parse.urljoin(args.host, args.port)
    rs2wa = RS2WebAdmin(addr)
    rs2wa.login(args.username, args.password)
    yd = YaaDiscord(args.webhook)

    # TODO:
    chat = rs2wa.get_chat()
    yd.post_chat(chat)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
