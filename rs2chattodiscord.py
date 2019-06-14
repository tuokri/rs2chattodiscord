#!/usr/bin/env python3

import argparse
import os
import sys
import time
from urllib import parse

from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.support.ui import Select

RS2_CHAT_PATH = "/ServerAdmin/current/chat"
RS2_LOGIN_PATH = "/ServerAdmin/"


class RS2WebAdmin(object):
    def __init__(self, base_addr: str):
        proxy = os.environ.get("http_proxy")
        if proxy:
            print(f"Using proxy: {proxy}")
            webdriver.DesiredCapabilities.FIREFOX["proxy"] = {
                "httpProxy": proxy,
                "ftpProxy": proxy,
                "sslProxy": proxy,
                "proxyType": "MANUAL",
            }
        self.driver = webdriver.Firefox()
        self.login_url = parse.urljoin(base_addr, RS2_LOGIN_PATH)
        self.chat_url = parse.urljoin(base_addr, RS2_CHAT_PATH)
        print(self.login_url)
        print(self.chat_url)

    def __del__(self):
        self.driver.close()
        self.driver.quit()

    def login(self, username: str, password: str):
        self.driver.get(self.login_url)
        if "Login" not in self.driver.title:
            raise NoSuchElementException("no 'Login' in driver.title")

        uname = self.driver.find_element_by_id("username")
        uname.clear()
        uname.send_keys(username)

        passw = self.driver.find_element_by_id("password")
        passw.clear()
        passw.send_keys(password)

        remember = Select(self.driver.find_element_by_tag_name("select"))
        remember.select_by_value("2678400")

        self.driver.find_element_by_tag_name("button").click()

    def navigate_to_chat(self):
        self.driver.get(self.chat_url)

    def get_chat_messages(self) -> list:
        try:
            chatlog = self.driver.find_element_by_id("chatlog")
        except NoSuchElementException as nse:
            print(f"error {nse}")
            return []

        chat_messages = chatlog.find_elements_by_class_name("chatmessage")
        return [{
            "teamcolor:": cm.find_element_by_class_name("teamcolor").get_attribute("style"),
            "teamnotice": cm.find_element_by_class_name("teamnotice").text if
            element_exists_by_class_name(cm, "teamnotice") else "",
            "username": cm.find_element_by_class_name("username").text,
            "message": cm.find_element_by_class_name("message").text,
        } for cm in chat_messages]

    def get_chat_notices(self) -> list:
        try:
            chatlog = self.driver.find_element_by_id("chatlog")
        except NoSuchElementException as nse:
            print(f"error {nse}")
            return []

        chat_notices = chatlog.find_elements_by_class_name("chatnotice")
        return [{
            "noticesymbol:": cn.find_element_by_class_name("noticesymbol").text,
            "username": cn.find_element_by_class_name("username").text,
            "message": cn.find_element_by_class_name("message").text,
        } for cn in chat_notices]


class YaaDiscord(object):
    def __init__(self, webhook):
        self.webhook = webhook

    def post_chat(self, chat_messages):
        pass


# TODO: is this needed?
def element_exists_by_class_name(parent, classname) -> bool:
    try:
        parent.find_element_by_class_name(classname)
    except NoSuchElementException:
        return False
    return True


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("-a", "--address")
    ap.add_argument("-u", "--username")
    ap.add_argument("-s", "--password")
    ap.add_argument("-w", "--webhook")
    return ap.parse_args()


def main():
    args = parse_args()
    print(args)
    addr = parse.urlparse(args.address)
    addr = parse.urlunparse((addr.scheme, addr.netloc, "", "", "", ""))
    print(addr)
    rs2wa = RS2WebAdmin(addr)
    yd = YaaDiscord(args.webhook)
    rs2wa.login(args.username, args.password)
    rs2wa.navigate_to_chat()

    while True:
        print(rs2wa.get_chat_messages())
        print(rs2wa.get_chat_notices())
        time.sleep(5)

    yd.post_chat(chat)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
