#!/usr/bin/env python3

import argparse
import configparser as cp
import hashlib
import os
import re
import sys
import time
from collections import defaultdict
from io import BytesIO
from urllib import parse

import pycurl
from bs4 import BeautifulSoup

import logger
from yaadiscord import YaaDiscord

logger = logger.get_logger(__file__ + ":" + __name__)

HEADERS = {}
HEADERS_MAX_LEN = 50
RUNNING = True
MESSAGE_FORMAT = "({team}){emoji} **{username}**: {message}"
NORTH_EMOJI = ":red_circle:"
SOUTH_EMOJI = ":large_blue_circle:"


class AuthData(object):
    def __init__(self, timeout: int, authcred: str, sessionid: str, authtimeout: str):
        self._timeout = int(timeout)
        self._authcred = authcred
        self._sessionid = sessionid
        self._authtimeout = authtimeout

    @property
    def timeout(self) -> int:
        return self._timeout

    @property
    def authcred(self) -> str:
        return self._authcred

    @property
    def sessionid(self) -> str:
        return self._sessionid

    @property
    def authtimeout(self) -> str:
        return self._authtimeout


def read_config(config_file: str) -> cp.ConfigParser:
    config = cp.ConfigParser()
    config.read(config_file)
    return config


def validate_address(address: str) -> str:
    try:
        address = parse.urlparse(address)
        return parse.urlunparse((address.scheme, address.netloc, "", "", "", ""))
    except Exception as e:
        logger.error("Invalid address: %s", e)
        raise ValueError(e)


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--heroku", action="store_true")
    ap.add_argument("-c", "--config")
    return ap.parse_args()


def header_function(header_line):
    global HEADERS

    try:
        if len(HEADERS["connection"]) > HEADERS_MAX_LEN:
            print(HEADERS)
            logger.info(("Headers 'connection' values max length (%s) exceeded, resetting headers "
                         + "(preserving latest entries)"), HEADERS_MAX_LEN)
            new_headers = {}
            for k, v in HEADERS.items():
                new_headers[k] = v[-1]
            HEADERS = new_headers
            print(new_headers)
            logger.info("Headers 'connection' list new length=%s", len(HEADERS["connection"]))
    except KeyError as ke:
        logger.error("header_function(): error: %s", ke)
    except IndexError as ie:
        logger.error("header_function(): error: %s", ie)

    # HTTP standard specifies that headers are encoded in iso-8859-1.
    header_line = header_line.decode("iso-8859-1")

    # Header lines include the first status line (HTTP/1.x ...).
    # We are going to ignore all lines that don't have a colon in them.
    # This will botch headers that are split on multiple lines...
    if ":" not in header_line:
        return

    # Break the header line into header name and value.
    name, value = header_line.split(":", 1)

    # Remove whitespace that may be present.
    # Header lines include the trailing newline, and there may be whitespace
    # around the colon.
    name = name.strip()
    value = value.strip()

    # Header names are case insensitive.
    # Lowercase name here.
    name = name.lower()

    if name in HEADERS:
        if isinstance(HEADERS[name], list):
            HEADERS[name].append(value)
        else:
            HEADERS[name] = [HEADERS[name], value]
    else:
        HEADERS[name] = value


def print_headers(headers):
    print("** HEADER ITEMS **")
    for k, v in headers.items():
        print(f"{k}:", v)
    print("******************")


def read_encoding(headers: dict, index: int) -> str:
    encoding = None
    if "content-type" in headers:
        content_type = headers["content-type"][index].lower()
        match = re.search(r"charset=(\S+)", content_type)
        if match:
            encoding = match.group(1)
            logger.info("Decoding using %s", encoding)
    if encoding is None:
        # Default encoding for HTML is iso-8859-1.
        # Other content types may have different default encoding,
        # or in case of binary data, may have no encoding at all.
        encoding = "iso-8859-1"
        logger.info("Assuming encoding is %s", encoding)
    return encoding


def get_login(c: pycurl.Curl, url: str) -> bytes:
    buffer = BytesIO()

    header = [
        "User-Agent: Mozilla/5.0 (Windows NT 6.1; rv:60.0) Gecko/20100101 Firefox/60.0)",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language: en-US,en;q=0.7,fi;q=0.3",
        "DNT: 1",
        "Connection: keep-alive",
        "Upgrade-Insecure-Requests: 1",
    ]

    c.setopt(c.WRITEFUNCTION, buffer.write)
    c.setopt(c.HEADERFUNCTION, header_function)

    c.setopt(c.BUFFERSIZE, 102400)
    c.setopt(c.URL, url)
    c.setopt(c.HTTPHEADER, header)
    c.setopt(c.USERAGENT, "curl/7.65.1")
    c.setopt(c.MAXREDIRS, 50)
    # c.setopt(c.HTTP_VERSION, pycurl.CURL_HTTP_VERSION_2TLS)
    c.setopt(c.ACCEPT_ENCODING, "")
    # c.setopt(c.HTTP09_ALLOWED, 1)
    c.setopt(c.TCP_KEEPALIVE, 1)
    c.setopt(c.FOLLOWLOCATION, True)

    c.perform()
    logger.info("get_login() HTTP response: %s", c.getinfo(c.HTTP_CODE))
    return buffer.getvalue()


def post_login(c: pycurl.Curl, url: str, sessionid: str, token: str, username: str, password: str,
               remember=2678400) -> bytes:
    buffer = BytesIO()

    header = [
        "User-Agent: Mozilla/5.0 (Windows NT 6.1; rv:60.0) Gecko/20100101 Firefox/60.0)",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language: en-US,en;q=0.7,fi;q=0.3",
        "Referer: http://81.19.210.136:1005/",
        "Content-Type: application/x-www-form-urlencoded",
        "DNT: 1",
        "Connection: keep-alive",
        f"Cookie: {sessionid}",
        "Upgrade-Insecure-Requests: 1",
    ]

    password_hash = hashlib.sha1(
        bytearray(password, "utf-8") + bytearray(username, "utf-8")).hexdigest()

    postfields = (f"token={token}&password_hash=%24sha1%24{password_hash}"
                  + f"&username={username}&password=&remember={remember}")

    logger.debug(postfields)

    c.setopt(c.WRITEFUNCTION, buffer.write)
    c.setopt(c.HEADERFUNCTION, header_function)

    c.setopt(c.BUFFERSIZE, 102400)
    c.setopt(c.URL, url)
    c.setopt(c.POSTFIELDS, postfields)
    c.setopt(c.POSTFIELDSIZE_LARGE, 123)
    c.setopt(c.HTTPHEADER, header)
    c.setopt(c.USERAGENT, "curl/7.65.1")
    c.setopt(c.MAXREDIRS, 50)
    # c.setopt(c.HTTP_VERSION, pycurl.CURL_HTTP_VERSION_2TLS)
    c.setopt(c.ACCEPT_ENCODING, "")
    # c.setopt(c.HTTP09_ALLOWED, True)
    c.setopt(c.TCP_KEEPALIVE, 1)
    c.setopt(c.FOLLOWLOCATION, True)

    c.perform()
    logger.info("post_login() HTTP response: %s", c.getinfo(c.HTTP_CODE))
    return buffer.getvalue()


def get_messages(c: pycurl.Curl, url: str, sessionid: str, authcred: str, authtimeout: int) -> bytes:
    buffer = BytesIO()

    header = [
        "User-Agent: Mozilla/5.0 (Windows NT 6.1; rv:60.0) Gecko/20100101 Firefox/60.0)",
        "Accept: */*",
        "Accept-Language: en-US,en;q=0.7,fi;q=0.3",
        "Referer: http://81.19.210.136:1005/",
        "Content-Type: application/x-www-form-urlencoded",
        "X-Requested-With: XMLHttpRequest",
        "DNT: 1",
        "Connection: keep-alive",
        f"Cookie: {sessionid}; {authcred}; {authtimeout}",
        "Upgrade-Insecure-Requests: 1",
    ]

    postfields = "ajax=1"

    c.setopt(c.WRITEFUNCTION, buffer.write)
    c.setopt(c.HEADERFUNCTION, header_function)

    c.setopt(c.BUFFERSIZE, 102400)
    c.setopt(c.URL, url)
    c.setopt(c.POSTFIELDS, postfields)
    c.setopt(c.POSTFIELDSIZE_LARGE, 6)
    c.setopt(c.HTTPHEADER, header)
    c.setopt(c.USERAGENT, "curl/7.65.1")
    c.setopt(c.MAXREDIRS, 50)
    # c.setopt(c.HTTP_VERSION, pycurl.CURL_HTTP_VERSION_2TLS)
    c.setopt(c.ACCEPT_ENCODING, "")
    # c.setopt(c.HTTP09_ALLOWED, True)
    c.setopt(c.TCP_KEEPALIVE, 1)
    c.setopt(c.FOLLOWLOCATION, True)

    c.perform()
    logger.info("get_messages() HTTP response: %s", c.getinfo(c.HTTP_CODE))
    return buffer.getvalue()


def authenticate(login_url: str, username: str, password: str) -> AuthData:
    c = pycurl.Curl()

    resp = get_login(c, login_url)
    encoding = read_encoding(HEADERS, -1)
    parsed_html = BeautifulSoup(resp.decode(encoding), features="html.parser")
    token = parsed_html.find("input", attrs={"name": "token"}).get("value")
    logger.debug("token: %s", token)
    sessionid = HEADERS["set-cookie"].split(";")[0]

    post_login(c, login_url, sessionid=sessionid,
               token=token, username=username, password=password)

    authcred = [i for i in HEADERS["set-cookie"] if i.startswith("authcred=")][0]
    authtimeout = [i for i in HEADERS["set-cookie"] if i.startswith("authtimeout=")][0]

    authtimeout_value = int(re.search(r'authtimeout="(.*?)"', authtimeout).group(1))

    # print_headers(HEADERS)
    logger.debug("authcred: %s", authcred)
    logger.debug("authtimeout: %s", authtimeout)
    logger.info("authtimeout_value: %s", authtimeout_value)

    c.close()
    return AuthData(timeout=authtimeout_value, authcred=authcred, sessionid=sessionid, authtimeout=authtimeout)


def auth_timed_out(start_time, timeout):
    time_now = time.time()
    if (start_time + timeout) < time_now:
        logger.info("Authentication timed out for start_time=%s, timeout=%s, time_now=%s",
                    start_time, timeout, time_now)
        return True
    return False


def rs2_webadmin_worker():
    while True:
        pass


def discord_webhook_worker():
    while True:
        pass


def main():
    args = parse_args()
    cfg = defaultdict(dict)

    if args.heroku:
        logger.info("Running with --heroku argument")
        cfg["RS2_WEBADMIN"]["ADDRESS"] = os.environ["RS2_WEBADMIN_ADDRESS"]
        cfg["RS2_WEBADMIN"]["USERNAME"] = os.environ["RS2_WEBADMIN_USERNAME"]
        cfg["RS2_WEBADMIN"]["PASSWORD"] = os.environ["RS2_WEBADMIN_PASSWORD"]
        cfg["RS2_WEBADMIN"]["CHAT_PATH"] = os.environ["RS2_WEBADMIN_CHAT_PATH"]
        cfg["RS2_WEBADMIN"]["LOGIN_PATH"] = os.environ["RS2_WEBADMIN_LOGIN_PATH"]
        cfg["DISCORD"]["USERNAME"] = os.environ["DISCORD_USERNAME"]
        cfg["DISCORD"]["WEBHOOK_URL"] = os.environ["DISCORD_WEBHOOK_URL"]
        cfg["DISCORD"]["AVATAR_URL"] = os.environ["DISCORD_AVATAR_URL"]
        cfg["DISCORD"]["USER_AGENT"] = os.environ["DISCORD_USER_AGENT"]
        cfg["MISC"]["CREATOR"] = os.environ["CREATOR"]
        cfg["MISC"]["DATABASE_URL"] = os.environ["DATABASE_URL"]
    else:
        cfg = read_config(args.config)

    try:
        cfg["RS2_WEBADMIN"]["ADDRESS"] = validate_address(cfg["RS2_WEBADMIN"]["ADDRESS"])
    except ValueError as ve:
        logger.error("Error: %s", ve)
        sys.exit(1)

    login_url = parse.urljoin(cfg["RS2_WEBADMIN"]["ADDRESS"], cfg["RS2_WEBADMIN"]["LOGIN_PATH"])
    chat_data_url = parse.urljoin(cfg["RS2_WEBADMIN"]["ADDRESS"], cfg["RS2_WEBADMIN"]["CHAT_PATH"])

    username = cfg["RS2_WEBADMIN"]["USERNAME"]
    password = cfg["RS2_WEBADMIN"]["PASSWORD"]
    creator = cfg["MISC"]["CREATOR"]

    yd = YaaDiscord(cfg["DISCORD"])

    auth_data = authenticate(login_url, username, password)
    t = time.time()
    while RUNNING:
        if auth_timed_out(t, auth_data.timeout):
            logger.info("Re-authenticating")
            auth_data = authenticate(login_url, username, password)
            t = time.time()

        c = pycurl.Curl()

        resp = get_messages(c, chat_data_url, auth_data.sessionid, auth_data.authcred, auth_data.timeout)
        encoding = read_encoding(HEADERS, -1)
        parsed_html = BeautifulSoup(resp.decode(encoding), features="html.parser")
        divs = parsed_html.find_all("div", attrs={"class": "chatmessage"})

        # TODO:
        #  multiprocessing:
        #  process1: read messages from RS2 WebAdmin and enqueue them (producer).
        #  process2: dequeue messages and post them to webhook (consumer).

        # TODO:
        #  10 minute delay for posting to webhook.
        #  Store messages in PostgreSQL DB (in Heroku)?

        for div in divs:
            logger.info("%s divs in parsed HTML", len(divs))
            teamcolor = div.find("span", attrs={"class": "teamcolor"})
            teamnotice = div.find("span", attrs={"class": "teamnotice"})
            name = div.find("span", attrs={"class": "username"})
            msg = div.find("span", attrs={"class": "message"})

            if teamnotice:
                team = "TEAM"
                if teamcolor.get("style") == "background: #E54927;":
                    emoji = NORTH_EMOJI
                else:
                    emoji = SOUTH_EMOJI
            else:
                team = "ALL"
                emoji = ""

            chat_msg = MESSAGE_FORMAT.format(
                team=team, emoji=emoji, username=name.text, message=msg.text)

            logger.info("Posting message: %s", chat_msg)
            success = yd.post_chat_message(chat_msg)
            if not success:
                logger.info("Failed to post message to webhook, retrying")
                success = yd.retry_all_messages()
                if not success:
                    logger.error("Failed to retry")
                    yd.post_chat_message(f"Mr. {creator}, I don't feel so good. (Error, check logs!)")

            time.sleep(0.05)

        c.close()
        time.sleep(5)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
