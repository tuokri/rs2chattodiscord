#!/usr/bin/env python3

import argparse
import configparser as cp
import hashlib
import logging
import multiprocessing as mp
import os
import re
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
from urllib import parse

import numpy as np
import pycurl
from bs4 import BeautifulSoup

import mplogger
from yaadiscord import YaaDiscord

logger = logging.getLogger(__file__ + ":" + __name__)

HEADERS = {}
HEADERS_MAX_LEN = 50
RUNNING = True
MESSAGE_FORMAT = "({team}){emoji} **{username}**: {message}"
NOTICE_FORMAT = "**{message}**"
NORTH_EMOJI = ":red_circle:"
SOUTH_EMOJI = ":large_blue_circle:"
DELAY_SECONDS = 5 * 60
PING_ADMIN = "!admin"
PING_HC = "<@&548614059768020993>"
PING_PO = "<@&563072608564936704>"

HH_QUOTES = [
    "Your government has abandoned you, G.I.",
    "Defect, G.I., it is a very good idea to leave a sinking ship.",
    "You know you cannot win this war.",
    "G.I., the government has abandoned you, they have ordered you to die, G.I. Do not trust them.",
    "Defect, G.I.",
    "They lie to you, G.I.",
    "Your rich leaders grow richer while you die in the swamp, G.I.",
    "They will give you a medal, G.I., but only after you are dead.",
    "Your government lies to you every day, poor soldier.",
    "You have lost this war, G.I. Your army will leave you behind.",
    "G.I., your government has betrayed you, they will not return for you.",
    "The skies are dangerous, G.I., hey will napalm you tonight.",
    "G.I., your helicopters fall from the sky like broken birds.",
    "G.I., your airplanes bomb your own men.",
    "You are not safe here.",
    "Your pilots don't care that you are down here, G.I.",
    "They can not see you from their airplanes, G.I. They come to bomb you.",
    "How are you, G.I. Joe?",
    "Our rice is safe, G.I.",
    "Hahaha! Screw you, flying G.I.!",
    "I kill you, G.I.",
    "Go home, G.I.",
    "YAAA!",
    "G.I., your government feed you no rice. You go hungry in your fox hole, G.I.",
    "Imperialists make you fight this war, G.I. They do not care about you.",
]


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

    @sessionid.setter
    def sessionid(self, sessionid: str):
        self._sessionid = sessionid

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

    if "connection" in HEADERS:
        try:
            if len(HEADERS["connection"]) > HEADERS_MAX_LEN:
                logger.info(("Headers 'connection' values max length (%s) exceeded, resetting headers "
                             + "(preserving latest entries)"), HEADERS_MAX_LEN)
                new_headers = {}
                for k, v in HEADERS.items():
                    new_headers[k] = v[-1]
                HEADERS = new_headers
                logger.info("Headers 'connection' %s new length=%s",
                            type(HEADERS["connection"]), len(HEADERS["connection"]))
        except KeyError as ke:
            logger.error("header_function(): error: %s", ke, exc_info=True)
        except IndexError as ie:
            logger.error("header_function(): error: %s", ie, exc_info=True)

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
            logger.info("read_encoding(): encoding is %s", encoding)
    if encoding is None:
        # Default encoding for HTML is iso-8859-1.
        # Other content types may have different default encoding,
        # or in case of binary data, may have no encoding at all.
        encoding = "iso-8859-1"
        logger.info("read_encoding(): assuming encoding is %s", encoding)
    return encoding


def get_login(c: pycurl.Curl, url: str) -> bytes:
    logger.info("get_login() called")

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
    logger.info("post_login() called")

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
    postfieldsize = len(postfields)
    logger.info("postfieldsize: %s", postfieldsize)

    logger.debug("postfields: %s", postfields)

    c.setopt(c.WRITEFUNCTION, buffer.write)
    c.setopt(c.HEADERFUNCTION, header_function)

    c.setopt(c.BUFFERSIZE, 102400)
    c.setopt(c.URL, url)
    c.setopt(c.POSTFIELDS, postfields)
    c.setopt(c.POSTFIELDSIZE_LARGE, postfieldsize)
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
    logger.info("get_messages() called")

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
    postfieldsize = len(postfields)
    logger.info("postfieldsize: %s", postfieldsize)

    c.setopt(c.WRITEFUNCTION, buffer.write)
    c.setopt(c.HEADERFUNCTION, header_function)

    c.setopt(c.BUFFERSIZE, 102400)
    c.setopt(c.URL, url)
    c.setopt(c.POSTFIELDS, postfields)
    c.setopt(c.POSTFIELDSIZE_LARGE, postfieldsize)
    c.setopt(c.HTTPHEADER, header)
    c.setopt(c.USERAGENT, "curl/7.65.1")
    c.setopt(c.MAXREDIRS, 50)
    # c.setopt(c.HTTP_VERSION, pycurl.CURL_HTTP_VERSION_2TLS)
    c.setopt(c.ACCEPT_ENCODING, "")
    # c.setopt(c.HTTP09_ALLOWED, True)
    c.setopt(c.TCP_KEEPALIVE, 1)
    c.setopt(c.FOLLOWLOCATION, True)

    # print_headers(HEADERS)

    c.perform()
    logger.info("get_messages() HTTP response: %s", c.getinfo(c.HTTP_CODE))
    return buffer.getvalue()


def find_sessionid(headers):
    logger.info("find_sessionid() called")

    # if type(headers["set-cookie"]) == str:
    #     logger.info("type(HEADERS['set-cookie']) == str")
    #     sessionid = headers["set-cookie"].split(";")[0]
    # elif type(headers["set-cookie"]) == list:
    #     logger.info("type(HEADERS['set-cookie']) == list")
    #     sessionid = headers["set-cookie"][-1].split(";")[0]
    # else:
    #     logger.error("type(HEADERS['set-cookie']) == %s", type(headers["set-cookie"]))
    #     logger.error("cant get sessionid from headers")
    #     sessionid = ""

    # 'sessionid="XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
    r = ""
    try:
        if type(headers["set-cookie"]) == str:
            logger.info("type(HEADERS['set-cookie']) == str")
            r = re.search(r'sessionid="(.*?)"', HEADERS["set-cookie"]).group(1)
        elif type(headers["set-cookie"]) == list:
            logger.info("type(HEADERS['set-cookie']) == list")
            sessionid_match = [i for i in HEADERS["set-cookie"] if i.startswith("sessionid=")][-1]
            logger.info("find_sessionid(): sessionid_match: %s", sessionid_match)
            r = re.search(r'sessionid="(.*?)"', sessionid_match).group(1)
        else:
            logger.error("type(HEADERS['set-cookie']) == %s", type(headers["set-cookie"]))
            logger.error("cant get sessionid from headers")
            return r
    except AttributeError as ae:
        logger.error("find_sessionid(): error: %s", ae)
        return r
    except Exception as e:
        logger.error("find_sessionid(): error: %s", e, exc_info=True)
        return r

    return f'sessionid="{r}";'


def authenticate(login_url: str, username: str, password: str) -> AuthData:
    logger.info("authenticate() called")

    c = pycurl.Curl()

    resp = get_login(c, login_url)
    encoding = read_encoding(HEADERS, -1)
    parsed_html = BeautifulSoup(resp.decode(encoding), features="html.parser")
    token = parsed_html.find("input", attrs={"name": "token"}).get("value")
    logger.debug("token: %s", token)

    # print_headers(HEADERS)
    sessionid = find_sessionid(HEADERS)

    logger.debug("authenticate(): got sessionid: %s, from headers", sessionid)

    post_login(c, login_url, sessionid=sessionid,
               token=token, username=username, password=password)

    # print_headers(HEADERS)

    authcred = [i for i in HEADERS["set-cookie"] if i.startswith("authcred=")][-1]
    authtimeout = [i for i in HEADERS["set-cookie"] if i.startswith("authtimeout=")][-1]

    authtimeout_value = int(re.search(r'authtimeout="(.*?)"', authtimeout).group(1))

    # print_headers(HEADERS)
    logger.debug("authcred: %s", authcred)
    logger.debug("authtimeout: %s", authtimeout)
    logger.info("authtimeout_value: %s", authtimeout_value)

    c.close()
    return AuthData(timeout=authtimeout_value, authcred=authcred, sessionid=sessionid,
                    authtimeout=authtimeout)


def auth_timed_out(start_time, timeout):
    if timeout <= 0:
        logger.info(
            "auth_timed_out(): cannot calculate authentication timeout for timeout: %s", timeout)
        return False

    time_now = time.time()
    if (start_time + timeout) < time_now:
        logger.info(
            "auth_timed_out(): authentication timed out for start_time=%s, timeout=%s, time_now=%s",
            start_time, timeout, time_now)
        return True
    return False


def parse_chat_message_div(div) -> tuple:
    teamcolor = div.find("span", attrs={"class": "teamcolor"})
    teamnotice = div.find("span", attrs={"class": "teamnotice"})
    name = div.find("span", attrs={"class": "username"})
    msg = div.find("span", attrs={"class": "message"})
    return teamcolor, teamnotice, name, msg


def rs2_webadmin_worker(delayed_queue: mp.Queue, instant_queue: mp.Queue, log_queue: mp.Queue,
                        login_url: str, chat_url: str, username: str, password: str):
    mplogger.worker_configurer(log_queue)
    # noinspection PyShadowingNames
    logger = logging.getLogger(__file__ + ":" + __name__)

    logger.info("Starting rs2_webadmin_worker pid: %s", os.getpid())
    auth_data = authenticate(login_url, username, password)
    t = time.time()

    last_ping_time = time.time()

    while True:
        try:
            if auth_timed_out(t, auth_data.timeout):
                logger.info("rs2_webadmin_worker(): Re-authenticating")
                auth_data = authenticate(login_url, username, password)
                t = time.time()

            c = pycurl.Curl()

            latest_sessionid = find_sessionid(HEADERS)
            logger.info("rs2_webadmin_worker(): latest sessionid: %s", latest_sessionid)
            if latest_sessionid:
                auth_data.sessionid = latest_sessionid
            resp = get_messages(c, chat_url, auth_data.sessionid, auth_data.authcred, auth_data.timeout)
            encoding = read_encoding(HEADERS, -1)
            logger.info("rs2_webadmin_worker(): Encoding from headers: %s", encoding)
            parsed_html = BeautifulSoup(resp.decode(encoding), features="html.parser")
            logger.debug("rs2_webadmin_worker(): Raw HTML response: %s", parsed_html)
            chat_message_divs = parsed_html.find_all("div", attrs={"class": "chatmessage"})
            chat_notice_divs = parsed_html.find_all("div", attrs={"class": "chatnotice"})

            logger.info(
                "rs2_webadmin_worker(): Got %s 'class=chatmessage' divs from WebAdmin",
                len(chat_message_divs))
            logger.info(
                "rs2_webadmin_worker(): Got %s 'class=chatnotice' divs from WebAdmin",
                len(chat_notice_divs))

            for i, div in enumerate(chat_message_divs):
                tc, tn, name, msg = parse_chat_message_div(div)
                if msg.text.lower().lstrip().startswith(PING_ADMIN):
                    logger.info("rs2_webadmin_worker(): detected !admin ping")
                    instant_queue.put(div)
                    logger.info("rs2_webadmin_worker(): Enqueued div no. %s in instant queue", i)
                    ping_div = BeautifulSoup(f"""<div class="chatmessage">
                        <span class="teamcolor" style="background: #E54927;">&#160;</span>
                        <span class="username">__RADIOMAN__</span>:
                        <span class="message">__ADMIN SUMMONED INGAME__ by: {name}! {PING_HC} {PING_PO} '{msg.text}'</span>
                        </div>""", features="html.parser")
                    if time.time() > (last_ping_time + (60 * 15)):
                        instant_queue.put(ping_div)
                        last_ping_time = time.time()
                    logger.info("rs2_webadmin_worker(): Enqueued ping_div no. %s in instant queue", i)
                else:
                    delayed_queue.put((div, time.time(), DELAY_SECONDS))
                    logger.info("rs2_webadmin_worker(): Enqueued div no. %s in delayed queue", i)

            c.close()
            time.sleep(5)
        except pycurl.error as pe:
            logger.error("error: %s", pe)
            logger.error("retrying after: 50 ms")
            time.sleep(0.05)


def discord_webhook_worker(queue: mp.Queue, log_queue: mp.Queue, yd: YaaDiscord):
    mplogger.worker_configurer(log_queue)
    # noinspection PyShadowingNames
    logger = logging.getLogger(__file__ + ":" + __name__)

    logger.info("Starting discord_webhook_worker pid: %s", os.getpid())

    div = None
    while True:
        try:
            div = queue.get()
            logger.info("discord_webhook_worker(): dequeued div")

            teamcolor, teamnotice, name, msg = parse_chat_message_div(div)

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
            logger.info("discord_webhook_worker(): Posting message: %s", chat_msg)
            success = yd.post_chat_message(chat_msg)
            if not success:
                logger.error("discord_webhook_worker(): Failed to post message to webhook, retrying")
                success = yd.retry_all_messages()
                if not success:
                    logger.error("discord_webhook_worker(): Failed to retry")
                    # Refactor accessing yd.config here.
                    yd.post_chat_message(
                        f"Mr. {yd.config['CREATOR']}, I don't feel so good. (Error! Check logs!)")
            time.sleep(0.05)
        except Exception as e:
            logger.error("discord_webhook_worker(): error: %s", e, exc_info=True)
            if div:
                logger.error("discord_webhook_worker(): might lose message: %s", div.text)


# TODO: Refactor YaaDiscord into generic class.
# TODO: Refactor local YaaDiscord.
def radio_hanoi_worker(cfg: dict, log_queue: mp.Queue):
    mplogger.worker_configurer(log_queue)
    # noinspection PyShadowingNames
    logger = logging.getLogger(__file__ + ":" + __name__)

    logger.info("Starting radio_hanoi_worker: %s", os.getpid())

    yd = YaaDiscord(cfg)
    yd.config["WEBHOOK_URL"] = os.environ["DISCORD_WEBHOOK_URL_RADIO_HANOI"]
    time.sleep(5 * 60)
    while True:
        quote = np.random.choice(HH_QUOTES)
        logger.info("radio_hanoi_worker(): posting chat message: %s", quote)
        yd.post_chat_message(quote)
        logger.info("radio_hanoi_worker(): sleeping for %S seconds", str(60 * 60))
        time.sleep(60 * 60)


def sleep_and_put(div, start_time, delay, out_queue):
    duration = delay - (time.time() - start_time)
    logger.info("sleep_and_put(): sleeping for %s seconds", duration)
    time.sleep(duration)
    logger.info("sleep_and_put(): putting item into out_queue")
    out_queue.put(div)
    return True


def queue_worker(delayed_queue: mp.Queue, out_queue: mp.Queue, log_queue: mp.Queue):
    mplogger.worker_configurer(log_queue)
    # noinspection PyShadowingNames
    logger = logging.getLogger(__file__ + ":" + __name__)

    logger.info("Starting queue_worker pid: %s", os.getpid())

    executor = ThreadPoolExecutor(max_workers=25)
    futures = []
    done_futures = []
    while True:
        div, start_time, delay = delayed_queue.get()
        logger.info("queue_worker(): got div with start_time: %s, delay: %s",
                    start_time, delay)
        futures.append(executor.submit(sleep_and_put, div, start_time, delay, out_queue))
        logger.info("len(futures): %s", len(futures))
        for f in futures:
            if f.done():
                result = f.result()
                logger.info("future done: %s, result: %s", f, result)
                if not result:
                    logger.error("future was not completed succesfully")
                done_futures.append(f)

        futures = [f for f in futures if f not in done_futures]
        logger.info("cleaned futures list, new len(futures): %s", len(futures))
        done_futures = []


# TODO:
#  10 minute delay for posting to webhook.
#  Store messages in PostgreSQL DB (in Heroku)?
def main():
    args = parse_args()
    cfg = defaultdict(dict)

    lqueue = mp.Queue()
    listener = mp.Process(target=mplogger.listener_process,
                          args=(lqueue, mplogger.listener_configurer))
    listener.start()

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
        cfg["DISCORD"]["CREATOR"] = os.environ["CREATOR"]
        cfg["MISC"]["DATABASE_URL"] = os.environ["DATABASE_URL"]
    else:
        cfg = read_config(args.config)

    try:
        cfg["RS2_WEBADMIN"]["ADDRESS"] = validate_address(cfg["RS2_WEBADMIN"]["ADDRESS"])
    except ValueError as ve:
        logger.error("Error: %s", ve, exc_info=True)
        sys.exit(1)

    login_url = parse.urljoin(cfg["RS2_WEBADMIN"]["ADDRESS"], cfg["RS2_WEBADMIN"]["LOGIN_PATH"])
    chat_data_url = parse.urljoin(cfg["RS2_WEBADMIN"]["ADDRESS"], cfg["RS2_WEBADMIN"]["CHAT_PATH"])

    username = cfg["RS2_WEBADMIN"]["USERNAME"]
    password = cfg["RS2_WEBADMIN"]["PASSWORD"]

    yd = YaaDiscord(cfg["DISCORD"])

    delayed_queue = mp.Queue()
    out_queue = mp.Queue()
    processes = [
        mp.Process(target=rs2_webadmin_worker, name="rs2_webadmin_worker",
                   args=(delayed_queue, out_queue, lqueue, login_url, chat_data_url, username, password)),
        mp.Process(target=discord_webhook_worker, name="discord_webhook_worker",
                   args=(out_queue, lqueue, yd)),
        mp.Process(target=queue_worker, name="queue_worker",
                   args=(delayed_queue, out_queue, lqueue)),
        mp.Process(target=radio_hanoi_worker, name="radio_hanoi_worker",
                   args=(cfg["DISCORD"], lqueue)),
    ]

    for p in processes:
        p.start()
        logger.info("Started Process: %s", p)

    for p in processes:
        p.join()
        logger.info("Joined Process: %s", p)

    lqueue.put_nowait(None)
    listener.join()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
