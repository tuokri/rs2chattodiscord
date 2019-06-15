import logging
import os
import sys
from urllib import parse

from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import Select
from selenium.webdriver.support.ui import WebDriverWait

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)


class RS2WebAdmin(object):
    def __init__(self, config: dict):
        self.config = config

        # # TODO: Refactor proxy.
        # proxy = os.environ.get("http_proxy")
        # if proxy:
        #     print(f"Using proxy: {proxy}")
        #     webdriver.DesiredCapabilities.FIREFOX["proxy"] = {
        #         "httpProxy": proxy,
        #         "ftpProxy": proxy,
        #         "sslProxy": proxy,
        #         "proxyType": "MANUAL",
        #     }

        chromedriver_path = "/app/.chromedriver/bin/chromedriver"

        chrome_bin = os.environ.get('GOOGLE_CHROME_BIN', "chromedriver")
        options = webdriver.ChromeOptions()
        options.binary_location = chrome_bin
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument('headless')
        options.add_argument('window-size=1200x600')
        self.driver = webdriver.Chrome(executable_path=chromedriver_path, chrome_options=options)

        self.login_url = parse.urljoin(self.config["ADDRESS"], self.config["LOGIN_PATH"])
        self.chat_url = parse.urljoin(self.config["ADDRESS"], self.config["CHAT_PATH"])

    def __del__(self):
        self.quit()

    def quit(self):
        self.driver.close()
        self.driver.quit()

    def login(self):
        logger.info("Logging in")
        self.driver.get(self.login_url)
        if "Login" not in self.driver.title:
            raise NoSuchElementException("no 'Login' in driver.title")

        try:
            uname = WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.ID, "username"))
            )
        except TimeoutException as te:
            logger.error("get_chat_messages(): error %s", te)
            raise te

        uname.clear()
        uname.send_keys(self.config["USERNAME"])

        try:
            passw = WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.ID, "password"))
            )
        except TimeoutException as te:
            logger.error("get_chat_messages(): error %s", te)
            raise te

        passw.clear()
        passw.send_keys(self.config["PASSWORD"])

        try:
            remember = Select(WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "select"))
            ))
        except TimeoutException as te:
            logger.error("get_chat_messages(): error %s", te)
            raise te

        remember.select_by_value("2678400")

        try:
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "button"))
            ).click()
        except TimeoutException as te:
            logger.error("get_chat_messages(): error %s", te)
            raise te

    def navigate_to_chat(self):
        logger.info("Navigating to chat: %s", self.chat_url)
        self.driver.get(self.chat_url)

    def get_chat_messages(self) -> list:
        # try:
        #     chatlog = WebDriverWait(self.driver, 10).until(
        #         EC.presence_of_element_located((By.ID, "chatlog"))
        #     )
        # except NoSuchElementException as nse:
        #     logger.error("get_chat_messages(): error %s", nse)
        #     return []
        # except TimeoutException as te:
        #     logger.error("get_chat_messages(): error %s", te)
        #     return []

        try:
            chat_messages = WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.CLASS_NAME, "chatmessage"))
            )
        except TimeoutException as te:
            logger.error("get_chat_messages(): error %s", te)
            return []

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
            logger.error(f"error {nse}")
            return []

        chat_notices = chatlog.find_elements_by_class_name("chatnotice")
        return [{
            "noticesymbol:": cn.find_element_by_class_name("noticesymbol").text,
            "username": cn.find_element_by_class_name("username").text,
            "message": cn.find_element_by_class_name("message").text,
        } for cn in chat_notices]


def element_exists_by_class_name(parent, classname) -> bool:
    try:
        parent.find_element_by_class_name(classname)
    except NoSuchElementException:
        return False
    return True
