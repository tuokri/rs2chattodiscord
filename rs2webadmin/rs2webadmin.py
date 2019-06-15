import os
from urllib import parse

from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.support.ui import Select
from selenium.webdriver.firefox.options import Options


class RS2WebAdmin(object):
    def __init__(self, config: dict):
        self.config = config

        opt = Options()
        opt.headless = True
        webdriver.DesiredCapabilities().FIREFOX["marionette"] = False

        # TODO: Refactor proxy.
        proxy = os.environ.get("http_proxy")
        if proxy:
            print(f"Using proxy: {proxy}")
            webdriver.DesiredCapabilities.FIREFOX["proxy"] = {
                "httpProxy": proxy,
                "ftpProxy": proxy,
                "sslProxy": proxy,
                "proxyType": "MANUAL",
            }

        self.driver = webdriver.Firefox(options=opt)
        self.login_url = parse.urljoin(self.config["ADDRESS"], self.config["LOGIN_PATH"])
        self.chat_url = parse.urljoin(self.config["ADDRESS"], self.config["CHAT_PATH"])

    def __del__(self):
        self.quit()

    def quit(self):
        self.driver.close()
        self.driver.quit()

    def login(self):
        self.driver.get(self.login_url)
        if "Login" not in self.driver.title:
            raise NoSuchElementException("no 'Login' in driver.title")

        uname = self.driver.find_element_by_id("username")
        uname.clear()
        uname.send_keys(self.config["USERNAME"])

        passw = self.driver.find_element_by_id("password")
        passw.clear()
        passw.send_keys(self.config["PASSWORD"])

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


def element_exists_by_class_name(parent, classname) -> bool:
    try:
        parent.find_element_by_class_name(classname)
    except NoSuchElementException:
        return False
    return True
