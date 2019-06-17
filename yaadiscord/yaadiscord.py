import json
import logging
import time
from urllib import request
from urllib.error import HTTPError
from urllib.error import URLError


class YaaDiscord(object):
    def __init__(self, config: dict):
        self.config = config
        self.retries = {}
        self._next_id = 0

    def next_id(self) -> int:
        r = self._next_id
        self._next_id += 1
        return r

    def send_request(self, data: dict):
        data = json.dumps(data).encode()
        req = request.Request(self.config["WEBHOOK_URL"], data=data, headers={
            "User-Agent": self.config["USER_AGENT"],
            "Content-Type": "application/json",
        })
        with request.urlopen(req) as resp:
            logging.info("send_request(): response: %s", resp.status)

    def retry_all_messages(self) -> bool:
        successful_retries = []

        for key, value in self.retries:
            logging.info("retry_all_messages(): retrying id: %s", key)
            retry_timeout_millis = value[0]
            time_of_request = value[1]
            data = value[2]
            if (time_of_request + retry_timeout_millis / 1000) > time.time():
                if self.post_webhook(data):
                    logging.info("retry_all_messages(): successfully retried id: %s", key)
                    successful_retries.append(key)

        for i in successful_retries:
            self.retries.pop(i)
            logging.info("retry_all_messages(): popped id: %s from retry dict", i)

        return bool(self.retries)

    def post_webhook(self, data_dict: dict) -> bool:
        try:
            self.send_request(data_dict)
            return True
        except HTTPError as he:
            logging.error("post_webhook(): error: %s", he.code)
            if he.code == 429:
                logging.error("post_webhook(): error: %s (rate limited)")
                body = he.read().decode()
                json_body = json.loads(body)
                try:
                    retry_after = json_body["retry_after"]
                except KeyError as ke:
                    logging.error("post_webhook(): error: %s", ke)
                    retry_after = 0
                i = self.next_id()
                # Format: {id: (retry_timeout_ms, time_of_request, data)}
                self.retries[i] = (retry_after, time.time(), data_dict)
                logging.info("id: %s, retrying after: %s ms", i, retry_after)
                return False
        except URLError as ue:
            logging.error("post_webhook(): error: %s", ue.reason)
            return False

    def post_chat_message(self, msg: str) -> bool:
        d = {
            "content": str(msg),
            # "username": self.config["USERNAME"],
            # "avatar_url": self.config["AVATAR_URL"],
        }
        return self.post_webhook(d)
