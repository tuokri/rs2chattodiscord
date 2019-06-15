import json

from urllib import request


class YaaDiscord(object):
    def __init__(self, config: dict):
        self.config = config

    def post_webhook(self, data_dict):
        data = json.dumps(data_dict).encode()
        req = request.Request(self.config["WEBHOOK_URL"], data=data, headers={
            "User-Agent": self.config["USER_AGENT"],
            "Content-Type": "application/json",
        })
        with request.urlopen(req) as resp:
            return resp

    def post_chat_message(self, msg):
        d = {
            "content": str(msg),
            "username": self.config["USERNAME"],
            "avatar_url": self.config["AVATAR_URL"],
        }
        return self.post_webhook(d)
