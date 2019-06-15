NORTH_EMOJI = ":red_circle:"
SOUTH_EMOJI = ":large_blue_circle:"


class ChatEntry(object):
    def __init__(self, msg_dict: dict):
        self.msg_dict = msg_dict
        self._sent = False

    def __hash__(self):
        print("msg=", self.msg_dict["message"], "hash=", hash(frozenset(self.msg_dict.items())))
        return hash(frozenset(self.msg_dict.items()))

    def __eq__(self, other):
        return hash(self) == hash(other)

    def __getitem__(self, item):
        return self.msg_dict[item]

    def __contains__(self, item):
        return item in self.msg_dict

    def __str__(self):
        return self.msg_dict.__str__()

    def __repr__(self):
        return self.msg_dict.__repr__()

    @property
    def sent(self) -> bool:
        return self._sent

    @sent.setter
    def sent(self, sent: bool):
        self._sent = sent


class ChatLog(object):
    def __init__(self):
        self.log = set()

    def __iter__(self):
        return self.log.__iter__()

    def __len__(self):
        return self.log.__len__()

    def add(self, chat_entry: ChatEntry):
        self.log.add(chat_entry)

    def remove(self, item):
        self.log.remove(item)


def to_pretty_str(chat_entry: ChatEntry) -> str:
    ps = "({team}) {name}: {message}"
    if "teamnotice" in chat_entry:
        if "rgb(229, 73, 39)" in chat_entry["teamcolor:"]:
            team = f"TEAM {NORTH_EMOJI}"
        else:
            team = f"TEAM {SOUTH_EMOJI}"
    else:
        team = "ALL"

    return ps.format(team=team, name=chat_entry["username"], message=chat_entry["message"])
