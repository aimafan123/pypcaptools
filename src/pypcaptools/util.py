import pickle
from typing import TypedDict


class DBConfig(TypedDict):
    host: str
    port: int
    user: str
    password: str
    database: str


def serialization(src_data):
    return pickle.dumps(src_data)


def deserialization(src_data):
    return pickle.loads(src_data)
