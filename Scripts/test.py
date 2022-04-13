import requests
from bs4 import BeautifulSoup
import datetime
import os
import pathlib

# relate to network operation
os.environ["http_proxy"] = "http://127.0.0.1:60377"
os.environ["https_proxy"] = "http://127.0.0.1:60377"


def list_files(repo_url):
    directory = pathlib.Path(repo_url)
    for file_name in os.listdir(directory):
        path = os.path.join(directory, file_name)
        if os.path.isfile(path):
            print(file_name)
        elif os.path.isdir(path):
            list_files(path)


if __name__ == "__main__":
    list_files("https://github.com/3norns/oss_sec_estimator")
