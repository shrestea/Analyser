import os
import urllib.request
import zipfile
from _socket import timeout
from http.client import IncompleteRead
from io import BytesIO
from urllib.parse import urlparse
import _socket
import json

_socket.setdefaulttimeout(10)  # set timeout

def get_domains():
    list_of_domains = []
    while True:
        try:
            list_from_urlhaus = urllib.request.urlopen(
                "https://urlhaus.abuse.ch/downloads/text/").read().decode(
                errors='replace').strip().split("\n")
            list_from_github = urllib.request.urlopen(
                "https://raw.githubusercontent.com/austinheap/sophos-xg-block-lists/master/malware-domain-list.txt").read().decode(
                errors='replace').strip().split("\n")
        except IncompleteRead:
            continue
        except timeout:
            list_from_urlhaus = ""
            list_from_github = ""
            break
        break

    list_of_mal_domains = list_from_urlhaus + list_from_github
    final_list_of_mal_domains = []
    for dom in list_of_mal_domains:
        if dom and not dom.startswith("#"):
            final_list_of_mal_domains.append(dom.strip())
            f = open("domain.txt", "w")
    f.write(json.dumps(final_list_of_mal_domains, indent = 2))

    return final_list_of_mal_domains