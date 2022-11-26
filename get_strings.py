import re
import subprocess
from urllib.parse import urlparse

def is_ip(list_of_strings):
    ipv4_pattern = re.compile(
        r'.*((([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])[ (\[]?(\.|dot)[ )\]]?){3}([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])).*')
    f = filter(ipv4_pattern.match, list_of_strings)
    lst=[]
    pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    for line in f:
        ip_addr = pattern.search(line)[0]
        if ip_addr not in lst:
            lst.append(ip_addr)
    return list(lst)

def is_website(list_of_strings):
    list_of_web_addresses = []
    for strng in list_of_strings:
        pattern = re.compile(r'\b((?:https?://)?(?:(?:www\.)?(?:[\da-z\.-]+)\.(?:[a-z]{2,6})|(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])))(?::[0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])?(?:/[\w\.-]*)*/?)\b')
        website_string = pattern.search(strng)
        try:
            netloc = urlparse(website_string[0].split()[0]).netloc
            if netloc and "." in netloc and not netloc.startswith(".") and not netloc.endswith("."):
                list_of_web_addresses.append(netloc)
        except:
            pass

    list_of_web_addresses = set(list_of_web_addresses)

    return list_of_web_addresses

def is_email(list_of_strings):
    email_pattern = re.compile(r'(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)')

    filtered_email = filter(email_pattern.match, list_of_strings)
    all_email = []
    for emal in list(filtered_email):
        if validate_email(emal):
            all_email.append(emal)
    return all_email


def ascii_strings(filename, enable):
    if not enable:
        strings_list = ""
    else:
        output = subprocess.check_output(["strings", "-a", filename])
        strings_list = list(output.decode("utf-8").split('\n'))
    return strings_list


def unicode_strings(filename, enalble):
    if not enalble:
        strings_list = ""
    else:
        output = subprocess.check_output(["strings", "-a", "-el", filename])
        strings_list = list(output.decode("utf-8").split('\n'))
    return 

class get_strings:
    def __init__(self, filename):
        self.chars = b"A-Za-z0-9!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ "
        self.shortest_run = 4
        self.filename = filename
        self.regexp = '[{}]{{{},}}'.format(self.chars.decode(), self.shortest_run).encode()
        self.pattern = re.compile(self.regexp)

        with open(self.filename, 'rb') as f:
            list_bytes = self.process(f)
            strings = []
            for n in list_bytes:
                strings.append(n.decode())
                
        self.result = (is_ip(strings), is_email(strings), is_website(strings))

    def process(self, filename):
        data = filename.read()
        return self.pattern.findall(data)

    def get_strings(self) -> tuple:
        return self.result