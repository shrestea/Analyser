import hashlib
import numbers
import os
import time
import binascii
import array
import magic
import math
import pefile
from subprocess import Popen, PIPE, STDOUT
from elftools.elf.elffile import ELFFile

class ELFScanner:
    def __init__(self, filename):
        self.filename = filename
        with open(self.filename, 'rb') as f:
            self.elffile = ELFFile(f)

    def file_info(self):
        info = []
        with open(self.filename, 'rb') as f:
            file = f.read()
            info.append("File: {}".format(self.filename))
            info.append("Size: {} bytes".format(os.path.getsize(self.filename)))
            info.append("Type: {}".format(magic.from_file(self.filename, mime=True)))
            info.append("MD5: {}".format(hashlib.md5(file).hexdigest()))
            info.append("SHA1: {}".format(hashlib.sha1(file).hexdigest()))

        return info

    def dependencies(self):
        try:
            output = Popen(['ldd', self.filename],
                           stdout=PIPE, stdin=PIPE, stderr=STDOUT, bufsize=1)
            return output.stdout
        except:
            pass

    def elf_header(self):
        try:
            output = Popen(['readelf', '-h', self.filename],
                           stdout=PIPE, stdin=PIPE, stderr=STDOUT, bufsize=1)
            return output.stdout
        except:
            pass

    def program_header(self):
        try:
            output = Popen(['readelf', '-l', self.filename],
                           stdout=PIPE, stdin=PIPE, stderr=STDOUT, bufsize=1)
            return output.stdout
        except:
            pass

    def section_header(self):
        try:
            output = Popen(['readelf', '-S', self.filename],
                           stdout=PIPE, stdin=PIPE, stderr=STDOUT, bufsize=1)
            return output.stdout
        except:
            pass

    def symbols(self):
        try:
            output = Popen(['readelf', '-s', self.filename],
                           stdout=PIPE, stdin=PIPE, stderr=STDOUT, bufsize=1)
            return output.stdout
        except:
            pass

    def checksec(self):
        result = {}
        result["RELRO"] = 0
        result["CANARY"] = 0
        result["NX"] = 1
        result["PIE"] = 0
        result["FORTIFY"] = 0
        try:
            output =  Popen(['readelf', '-W', '-a', self.filename],
                            stdout=PIPE, stdin=PIPE, stderr=STDOUT, bufsize=1)

            for line in output.stdout:
                line = line.decode('utf-8', 'ignore').replace("\n", "")
                if "GNU_RELRO" in line:
                    result["RELRO"] |= 2
                if "BIND_NOW" in line:
                    result["RELRO"] |= 1
                if "__stack_chk_fail" in line:
                    result["CANARY"] = 1
                if "GNU_STACK" in line and "RWE" in line:
                    result["NX"] = 0
                if "Type:" in line and "DYN (" in line:
                    result["PIE"] = 4
                if "(DEBUG)" in line and result["PIE"] == 4:
                    result["PIE"] = 1
                if "_chk@" in line:
                    result["FORTIFY"] = 1

            if result["RELRO"] == 1:
                result["RELRO"] = 0
            return result
        except:
            pass

