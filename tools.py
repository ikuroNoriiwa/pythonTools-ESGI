#!/usr/bin/python3

from sys import exit, stderr


def error(msg, errors):
    if len(errors)!=0:
        print("\033[41m{}\033[0m".format(msg), file=stderr)
        for err in errors:
            print("\033[91m{}\033[0m".format(err), file=stderr)
        exit(1)



class Output():
    def __init__(self, file=False, verbose=True):
        if file:
            self._file = True
            self._fp = open(file, "a")
        else:
            self._file = False
        self._verbose = verbose
    
    def out(self, info, to_write=False):
        if self._verbose:
            print(info)
        if self._file and to_write:
            self._fp.write(str(info)+'\n')

    def __del__(self):
        if self._file:
            self._fp.close()