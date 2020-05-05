#!/usr/bin/env python3
#
# Stylechecker
#
# Example usage of this addon (scan a sourcefile main.cpp)
# cppcheck --dump main.cpp
# python style.py --rules-files=<path-to-rules-file> main.cpp.dump
#
# Limitations: This addon is released as open source. Rule texts can't be freely
# distributed. https://www.misra.org.uk/forum/viewtopic.php?f=56&t=1189
#

from __future__ import print_function

import cppcheckdata
import itertools
import sys
import re
import os
import argparse
import codecs
import string
import json


class StyleChecker:

    class Checker:

        def __init__(self, rule):
            self.err_id = rule["errId"]
            self.err_msg = rule["errMsg"]
            self.severity = rule["severity"]
        
        def reportError_fromToken(self, token, info = None):
            if info:
                err_msg = self.err_msg + " " + str(info)
            else:
                err_msg = self.err_msg
            
            cppcheckdata.reportError(token, "style", err_msg, 'style', self.err_id, self.severity)
        
        def reportError(self, file, line, column, info = None):
            token = cppcheckdata.Token
            token.file = file
            token.linenr = line
            token.column = column
            self.reportError_fromToken(token, info)

    class LineBlacklist(Checker):

        def __init__(self, rule):
            super().__init__(rule)
            self.parser = re.compile(rule["args"]["regex"])

        def run(self, first_run, cfg, raw_tokens, file_name, file_content):
            if first_run:
                line_nr = 0
                for line in file_content:
                    line_nr = line_nr + 1
                    if self.parser.findall(line):
                        super().reportError(file_name, line_nr, 0, self.parser.findall(line))

    def __init__(self, args):
        self.checker_list = []

        with open(args.rules_file) as rules_file:
            data = json.load(rules_file)
            for rule in data["rules"]:
                if rule["tool"] == "lineBlacklist":
                    self.checker_list.append(self.LineBlacklist(rule))
                #else :
                    #print("Warning: Unknown tool: {}".format(rule["tool"]))

    def run(self, dumpfile):
        data = cppcheckdata.parsedump(dumpfile)
        sourceFileName = data.rawTokens[0].file

        with open(sourceFileName, 'r') as file:
            sourceFile = file.readlines();

        first_run = True

        for cfg in data.configurations:

            for checker in self.checker_list:
                checker.run(first_run, cfg, data.rawTokens, sourceFileName, sourceFile)

            first_run = False

def get_args():
    """Generates list of command-line arguments acceptable by misra.py script."""
    parser = cppcheckdata.ArgumentParser()
    parser.add_argument("--rules-file", type=str, help="json file to define the stylechecker rules")
    parser.add_argument("-verify", help=argparse.SUPPRESS, action="store_true")
    return parser.parse_args()


def main():
    args = get_args()

    if not args.rules_file:
        print('Fatal error: no rule file set')
        sys.exit(1)

    stylechecker = StyleChecker(args)

    for item in args.dumpfile:
        stylechecker.run(item)

if __name__ == '__main__':
    main()
