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

import sys
import re
import os
import argparse
import json
import cppcheckdata


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
                    for match in re.finditer(self.parser, line):
                        super().reportError(file_name, line_nr, match.span()[0] + 1, match.group())

    class LineLength(Checker):

        def __init__(self, rule):
            super().__init__(rule)
            self.length = rule["args"]["length"]

        def run(self, first_run, cfg, raw_tokens, file_name, file_content):
            if first_run:
                line_nr = 0
                for line in file_content:
                    line_nr = line_nr + 1
                    if len(line) - 1 > self.length:
                        super().reportError(file_name, line_nr, len(line) - 1, "{} > {}".format(len(line) - 1, self.length))

    class NameChecker(Checker):
        types = ["file", "function", "variable", "define", "enum"]
        scopes = ["global", "local"]

        def __init__(self, rule):
            super().__init__(rule)
            self.parser = re.compile(rule["args"]["regex"])
            self.type = rule["args"]["type"]
            self.scope = rule["args"]["scope"]
            if not self.type in self.types:
                print("invalid name type: {}".format(self.type))
            if not self.scope in self.scopes:
                print("invalid name scope: {}".format(self.scope))

        def run(self, first_run, cfg, raw_tokens, file_name, file_content):
            if self.type == "file":
                if first_run:
                    if not self.parser.match(os.path.basename(file_name)):
                        super().reportError(file_name, 0, 0, "")

            elif self.type == "function":
                for fct in cfg.functions:
                    if (self.scope == "local" and fct.isStatic) or (self.scope == "global" and not fct.isStatic):
                        if not self.parser.match(fct.name):
                            super().reportError_fromToken(fct.tokenDef, fct.name)

            elif self.type == "variable":
                for var in cfg.variables:
                    if (self.scope == "local" and var.isStatic) or (self.scope == "global" and var.isGlobal):
                        if not self.parser.match(var.nameToken.str):
                            super().reportError_fromToken(var.tokenDef, var.nameToken.str)

            elif self.type == "define":
                for directive in cfg.directives:
                    res = re.search(r'#define ([^ ]+)', directive.str)
                    if res:
                        extension = directive.file.split(".")[-1]
                        if (self.scope == "local" and extension == "c") or (self.scope == "global" and extension == "h"):
                            if not self.parser.match(res.group(1)):
                                super().reportError_fromToken(directive, res.group(1))

            elif self.type == "enum":
                for scope in cfg.scopes:
                    if scope.type == "Enum":
                        extension = scope.bodyStart.file.split(".")[-1]
                        if (self.scope == "local" and extension == "c") or (self.scope == "global" and extension == "h"):
                            token = scope.bodyStart

                            while token and token != scope.bodyEnd:
                                if token.isName:
                                    if not self.parser.match(token.str):
                                        super().reportError_fromToken(token, token.str)
                                token = token.next

    def __init__(self, args):
        self.checker_list = []

        with open(args.rules_file) as rules_file:
            data = json.load(rules_file)
            for rule in data["rules"]:
                if rule["tool"] == "lineBlacklist":
                    self.checker_list.append(self.LineBlacklist(rule))
                elif rule["tool"] == "lineLength":
                    self.checker_list.append(self.LineLength(rule))
                elif rule["tool"] == "nameChecker":
                    self.checker_list.append(self.NameChecker(rule))
                #else :
                    #print("Warning: Unknown tool: {}".format(rule["tool"]))

    def run(self, dumpfile):
        data = cppcheckdata.parsedump(dumpfile)
        sourceFileName = data.rawTokens[0].file

        with open(sourceFileName, 'r') as file:
            sourceFile = file.readlines()

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
