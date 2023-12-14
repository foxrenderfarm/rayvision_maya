#! /usr/bin/env python
#coding=utf-8
import sys
import os

script_version = "py" + "".join([str(i) for i in sys.version_info[:2]])
script_path = os.path.dirname(__file__)


sys.path.insert(0, script_path)

print("python executable is: " + sys.executable)
print("python version is: " + sys.version)
print("import Analyze path: " + script_path)
sys.stdout.flush()
print("from " + script_version + ".Analyze import *")
exec("from " + script_version + ".Analyze import *")
