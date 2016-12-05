# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2016 McAfee Inc. - All Rights Reserved.
################################################################################

import os
import subprocess
from distutils.dir_util import copy_tree, remove_tree
from distutils.file_util import copy_file, move_file
from distutils.core import run_setup
from distutils.archive_util import make_archive

print("Starting dist.\n")

VERSION = __import__('dxltieclient').get_version()
RELEASE_NAME = "dxltieclient-python-sdk-" + str(VERSION)

DIST_PY_FILE_LOCATION = os.path.dirname(os.path.realpath(__file__))
DIST_DIRECTORY = os.path.join(DIST_PY_FILE_LOCATION, "dist")
DIST_DOCTMP_DIR = os.path.join(DIST_DIRECTORY, "doctmp")
SETUP_PY = os.path.join(DIST_PY_FILE_LOCATION, "setup.py")
DIST_LIB_DIRECTORY = os.path.join(DIST_DIRECTORY, "lib")
DIST_RELEASE_DIR = os.path.join(DIST_DIRECTORY, RELEASE_NAME)

# Remove the dist directory if it exists
if os.path.exists(DIST_DIRECTORY):
    print("\nRemoving dist directory: " + DIST_DIRECTORY + "\n")
    remove_tree(DIST_DIRECTORY, verbose=1)

# Make the dist directory
print("\nMaking dist directory: " + DIST_DIRECTORY + "\n")
os.makedirs(DIST_DIRECTORY)

# Call Sphinx to create API doc
print("\nCalling sphinx-apidoc\n")
subprocess.check_call(["sphinx-apidoc",
                       "--force",
                       "--separate",
                       "--no-toc",
                       "--output-dir=" + DIST_DOCTMP_DIR,
                       os.path.join(DIST_PY_FILE_LOCATION, "dxltieclient")])

# Copy files to dist/doctmp
print("\nCopying conf.py and sdk directory\n")
copy_file(os.path.join(DIST_PY_FILE_LOCATION, "doc", "conf.py"), os.path.join(DIST_DOCTMP_DIR, "conf.py"))
copy_tree(os.path.join(DIST_PY_FILE_LOCATION, "doc", "sdk"), DIST_DOCTMP_DIR)

# Call Sphinx build
print("\nCalling sphinx-build\n")
subprocess.check_call(["sphinx-build", "-b", "html", DIST_DOCTMP_DIR, os.path.join(DIST_DIRECTORY, "doc")])

# Move README.html to root of dist directory
print("\nMoving README.html\n")
move_file(os.path.join(DIST_DOCTMP_DIR, "README.html"), DIST_DIRECTORY)

# Remove doctmp directory
print("\nDeleting doctmp directory\n")
remove_tree(DIST_DOCTMP_DIR)

# Call setup.py
print("\nRunning setup.py sdist\n")
run_setup(SETUP_PY,
          ["sdist",
           "--format",
           "zip",
           "--dist-dir",
           DIST_LIB_DIRECTORY])

print("\nRunning setup.py bdist_egg\n")
run_setup(SETUP_PY,
          ["bdist_egg",
           "--dist-dir",
           DIST_LIB_DIRECTORY])

print("\nRunning setup.py bdist_wheel\n")
run_setup(SETUP_PY,
          ["bdist_wheel",
           "--dist-dir",
           DIST_LIB_DIRECTORY,
           "--python-tag",
           "py2.7"])

# cp -rf sample dist
print("\nCopying sample in to dist directory\n")
copy_tree(os.path.join(DIST_PY_FILE_LOCATION, "sample"), os.path.join(DIST_DIRECTORY, "sample"))

# Copy everything in to release dir
print("\nCopying dist to " + DIST_RELEASE_DIR + "\n")
copy_tree(DIST_DIRECTORY, DIST_RELEASE_DIR)

# rm -rf build
print("\nRemoving build directory\n")
remove_tree(os.path.join(DIST_PY_FILE_LOCATION, "build"))

# rm -rf dxltieclient.egg-info
print("\nRemoving dxltieclient.egg-info\n")
remove_tree(os.path.join(DIST_PY_FILE_LOCATION, "dxltieclient.egg-info"))

# Make dist zip
print("\nMaking dist zip\n")
make_archive(DIST_RELEASE_DIR, "zip", DIST_DIRECTORY, RELEASE_NAME)

print("\nRemoving " + DIST_RELEASE_DIR + "\n")
remove_tree(DIST_RELEASE_DIR)

print("\nFinished")