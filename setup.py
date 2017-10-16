import os

from setuptools import setup
import distutils.command.sdist

import setuptools.command.sdist

# Patch setuptools' sdist behaviour with distutils' sdist behaviour
setuptools.command.sdist.sdist.run = distutils.command.sdist.sdist.run

version_info = {}
cwd=os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(cwd, "dxltieclient", "_version.py")) as f:
    exec(f.read(), version_info)

dist = setup(
    # Application name:
    name="dxltieclient",

    # Version number:
    version=version_info["__version__"],

    # Requirements
    install_requires=[
        "dxlbootstrap>=0.1.3",
        "dxlclient"
    ],

    # Application author details:
    author="McAfee, Inc.",

    # License
    license="Apache License 2.0",

    keywords=['opendxl', 'dxl', 'mcafee', 'client', 'tie'],

    # Packages
    packages=[
        "dxltieclient",
        "dxltieclient._config",
        "dxltieclient._config.sample"
    ],

    package_data={
        "dxltieclient._config.sample" : ['*']},

    # Details
    url="http://www.mcafee.com/",

    description="McAfee Threat Intelligence Exchange (TIE) DXL client library",

    long_description=open('README').read(),

    classifiers=[
        "Development Status :: 4 - Beta",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2.7",
    ],
)
