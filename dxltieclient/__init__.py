# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2017 McAfee LLC - All Rights Reserved.
################################################################################
from __future__ import absolute_import

from ._version import __version__
from .client import TieClient
from .constants import *
from .callbacks import *


def get_version():
    """
    Returns the version of the McAfee Threat Intelligence Exchange (TIE) DXL Client library

    :return: The version of the McAfee Threat Intelligence Exchange (TIE) DXL Client library
    """
    return __version__
