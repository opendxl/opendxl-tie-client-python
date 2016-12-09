# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2016 McAfee Inc. - All Rights Reserved.
################################################################################
from __future__ import absolute_import

from .client import TieClient
from .constants import *
from .callbacks import *

__version__ = "0.1.0"


def get_version():
    """
    Returns the version of the McAfee Threat Intelligence Exchange (TIE) DXL Client library

    :return: The version of the McAfee Threat Intelligence Exchange (TIE) DXL Client library
    """
    return __version__
