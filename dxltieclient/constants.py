# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2017 McAfee LLC - All Rights Reserved.
################################################################################

from __future__ import absolute_import
import base64
import sys
import time
import struct

# xrange was replaced with range in Python 3. Continue using xrange instead of
# range in Python 2 because it provides better performance.
if sys.version_info[0] > 2:
    RANGE = range
else:
    RANGE = xrange # pylint: disable=undefined-variable


class EpochMixin(object):
    """
    Mixin (helper) class that provides utility methods for parsing properties/attributes that
    contain Epoch times.
    """
    @staticmethod
    def to_localtime(epoch_time):
        """
        Converts the specified Epoch time to local time.

        **Example Usage**

            .. code-block:: python

                ent_rep = reputations_dict[FileProvider.ENTERPRISE]
                ent_rep_attribs = ent_rep[ReputationProp.ATTRIBUTES]
                local_time = FileEnterpriseAttrib.to_localtime(
                    ent_rep_attribs[FileEnterpriseAttrib.FIRST_CONTACT])

        :param epoch_time: Time as an Epoch time
        :return: Time in local time
        """
        return time.localtime(float(epoch_time))

    @staticmethod
    def to_localtime_string(epoch_time, format="%Y-%m-%d %H:%M:%S"): # pylint: disable=redefined-builtin
        """
        Converts the specified Epoch time to a local time string.

        **Example Usage**

            .. code-block:: python

                ent_rep = reputations_dict[FileProvider.ENTERPRISE]
                ent_rep_attribs = ent_rep[ReputationProp.ATTRIBUTES]
                local_time_string = FileEnterpriseAttrib.to_localtime_string(
                    ent_rep_attribs[FileEnterpriseAttrib.FIRST_CONTACT])

        :param epoch_time: Time as an Epoch time
        :param format: The format to use to convert time to a string (optional)
        :return: Time as a local time string
        """
        return time.strftime(format, EpochMixin.to_localtime(epoch_time))


class HashType(object):
    """
    Constants that are used to indicate `hash type`.

        +--------+-------------------------------------------------------+
        | Type   | Description                                           |
        +========+=======================================================+
        | MD5    | The MD5 algorithm (128-bit)                           |
        +--------+-------------------------------------------------------+
        | SHA1   | The Secure Hash Algorithm 1 (SHA-1) (160-bit)         |
        +--------+-------------------------------------------------------+
        | SHA256 | The Secure Hash Algorithm 2, 256 bit digest (SHA-256) |
        +--------+-------------------------------------------------------+
    """
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


class FileProvider(object):
    """
    Constants that are used to indicate the `provider` of a particular `file reputation`.

        +------------+---------+----------------------------------------------------------+
        | Provider   | Numeric | Description                                              |
        +============+=========+==========================================================+
        | GTI        |  1      | Global Threat Intelligence (GTI)                         |
        +------------+---------+----------------------------------------------------------+
        | ENTERPRISE |  3      | Enterprise reputation (specific to the local enterprise) |
        +------------+---------+----------------------------------------------------------+
        | ATD        |  5      | McAfee Advanced Threat Defense (ATD)                     |
        +------------+---------+----------------------------------------------------------+
        | MWG        |  7      | McAfee Web Gateway (MWG)                                 |
        +------------+---------+----------------------------------------------------------+
    """
    GTI = 1
    ENTERPRISE = 3
    ATD = 5
    MWG = 7


class CertProvider(object):
    """
    Constants that are used to indicate the `provider` of a particular `certificate reputation`.

        +------------+---------+----------------------------------------------------------+
        | Provider   | Numeric | Description                                              |
        +============+=========+==========================================================+
        | GTI        |  2      | Global Threat Intelligence (GTI)                         |
        +------------+---------+----------------------------------------------------------+
        | ENTERPRISE |  4      | Enterprise reputation (specific to the local enterprise) |
        +------------+---------+----------------------------------------------------------+
    """
    GTI = 2
    ENTERPRISE = 4


class TrustLevel(object):
    """
    Constants that are used to indicate the `trust level` of a file or certificate.

        +-------------------------+---------+---------------------------------------------------------------+
        | Trust Level             | Numeric | Description                                                   |
        +=========================+=========+===============================================================+
        | KNOWN_TRUSTED_INSTALLER |  100    | It is a trusted installer.                                    |
        +-------------------------+---------+---------------------------------------------------------------+
        | KNOWN_TRUSTED           |  99     | It is a trusted file or certificate.                          |
        +-------------------------+---------+---------------------------------------------------------------+
        | MOST_LIKELY_TRUSTED     |  85     | It is almost certain that the file or certificate is trusted. |
        +-------------------------+---------+---------------------------------------------------------------+
        | MIGHT_BE_TRUSTED        |  70     | It seems to be a benign file or certificate.                  |
        +-------------------------+---------+---------------------------------------------------------------+
        | UNKNOWN                 |  50     | The reputation provider has encountered the file or           |
        |                         |         | certificate before but the provider can't determine its       |
        |                         |         | reputation at the moment.                                     |
        +-------------------------+---------+---------------------------------------------------------------+
        | MIGHT_BE_MALICIOUS      |  30     | It seems to be a suspicious file or certificate.              |
        +-------------------------+---------+---------------------------------------------------------------+
        | MOST_LIKELY_MALICIOUS   |  15     | It is almost certain that the file or certificate is          |
        |                         |         | malicious.                                                    |
        +-------------------------+---------+---------------------------------------------------------------+
        | KNOWN_MALICIOUS         |  1      | It is a malicious file or certificate.                        |
        +-------------------------+---------+---------------------------------------------------------------+
        | NOT_SET                 |  0      | The file or certificate's reputation hasn't been determined   |
        |                         |         | yet.                                                          |
        +-------------------------+---------+---------------------------------------------------------------+
    """
    KNOWN_TRUSTED_INSTALLER = 100
    KNOWN_TRUSTED = 99
    MOST_LIKELY_TRUSTED = 85
    MIGHT_BE_TRUSTED = 70
    UNKNOWN = 50
    MIGHT_BE_MALICIOUS = 30
    MOST_LIKELY_MALICIOUS = 15
    KNOWN_MALICIOUS = 1
    NOT_SET = 0


class ReputationProp(object):
    """
    The standard set of properties that are included with each `reputation`.

        +---------------+-------------------------------------------------------------------------+
        | Name          | Description                                                             |
        +===============+=========================================================================+
        | PROVIDER_ID   | The identifier of the particular `provider` that provided the           |
        |               | reputation.                                                             |
        |               |                                                                         |
        |               | See the :class:`FileProvider` constants class for the list of           |
        |               | `file reputation providers`.                                            |
        |               |                                                                         |
        |               | See the :class:`CertProvider` constants class for the list of           |
        |               | `certificate reputation providers`.                                     |
        +---------------+-------------------------------------------------------------------------+
        | TRUST_LEVEL   | The `trust level` for the reputation subject (file, certificate, etc.)  |
        |               |                                                                         |
        |               | See the :class:`TrustLevel` constants class for the standard set of     |
        |               | `trust levels`.                                                         |
        +---------------+-------------------------------------------------------------------------+
        | CREATE_DATE   | The time this reputation was created (Epoch time)                       |
        |               |                                                                         |
        |               | See the :class:`EpochMixin` class for helper                            |
        |               | methods used to parse the Epoch time.                                   |
        +---------------+-------------------------------------------------------------------------+
        | ATTRIBUTES    | A provider-specific set of attributes associated with the reputation    |
        |               | as a Python ``dict`` (dictionary)                                       |
        |               |                                                                         |
        |               | :class:`FileEnterpriseAttrib`                                           |
        |               |     Attributes associated with the `Enterprise` reputation provider for |
        |               |     files                                                               |
        |               | :class:`FileGtiAttrib`                                                  |
        |               |     Attributes associated with the `Global Threat Intelligence (GTI)`   |
        |               |     reputation provider for files                                       |
        |               | :class:`AtdAttrib`                                                      |
        |               |     Attributes associated with the `Advanced Threat Defense (ATD)`      |
        |               |     reputation provider                                                 |
        |               | :class:`CertEnterpriseAttrib`                                           |
        |               |     Attributes associated with the `Enterprise` reputation provider for |
        |               |     certificates                                                        |
        |               | :class:`CertGtiAttrib`                                                  |
        |               |     Attributes associated with the `Global Threat Intelligence (GTI)`   |
        |               |     reputation provider for certificates                                |
        +---------------+-------------------------------------------------------------------------+
    """
    PROVIDER_ID = "providerId"
    TRUST_LEVEL = "trustLevel"
    CREATE_DATE = "createDate"
    ATTRIBUTES = "attributes"


class FileReputationProp(ReputationProp):
    """
    The standard set of properties that are included with each `file reputation`.

    This class extends the properties defined in the :class:`ReputationProp` class.
    """
    pass

"""
            "files": [
                {
                    "hashes": {
                        "md5": "fab5054707064ea9881954f98d9150c0",
                        "sha1": "13cc7e51efdac984cb746573449c399425c478e8",
                        "sha256": "37cf045819d636d5c41782af41e224edf6b88e4ea67394c5f0e659b4575b67ae"
                    }
                }
            ],
            "truncated": 0
""" # pylint: disable=pointless-string-statement


class CertReputationProp(ReputationProp):
    """
    The standard set of properties that are included with each `certificate reputation`.

    This class extends the properties defined in the :class:`ReputationProp` class.

    +---------------+-------------------------------------------------------------------------+
    | Name          | Description                                                             |
    +===============+=========================================================================+
    | OVERRIDDEN    | Includes the list of files that are currently overriding the            |
    |               | reputation of this certificate.                                         |
    |               |                                                                         |
    |               | The value associated with this property is a ``dict`` (dictionary)      |
    |               | containing the properties listed in the                                 |
    |               | :class:`CertReputationOverriddenProp` constants class.                  |
    +---------------+-------------------------------------------------------------------------+
    """
    OVERRIDDEN = "overridden"


class CertReputationOverriddenProp(object):
    """
    The set of properties associated with the ``OVERRIDDEN`` property of a `certificate reputation`
    (see :class:`CertReputationProp`).

    +---------------+--------------------------------------------------------------------------+
    | Name          | Description                                                              |
    +===============+==========================================================================+
    | FILES         | The ``list`` of files that currently override the certificate            |
    |               | identified by their ``"hashes"``.                                        |
    +---------------+--------------------------------------------------------------------------+
    | TRUNCATED     | Whether the ``list`` of files has been truncated (indicated by a ``1``). |
    +---------------+--------------------------------------------------------------------------+
    """
    FILES = "files"
    TRUNCATED = "truncated"


class EnterpriseAttrib(EpochMixin):
    """
    Attributes associated with `reputations` (for files and certificates) returned by
    the Enterprise `reputation provider`.

        +-----------------------+---------+------------------------------------------------------------------+
        | Name                  | Numeric | Description                                                      |
        +=======================+=========+==================================================================+
        | SERVER_VERSION        | 2139285 | The version of the TIE server that returned the `reputations`    |
        |                       |         | (encoded version string)                                         |
        |                       |         |                                                                  |
        |                       |         | See the :func:`to_version_tuple` and :func:`to_version_string`   |
        |                       |         | helper methods used to parse the encoded version string.         |
        +-----------------------+---------+------------------------------------------------------------------+
    """
    @staticmethod
    def to_version_tuple(version_attrib):
        """
        Returns a ``tuple`` of version values corresponding to the specified encoded version string

        For example: ``(1L, 4L, 0L, 190L)``

        **Example Usage**

            .. code-block:: python

                ent_rep = reputations_dict[FileProvider.ENTERPRISE]
                ent_rep_attribs = ent_rep[ReputationProp.ATTRIBUTES]
                version_tuple = EnterpriseAttrib.to_version_tuple(
                    ent_rep_attribs[EnterpriseAttrib.SERVER_VERSION])

        **Result**

            This method will return a ``tuple`` containing the server version values in the
            following order:

            * The major version
            * The minor version
            * The patch version
            * The build version

        :param version_attrib: The encoded version string
        :return: A ``tuple`` corresponding to the specified encoded version string
        """
        ver_long = int(version_attrib)
        return (((ver_long >> 56) & 0xff), ((ver_long >> 48) & 0xff),
                ((ver_long >> 32) & 0xffff), (ver_long & 0xffffffff))

    @staticmethod
    def to_version_string(version_attrib):
        """
        Returns a version string corresponding to the specified encoded version string

        For example: ``1.4.0.190``

        **Example Usage**

            .. code-block:: python

                ent_rep = reputations_dict[FileProvider.ENTERPRISE]
                ent_rep_attribs = ent_rep[ReputationProp.ATTRIBUTES]
                version_string = EnterpriseAttrib.to_version_string(
                    ent_rep_attribs[EnterpriseAttrib.SERVER_VERSION])

        :param version_attrib: The encoded version string
        :return: A version string corresponding to the specified encoded version string
        """
        return "{}.{}.{}.{}".format(
            *EnterpriseAttrib.to_version_tuple(version_attrib))

    SERVER_VERSION = "2139285"


class FileEnterpriseAttrib(EnterpriseAttrib):
    """
    Attributes associated with `file reputations` returned by the Enterprise `reputation provider`.

    This class extends the attributes defined in the :class:`EnterpriseAttrib` class.

        +-----------------------+---------+------------------------------------------------------------------+
        | Name                  | Numeric | Description                                                      |
        +=======================+=========+==================================================================+
        | FIRST_CONTACT         | 2102165 | The time the file was first seen (Epoch time)                    |
        |                       |         |                                                                  |
        |                       |         | See the :class:`EpochMixin` class for helper methods used to     |
        |                       |         | parse the Epoch time string.                                     |
        +-----------------------+---------+------------------------------------------------------------------+
        | PREVALENCE            | 2101652 | The count of unique systems that have executed the file          |
        +-----------------------+---------+------------------------------------------------------------------+
        | ENTERPRISE_SIZE       | 2111893 | The count of systems within the local enterprise                 |
        +-----------------------+---------+------------------------------------------------------------------+
        | MIN_LOCAL_REP         | 2112148 | The lowest reputation found locally on a system                  |
        +-----------------------+---------+------------------------------------------------------------------+
        | MAX_LOCAL_REP         | 2112404 | The highest reputation found locally on a system                 |
        +-----------------------+---------+------------------------------------------------------------------+
        | AVG_LOCAL_REP         | 2112660 | The average reputation found locally on systems                  |
        +-----------------------+---------+------------------------------------------------------------------+
        | PARENT_MIN_LOCAL_REP  | 2112916 | The lowest reputation for the parent found locally on a system   |
        +-----------------------+---------+------------------------------------------------------------------+
        | PARENT_MAX_LOCAL_REP  | 2113172 | The highest reputation for the parent found locally on a system  |
        +-----------------------+---------+------------------------------------------------------------------+
        | PARENT_AVG_LOCAL_REP  | 2113428 | The average reputation for the parent found locally on systems   |
        +-----------------------+---------+------------------------------------------------------------------+
        | FILE_NAME_COUNT       | 2114965 | The count of unique file names for the file                      |
        +-----------------------+---------+------------------------------------------------------------------+
        | DETECTION_COUNT       | 2113685 | The count of detections for the file or certificate              |
        +-----------------------+---------+------------------------------------------------------------------+
        | LAST_DETECTION_TIME   | 2113942 | The last time a detection occurred (Epoch time)                  |
        |                       |         |                                                                  |
        |                       |         | See the :class:`EpochMixin` class for helper methods used to     |
        |                       |         | parse the Epoch time.                                            |
        +-----------------------+---------+------------------------------------------------------------------+
        | IS_PREVALENT          | 2123156 | Whether the file is considered to be `prevalent` within the      |
        |                       |         | enterprise                                                       |
        +-----------------------+---------+------------------------------------------------------------------+
        | CHILD_FILE_REPS       | 2138520 | The child file reputations (aggregate string)                    |
        |                       |         |                                                                  |
        |                       |         | Use the :func:`to_aggregate_tuple` helper function to parse this |
        |                       |         | attribute                                                        |
        +-----------------------+---------+------------------------------------------------------------------+
        | PARENT_FILE_REPS      | 2138264 | The parent file reputations (aggregate string)                   |
        |                       |         |                                                                  |
        |                       |         | Use the :func:`to_aggregate_tuple` helper function to parse this |
        |                       |         | attribute                                                        |
        +-----------------------+---------+------------------------------------------------------------------+
    """
    @staticmethod
    def to_aggregate_tuple(aggregate_attrib):
        """
        Returns a `tuple` containing the values from the specified aggregate string.

        For example: ``(2, 100, 50, 100, 75.0)``

        **Example Usage**

            .. code-block:: python

                ent_rep = reputations_dict[FileProvider.ENTERPRISE]
                ent_rep_attribs = ent_rep[ReputationProp.ATTRIBUTES]
                aggregate_tuple = FileEnterpriseAttrib.to_aggregate_tuple(
                    ent_rep_attribs[FileEnterpriseAttrib.CHILD_FILE_REPS])

        **Result**

            This method will return a ``tuple`` containing the values that were in the aggregate
            string in the following order:

            * The count of files
            * The maximum `trust level` found across the files
            * The minimum `trust level` found across the files
            * The `trust level` for the last file
            * The average `trust level` across the files

        :param aggregate_attrib: The aggregate string
        :return: A `tuple` containing the values in the specified aggregate string
        """
        bin_attrib = base64.b64decode(aggregate_attrib)
        agg_list = \
            list(struct.unpack('<H', bin_attrib[i:i+2])[0]
                 for i in RANGE(0, len(bin_attrib), 2))
        if agg_list[4] > 0:
            agg_list[4] = (agg_list[4] / 100.0)
        return tuple(agg_list)

    FIRST_CONTACT = "2102165"
    PREVALENCE = "2101652"
    ENTERPRISE_SIZE = "2111893"
    MIN_LOCAL_REP = "2112148"
    MAX_LOCAL_REP = "2112404"
    AVG_LOCAL_REP = "2112660"
    PARENT_MIN_LOCAL_REP = "2112916"
    PARENT_MAX_LOCAL_REP = "2113172"
    PARENT_AVG_LOCAL_REP = "2113428"
    DETECTION_COUNT = "2113685"
    LAST_DETECTION_TIME = "2113942"
    IS_PREVALENT = "2123156"
    FILE_NAME_COUNT = "2114965"
    CHILD_FILE_REPS = "2138520"
    PARENT_FILE_REPS = "2138264"


class CertEnterpriseAttrib(EnterpriseAttrib):
    """
    Attributes associated with `certificate reputations` returned by the Enterprise `reputation provider`.

    This class extends the attributes defined in the :class:`EnterpriseAttrib` class.

        +-----------------------+---------+------------------------------------------------------------------+
        | Name                  | Numeric | Description                                                      |
        +=======================+=========+==================================================================+
        | FIRST_CONTACT         | 2109589 | The time the certificate was first seen (Epoch time)             |
        |                       |         |                                                                  |
        |                       |         | See the :class:`EpochMixin` class for helper methods used to     |
        |                       |         | parse the Epoch time.                                            |
        +-----------------------+---------+------------------------------------------------------------------+
        | PREVALENCE            | 2109333 | The count of unique systems that have executed a file that is    |
        |                       |         | associated with the certificate (via signing)                    |
        +-----------------------+---------+------------------------------------------------------------------+
        | HAS_FILE_OVERRIDES    | 2122901 | Whether one or more files associated with the certificate is     |
        |                       |         | overriding its reputation                                        |
        +-----------------------+---------+------------------------------------------------------------------+
        | IS_PREVALENT          | 2125972 | Whether the certificate is considered to be `prevalent` within   |
        |                       |         | the enterprise                                                   |
        +-----------------------+---------+------------------------------------------------------------------+
    """
    FIRST_CONTACT = "2109589"
    PREVALENCE = "2109333"
    HAS_FILE_OVERRIDES = "2122901"
    IS_PREVALENT = "2125972"


class GtiAttrib(object):
    """
    Attributes associated with `reputations` (for files and certificates) returned by
    the Global Threat Intelligence (GTI) `reputation provider`.

        +-----------------------+---------+------------------------------------------------------------------+
        | Name                  | Numeric | Description                                                      |
        +=======================+=========+==================================================================+
        | ORIGINAL_RESPONSE     | 2120340 | The raw response as returned by the                              |
        |                       |         | Global Threat Intelligence (GTI) `reputation provider`           |
        +-----------------------+---------+------------------------------------------------------------------+
    """
    ORIGINAL_RESPONSE = "2120340"


class FileGtiAttrib(GtiAttrib):
    """
    Attributes associated with `file reputations` returned by the Global Threat Intelligence (GTI)
    `reputation provider`.

    This class extends the attributes defined in the :class:`GtiAttrib` class.

        +-----------------------+---------+------------------------------------------------------------------+
        | Name                  | Numeric | Description                                                      |
        +=======================+=========+==================================================================+
        | FIRST_CONTACT         | 2101908 | The time the file was first seen (Epoch time)                    |
        |                       |         |                                                                  |
        |                       |         | See the :class:`EpochMixin` class for helper methods used to     |
        |                       |         | parse the Epoch time.                                            |
        +-----------------------+---------+------------------------------------------------------------------+
        | PREVALENCE            | 2102421 | The number of times the file has been requested.                 |
        +-----------------------+---------+------------------------------------------------------------------+
    """
    PREVALENCE = "2102421"
    FIRST_CONTACT = "2101908"


class CertGtiAttrib(GtiAttrib):
    """
    Attributes associated with `certificate reputations` returned by the Global Threat Intelligence (GTI)
    `reputation provider`.

    This class extends the attributes defined in the :class:`GtiAttrib` class.

        +-----------------------+---------+------------------------------------------------------------------+
        | Name                  | Numeric | Description                                                      |
        +=======================+=========+==================================================================+
        | FIRST_CONTACT         | 2109077 | The time the certificate was first seen (Epoch time)             |
        |                       |         |                                                                  |
        |                       |         | See the :class:`EpochMixin` class for helper methods used to     |
        |                       |         | parse the Epoch time.                                            |
        +-----------------------+---------+------------------------------------------------------------------+
        | PREVALENCE            | 2108821 | The number of times the certificate has been requested.          |
        +-----------------------+---------+------------------------------------------------------------------+
        | REVOKED               | 2117524 | Whether the certificate has been revoked                         |
        +-----------------------+---------+------------------------------------------------------------------+
    """
    PREVALENCE = "2108821"
    FIRST_CONTACT = "2109077"
    REVOKED = "2117524"


class AtdAttrib(object):
    """
    Attributes associated with `file reputations` returned by the Advanced Threat Defense (ATD)
    `reputation provider`.

        +-----------------------+---------+------------------------------------------------------------------+
        | Name                  | Numeric | Description                                                      |
        +=======================+=========+==================================================================+
        | GAM_SCORE             | 4194962 | The `trust score` reported by the Gateway Anti-Malware (GAM)     |
        |                       |         |                                                                  |
        |                       |         | See the :class:`AtdTrustLevel` constants class for the list of   |
        |                       |         | ATD `trust levels`                                               |
        +-----------------------+---------+------------------------------------------------------------------+
        | AV_ENGINE_SCORE       | 4195218 | The `trust score` reported by the Anti-Virus engine              |
        |                       |         |                                                                  |
        |                       |         | See the :class:`AtdTrustLevel` constants class for the list of   |
        |                       |         | ATD `trust levels`                                               |
        +-----------------------+---------+------------------------------------------------------------------+
        | SANDBOX_SCORE         | 4195474 | The `trust score` as a result of the sandbox evaluation          |
        |                       |         |                                                                  |
        |                       |         | See the :class:`AtdTrustLevel` constants class for the list of   |
        |                       |         | ATD `trust levels`                                               |
        +-----------------------+---------+------------------------------------------------------------------+
        | VERDICT               | 4195730 | The overall verdict (taking into consideration all available     |
        |                       |         | information)                                                     |
        |                       |         |                                                                  |
        |                       |         | See the :class:`AtdTrustLevel` constants class for the list of   |
        |                       |         | ATD `trust levels`                                               |
        +-----------------------+---------+------------------------------------------------------------------+
        | BEHAVIORS             | 4197784 | An encoded structure that contains observed behaviors of the     |
        |                       |         | file.                                                            |
        +-----------------------+---------+------------------------------------------------------------------+
    """
    GAM_SCORE = "4194962"
    AV_ENGINE_SCORE = "4195218"
    SANDBOX_SCORE = "4195474"
    VERDICT = "4195730"
    BEHAVIORS = "4197784"


class AtdTrustLevel(object):
    """
    Constants that are used to indicate the `trust level` of a file or certificate as returned by the
    Advanced Threat Defense (ATD) `reputation provider`.

        +-----------------------+---------+---------------------------------------------------------------+
        | Trust Level           | Numeric | Description                                                   |
        +=======================+=========+===============================================================+
        | KNOWN_TRUSTED         |  -1     | It is a trusted file or certificate.                          |
        +-----------------------+---------+---------------------------------------------------------------+
        | MOST_LIKELY_TRUSTED   |  0      | It is almost certain that the file or certificate is trusted. |
        +-----------------------+---------+---------------------------------------------------------------+
        | MIGHT_BE_TRUSTED      |  1      | It seems to be a benign file or certificate.                  |
        +-----------------------+---------+---------------------------------------------------------------+
        | UNKNOWN               |  2      | The reputation provider has encountered the file or           |
        |                       |         | certificate before but the provider can't determine its       |
        |                       |         | reputation at the moment.                                     |
        +-----------------------+---------+---------------------------------------------------------------+
        | MIGHT_BE_MALICIOUS    |  3      | It seems to be a suspicious file or certificate.              |
        +-----------------------+---------+---------------------------------------------------------------+
        | MOST_LIKELY_MALICIOUS |  4      | It is almost certain that the file or certificate is          |
        |                       |         | malicious.                                                    |
        +-----------------------+---------+---------------------------------------------------------------+
        | KNOWN_MALICIOUS       |  5      | It is a malicious file or certificate.                        |
        +-----------------------+---------+---------------------------------------------------------------+
        | NOT_SET               |  -2     | The file or certificate's reputation hasn't been determined   |
        |                       |         | yet.                                                          |
        +-----------------------+---------+---------------------------------------------------------------+
    """
    NOT_SET = -2
    KNOWN_TRUSTED = -1
    MOST_LIKELY_TRUSTED = 0
    MIGHT_BE_TRUSTED = 1
    UNKNOWN = 2
    MIGHT_BE_MALICIOUS = 3
    MOST_LIKELY_MALICIOUS = 4
    KNOWN_MALICIOUS = 5


class FirstRefProp(EpochMixin):
    """
    The properties that are available in a ``dict`` (dictionary) for each system that has referenced a
    file or certificate.

    For more information, see the "first reference" methods:

        For files:
            :func:`dxltieclient.client.TieClient.get_file_first_references`

        For certificates:
            :func:`dxltieclient.client.TieClient.get_certificate_first_references`

        +---------------+-------------------------------------------------------------------------+
        | Name          | Description                                                             |
        +===============+=========================================================================+
        | DATE          | The time the system first referenced the file or certificate            |
        |               | (Epoch time)                                                            |
        |               |                                                                         |
        |               | See the :class:`EpochMixin` class for helper methods used to parse the  |
        |               | Epoch time.                                                             |
        +---------------+-------------------------------------------------------------------------+
        | SYSTEM_GUID   | The GUID of the system that referenced the file or certificate          |
        +---------------+-------------------------------------------------------------------------+
    """
    DATE = "date"
    SYSTEM_GUID = "agentGuid"


class RepChangeEventProp(object):
    """
    The standard set of properties that are included with a `reputation change event`.

    See the :class:`dxltieclient.callbacks.ReputationChangeCallback` class for more information about
    reputation change events.

        +-----------------+-------------------------------------------------------------------------+
        | Name            | Description                                                             |
        +=================+=========================================================================+
        | HASHES          | A ``dict`` (dictionary) of hashes that identify the file or certificate |
        |                 | whose reputation has changed. The ``key`` in the dictionary is the      |
        |                 | `hash type` and the ``value`` is the `hex` representation of the hash   |
        |                 | value. See the :class:`HashType` class for the list of `hash type`      |
        |                 | constants.                                                              |
        +-----------------+-------------------------------------------------------------------------+
        | NEW_REPUTATIONS | The new `Reputations` for the file or certificate whose reputation has  |
        |                 | changed as a Python ``dict`` (dictionary).                              |
        +-----------------+-------------------------------------------------------------------------+
        | OLD_REPUTATIONS | The previous `Reputations` for the file or certificate whose reputation |
        |                 | has changed as a Python ``dict`` (dictionary).                          |
        +-----------------+-------------------------------------------------------------------------+
        | UPDATE_TIME     | The time the reputation change occurred (Epoch time).                   |
        |                 |                                                                         |
        |                 | See the :class:`EpochMixin` class for helper methods used to parse the  |
        |                 | Epoch time.                                                             |
        +-----------------+-------------------------------------------------------------------------+
    """
    HASHES = "hashes"
    NEW_REPUTATIONS = "newReputations"
    OLD_REPUTATIONS = "oldReputations"
    UPDATE_TIME = "updateTime"


class FileRepChangeEventProp(RepChangeEventProp):
    """
    The standard set of properties that are included with a `file reputation change event`.

    This class extends the properties defined in the :class:`RepChangeEventProp` class.

         +-----------------+-------------------------------------------------------------------------+
         | Name            | Description                                                             |
         +=================+=========================================================================+
         | RELATIONSHIPS   | Contains information regarding the certificate associated with this     |
         |                 | file (if such a relationship exists).                                   |
         +-----------------+-------------------------------------------------------------------------+
    """
    RELATIONSHIPS = "relationships"


class CertRepChangeEventProp(RepChangeEventProp):
    """
    The standard set of properties that are included with a `certificate reputation change event`.

    This class extends the properties defined in the :class:`RepChangeEventProp` class.

         +-----------------+-------------------------------------------------------------------------+
         | Name            | Description                                                             |
         +=================+=========================================================================+
         | PUBLIC_KEY_SHA1 | The SHA-1 of the certificate's public key                               |
         +-----------------+-------------------------------------------------------------------------+
    """
    PUBLIC_KEY_SHA1 = "publicKeySha1"


class DetectionEventProp(object):
    """
    The standard set of properties that are included with a `detection event`.

    See the :class:`dxltieclient.callbacks.DetectionCallback` class for more information about
    detection events.

        +--------------------+-------------------------------------------------------------------------+
        | Name               | Description                                                             |
        +====================+=========================================================================+
        | SYSTEM_GUID        | The GUID of the system that the detection occurred on.                  |
        +--------------------+-------------------------------------------------------------------------+
        | HASHES             | A ``dict`` (dictionary) of hashes that identify the file that triggered |
        |                    | the detection. The ``key`` in the dictionary is the                     |
        |                    | `hash type` and the ``value`` is the `hex` representation of the hash   |
        |                    | value. See the :class:`HashType` class for the list of `hash type`      |
        |                    | constants.                                                              |
        +--------------------+-------------------------------------------------------------------------+
        | DETECTION_TIME     | The time the detection occurred (Epoch time).                           |
        |                    |                                                                         |
        |                    | See the :class:`EpochMixin` class for helper methods used to parse the  |
        |                    | Epoch time.                                                             |
        +--------------------+-------------------------------------------------------------------------+
        | LOCAL_REPUTATION   | The local reputation determined for the file that triggered the         |
        |                    | detection.                                                              |
        |                    |                                                                         |
        |                    | See the :class:`TrustLevel` constants class for the standard set of     |
        |                    | `trust levels`.                                                         |
        +--------------------+-------------------------------------------------------------------------+
        | NAME               | The name of the file that triggered the detection.                      |
        +--------------------+-------------------------------------------------------------------------+
        | REMEDIATION_ACTION | A numeric value indicating the type of remediation that occurred in     |
        |                    | response to the detection.                                              |
        +--------------------+-------------------------------------------------------------------------+
    """
    SYSTEM_GUID = "agentGuid"
    HASHES = "hashes"
    DETECTION_TIME = "detectionTime"
    LOCAL_REPUTATION = "localReputation"
    NAME = "name"
    REMEDIATION_ACTION = "remediationAction"


class FirstInstanceEventProp(object):
    """
    The standard set of properties that are included with a `first instance event`.

    See the :class:`dxltieclient.callbacks.FirstInstanceCallback` class for more information about
    first instance events.

        +--------------------+-------------------------------------------------------------------------+
        | Name               | Description                                                             |
        +====================+=========================================================================+
        | SYSTEM_GUID        | The GUID of the system where the first instance of the file was found.  |
        +--------------------+-------------------------------------------------------------------------+
        | HASHES             | A ``dict`` (dictionary) of hashes that identify the file.               |
        |                    | The ``key`` in the dictionary is the                                    |
        |                    | `hash type` and the ``value`` is the `hex` representation of the hash   |
        |                    | value. See the :class:`HashType` class for the list of `hash type`      |
        |                    | constants.                                                              |
        +--------------------+-------------------------------------------------------------------------+
        | NAME               | The name of the file.                                                   |
        +--------------------+-------------------------------------------------------------------------+
    """
    SYSTEM_GUID = "agentGuid"
    HASHES = "hashes"
    NAME = "name"
