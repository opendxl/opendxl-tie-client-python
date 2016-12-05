Overview
========

The `McAfee Threat Intelligence Exchange <http://www.mcafee.com/us/products/threat-intelligence-exchange.aspx>`_
(TIE) DXL Python client  library provides a high level wrapper for the TIE
`Data Exchange Layer <http://www.mcafee.com/us/solutions/data-exchange-layer.aspx>`_ (DXL) API.

The purpose of this library is to allow users to access the features of TIE (manage reputations, determine where a file
has executed, etc.) without having to focus on lower-level details such as TIE-specific DXL topics and message formats.

The :class:`dxltieclient.client.TieClient` class wraps the connection to the DXL fabric and is used to
access the features of TIE.