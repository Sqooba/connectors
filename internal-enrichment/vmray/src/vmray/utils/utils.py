# -*- coding: utf-8 -*-
"""Utils methods for VMRay Connector."""

import re
from functools import reduce
from typing import Any, Union
from urllib.parse import urlparse

from stix2.base import _STIXBase

from .constants import VERDICTS


def deep_get(data: Union[dict, str], *keys, default: Any = None) -> Any:
    """
    This method is a helper to retrieve data from a dictionary or from a Stix object.
    Parameters
    ----------
    data: str
        * The dictionary or the Stix object where the method will search
    keys: str
        * The key(s) that will be used to search.
    default: Any
        * The default parameter that will be return if the search key is not found.
        If this parameter is ignored, None will be return
    """
    return reduce(
        lambda d, key: d.get(key, default)
        if isinstance(d, (dict, _STIXBase))
        else default,
        keys,
        data,
    )


def format_domain(url: str) -> str:
    """
    This method remove 'http://', 'https://' and 'www.' in the url parameter.

    Some examples :
        * http://test.com --> test.com
        * https://test.com --> test.com
        * http://www.test.com --> test.com
        * www.test.com --> test.com
    Parameters
    ----------
    url: str
        * The string that will be process
    Returns
    -------
    str:
        * A formatted string that contains the desired domain-name format
    """
    # Format url
    formatted = urlparse(url)
    result = ""
    # Check if netloc/path is not empty
    if formatted.netloc:
        result = formatted.netloc
    elif formatted.path:
        result = formatted.path
    # Replace www. if it exists in the string
    return result.replace("www.", "")


def format_email_address(email: str) -> Union[str, None]:
    """
    This method searches for an email address in the string specified as argument.
    If no conventional value is found in the candidate, None is returned.

    Parameters
    ----------
    email: str
        * The string that needs to be processed
    Returns
    -------
    str:
        * A formatted string that contains the email-address value
    """
    match = re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", email)
    if match:
        return match.group(0)
    return None


def get_score(verdict: str) -> int:
    """
    Compare the verdict and return a score accordingly. clean -> 10, suspicious -> 80, malicious -> 100.
    Returns
    -------
    int:
        The score assigned to the verdict
    """
    return (
        VERDICTS.get(verdict.lower(), None)
        if verdict and isinstance(verdict, str)
        else None
    )
