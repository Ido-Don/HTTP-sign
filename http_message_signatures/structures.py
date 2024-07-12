import dataclasses
from collections import OrderedDict, namedtuple
from collections.abc import Mapping, MutableMapping
from typing import List, Any, Dict

import requests
from requests import Request, PreparedRequest

VerifyResult = namedtuple("VerifyResult", "label algorithm covered_components parameters body")
DERIVED_HTTP_ATTRIBUTES = [
    "@method",
    "@target-uri",
    "@authority",
    "@scheme",
    "@request-target",
    "@path",
    "@query",
    "@query-param",
    "@status",
]


class SignatureInput:
    def __init__(self, header_names: List[str], signature_params: Dict[str, Any]):
        self.lower_case_header_names = [header_name.lower() for header_name in header_names]
        self.signature_params = signature_params

    def get_canonical_headers(self, prepared_request: PreparedRequest):
        pass

    def __str__(self):
        header_names_with_spaces = ' '.join(self.lower_case_header_names)
        header_names_string = f'({header_names_with_spaces})'
        signature_parameter_strings = [f";{key}={value}" for key, value in self.signature_params.items()]
        signature_parameter_string = ''.join(signature_parameter_strings)
        signature_input_string = header_names_string + signature_parameter_string
        return signature_input_string


class CaseInsensitiveDict(MutableMapping):
    """
    A copy of requests.structures.CaseInsensitiveDict.
    """

    def __init__(self, data=None, **kwargs):
        self._store = OrderedDict()
        if data is None:
            data = {}
        self.update(data, **kwargs)

    def __setitem__(self, key, value):
        # Use the lowercased key for lookups, but store the actual
        # key alongside the value.
        self._store[key.lower()] = (key, value)

    def __getitem__(self, key):
        return self._store[key.lower()][1]

    def __delitem__(self, key):
        del self._store[key.lower()]

    def __iter__(self):
        return (casedkey for casedkey, mappedvalue in self._store.values())

    def __len__(self):
        return len(self._store)

    def lower_items(self):
        """Like iteritems(), but with all lowercase keys."""
        return ((lowerkey, keyval[1]) for (lowerkey, keyval) in self._store.items())

    def __eq__(self, other):
        if isinstance(other, Mapping):
            other = CaseInsensitiveDict(other)
        else:
            return NotImplemented
        # Compare insensitively
        return dict(self.lower_items()) == dict(other.lower_items())

    # Copy is required
    def copy(self):
        return CaseInsensitiveDict(self._store.values())

    def __repr__(self):
        return str(dict(self.items()))
