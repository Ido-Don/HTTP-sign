import collections
import datetime
import hashlib
import logging
from typing import Any, Dict, List, Optional, Sequence, Tuple, Type

import http_sf
import http_sfv
from requests import PreparedRequest

from .algorithms import HTTPSignatureAlgorithm, signature_algorithms
from .exceptions import HTTPMessageSignaturesException, InvalidSignature
from .resolvers import HTTPSignatureComponentResolver, HTTPSignatureKeyResolver
from .structures import VerifyResult

logger = logging.getLogger(__name__)
SIGNATURE_INPUT_HEADER_NAME = 'Signature-input'
DEFAULT_SIGNATURE_PARAMETERS = {}
STRING_ENCODING = 'UTF-8'
SIGNATURE_HEADER_NAME = "Signature"
DIGEST_HEADER_NAME = "Content-digest"
signature_input_type = Dict[str, Tuple[List[Tuple[str, Dict[str, Any]]], Dict[str, Any]]]

derived_component_names = {
    "@method",
    "@target-uri",
    "@authority",
    "@scheme",
    "@request-target",
    "@path",
    "@query",
    "@query-params",
    "@status",
    "@request-response",
}


def get_derived_header_from_request(request: PreparedRequest, header_name: str, header_parameters: Dict):
    assert header_name in derived_component_names
    if header_name == "@method":
        return request.method
    raise NotImplementedError(f"header {header_name} is not supported yet")


def get_request_signature_base(request: PreparedRequest, headers_to_go_over: List[Tuple[str, Dict[str, Any]]]):
    signature_base = ""
    for header_name, header_parameters in headers_to_go_over:
        if header_name in derived_component_names:
            header_value = get_derived_header_from_request(request, header_name, header_parameters)
        elif header_name in request.headers:
            header_value = request.headers[header_name]
        else:
            raise ValueError(f"header {header_name} is not a header or a derived header")
        signature_base += f"{header_name}: {header_value}\n"
    signature_base += request.headers[SIGNATURE_INPUT_HEADER_NAME]
    return signature_base


def add_body_digest_to_request(request: PreparedRequest, algorithm: str):
    if DIGEST_HEADER_NAME in request.headers:
        raise NotImplementedError("multiple signature is not implanted.")
    new_request = request.copy()
    body_byte_string = request.body.encode(STRING_ENCODING)
    body_digest = get_hash(algorithm, body_byte_string)
    body_digest_header_value = {
        algorithm: body_digest.decode(STRING_ENCODING)
    }
    new_request.headers[DIGEST_HEADER_NAME] = http_sf.ser_dictionary(body_digest_header_value)
    return new_request


def get_hash(algorithm: str, data: bytes) -> bytes:
    if algorithm == 'SHA-256':
        body_bytes_hash = hashlib.sha256(data).digest()
        return body_bytes_hash
    raise NotImplementedError(f"sorry {algorithm} is not implemented")


def sign_request(
        request: PreparedRequest,
        headers: List[Tuple[str, Dict[str, Any]]],
        algorithm: HTTPSignatureAlgorithm,
        signature_params: Dict[str, Any] = None,
        signature_label: str = "signature1"
) -> PreparedRequest:
    if signature_params is None:
        signature_params = DEFAULT_SIGNATURE_PARAMETERS

    new_request = request.copy()
    if SIGNATURE_INPUT_HEADER_NAME in new_request.headers:
        raise NotImplementedError("multiple signature is not implanted.")
    signature_input = {
        signature_label: (
            headers,
            signature_params
        )
    }
    new_request.headers[SIGNATURE_INPUT_HEADER_NAME] = http_sf.ser_dictionary(signature_input)
    signature_base = get_request_signature_base(new_request, headers)
    bytes_signature_base = signature_base.encode(STRING_ENCODING)
    signature = algorithm.sign(bytes_signature_base)
    signature_header_value = {
        signature_label: signature
    }
    new_request.headers[SIGNATURE_HEADER_NAME] = http_sf.ser_dictionary(signature_header_value)
    return new_request


class HTTPSignatureHandler:
    signature_metadata_parameters = {"alg", "created", "expires", "keyid", "nonce"}

    def __init__(
            self,
            *,
            signature_algorithm: Type[HTTPSignatureAlgorithm],
            key_resolver: HTTPSignatureKeyResolver,
            component_resolver_class: type = HTTPSignatureComponentResolver,
    ):
        if signature_algorithm not in signature_algorithms.values():
            raise HTTPMessageSignaturesException(f"Unknown signature algorithm {signature_algorithm}")
        self.signature_algorithm = signature_algorithm
        self.key_resolver = key_resolver
        self.component_resolver_class = component_resolver_class

    def _build_signature_base(
            self, message, *, covered_component_ids: List[Any], signature_params: Dict[str, str]
    ) -> Tuple:
        assert "@signature-params" not in covered_component_ids
        sig_elements = collections.OrderedDict()
        component_resolver = self.component_resolver_class(message)
        for component_id in covered_component_ids:
            component_key = str(http_sfv.List([component_id]))
            # TODO: model situations when header occurs multiple times
            component_value = component_resolver.resolve(component_id)
            if str(component_id.value).lower() != str(component_id.value):
                msg = f'Component ID "{component_id.value}" is not all lowercase'  # type: ignore
                raise HTTPMessageSignaturesException(msg)
            if "\n" in component_key:
                raise HTTPMessageSignaturesException(f'Component ID "{component_key}" contains newline character')
            if component_key in sig_elements:
                raise HTTPMessageSignaturesException(
                    f'Component ID "{component_key}" appeared multiple times in ' "signature input"
                )
            sig_elements[component_key] = component_value
        sig_params_node = http_sfv.InnerList(covered_component_ids)
        sig_params_node.params.update(signature_params)
        sig_elements['"@signature-params"'] = str(sig_params_node)
        sig_base = "\n".join(f"{k}: {v}" for k, v in sig_elements.items())
        return sig_base, sig_params_node, sig_elements


def _parse_covered_component_ids(covered_component_ids):
    covered_component_nodes = []
    for component_id in covered_component_ids:
        component_name_node = http_sfv.Item()
        if component_id.startswith('"'):
            component_name_node.parse(component_id.encode())
        else:
            component_name_node.value = component_id
        covered_component_nodes.append(component_name_node)
    return covered_component_nodes


class HTTPMessageSigner(HTTPSignatureHandler):
    DEFAULT_SIGNATURE_LABEL = "pyhms"

    def sign(
            self,
            message,
            *,
            key_id: str,
            created: Optional[datetime.datetime] = None,
            expires: Optional[datetime.datetime] = None,
            nonce: Optional[str] = None,
            label: Optional[str] = None,
            include_alg: bool = True,
            covered_component_ids: Sequence[str] = ("@method", "@authority", "@target-uri"),
    ):
        # TODO: Accept-Signature autonegotiation
        key = self.key_resolver.resolve_private_key(key_id)
        if created is None:
            created = datetime.datetime.now()
        signature_params: Dict[str, Any] = collections.OrderedDict()
        signature_params["created"] = int(created.timestamp())
        signature_params["keyid"] = key_id
        if expires:
            signature_params["expires"] = int(expires.timestamp())
        if nonce:
            signature_params["nonce"] = nonce
        if include_alg:
            signature_params["alg"] = self.signature_algorithm.algorithm_id
        covered_component_nodes = _parse_covered_component_ids(covered_component_ids)
        sig_base, sig_params_node, _ = self._build_signature_base(
            message, covered_component_ids=covered_component_nodes, signature_params=signature_params
        )
        signer = self.signature_algorithm(private_key=key)
        signature = signer.sign(sig_base.encode())
        sig_label = self.DEFAULT_SIGNATURE_LABEL
        if label is not None:
            sig_label = label
        sig_input_node = http_sfv.Dictionary({sig_label: sig_params_node})
        message.headers["Signature-Input"] = str(sig_input_node)
        sig_node = http_sfv.Dictionary({sig_label: signature})
        message.headers["Signature"] = str(sig_node)


def _parse_dict_header(header_name, headers):
    if header_name not in headers:
        raise InvalidSignature(f'Expected "{header_name}" header field to be present')
    try:
        dict_header_node = http_sfv.Dictionary()
        dict_header_node.parse(headers[header_name].encode())
    except Exception as e:
        raise InvalidSignature(f'Malformed structured header field "{header_name}"') from e
    return dict_header_node


def _parse_integer_timestamp(ts, field_name):
    try:
        ts = int(ts)
        dt = datetime.datetime.fromtimestamp(ts)
    except Exception as e:
        raise InvalidSignature(f'Malformed "{field_name}" parameter: {e}') from e
    return dt


def validate_created_and_expires(sig_input, max_age=None):
    now = datetime.datetime.now()
    min_time = now - HTTPMessageVerifier.max_clock_skew
    max_time = now + HTTPMessageVerifier.max_clock_skew
    if "created" in sig_input.params:
        if _parse_integer_timestamp(sig_input.params["created"], field_name="created") > max_time:
            raise InvalidSignature('Signature "created" parameter is set to a time in the future')
    elif HTTPMessageVerifier.require_created:
        raise InvalidSignature('Signature is missing a required "created" parameter')
    if "expires" in sig_input.params:
        if _parse_integer_timestamp(sig_input.params["expires"], field_name="expires") < min_time:
            raise InvalidSignature('Signature "expires" parameter is set to a time in the past')
    if max_age is not None:
        if _parse_integer_timestamp(sig_input.params["created"], field_name="created") + max_age < min_time:
            raise InvalidSignature(f"Signature age exceeds maximum allowable age {max_age}")


class HTTPMessageVerifier(HTTPSignatureHandler):
    max_clock_skew: datetime.timedelta = datetime.timedelta(seconds=5)
    require_created: bool = True

    def verify(self, message, *, max_age: datetime.timedelta = datetime.timedelta(days=1)) -> List[VerifyResult]:
        sig_inputs = _parse_dict_header("Signature-Input", message.headers)
        if len(sig_inputs) != 1:
            # TODO: validate all behaviors with multiple signatures
            raise InvalidSignature("Multiple signatures are not supported")
        signature = _parse_dict_header("Signature", message.headers)
        verify_results = []
        for label, sig_input in sig_inputs.items():
            validate_created_and_expires(sig_input, max_age=max_age)
            if label not in signature:
                raise InvalidSignature("Signature-Input contains a label not listed in Signature")
            if "alg" in sig_input.params:
                if sig_input.params["alg"] != self.signature_algorithm.algorithm_id:
                    raise InvalidSignature("Unexpected algorithm specified in the signature")
            key = self.key_resolver.resolve_public_key(sig_input.params["keyid"])
            for param in sig_input.params:
                if param not in self.signature_metadata_parameters:
                    raise InvalidSignature(f'Unexpected signature metadata parameter "{param}"')
            try:
                sig_base, sig_params_node, sig_elements = self._build_signature_base(
                    message, covered_component_ids=list(sig_input), signature_params=sig_input.params
                )
            except Exception as e:
                raise InvalidSignature(e) from e
            verifier = self.signature_algorithm(public_key=key)
            raw_signature = signature[label].value
            try:
                verifier.verify(signature=raw_signature, message=sig_base.encode())
            except Exception as e:
                raise InvalidSignature(e) from e
            verify_result = VerifyResult(
                label=label,
                algorithm=self.signature_algorithm,
                covered_components=sig_elements,
                parameters=dict(sig_params_node.params),
                body=None,
            )
            verify_results.append(verify_result)
        return verify_results
