from types import SimpleNamespace

import pytest

import handshake as hs
import secure_record as sr


@pytest.fixture(scope="session")
def identities():
    parameters = hs.load_parameters()
    gateway_key = hs.load_or_create_signing_key("gateway-rsa.pem")
    node_key = hs.load_or_create_signing_key("node-rsa.pem")
    return parameters, gateway_key, node_key


@pytest.fixture
def exchange(identities):
    parameters, gateway_key, node_key = identities
    gateway = hs.new_pending(parameters, hs.GATEWAY_ROLE)
    node = hs.new_pending(parameters, hs.NODE_ROLE)
    transcript = hs.build_transcript(gateway, node)
    return SimpleNamespace(
        parameters=parameters,
        gateway=gateway,
        node=node,
        transcript=transcript,
        gateway_key=gateway_key,
        node_key=node_key,
        gateway_signature=hs.sign_transcript(
            gateway, transcript, gateway_key
        ),
        node_signature=hs.sign_transcript(node, transcript, node_key),
    )


@pytest.fixture
def endpoints(identities):
    parameters, gateway_key, node_key = identities
    gateway_keys, node_keys, _ = hs.run_handshake(
        parameters, gateway_key, node_key
    )
    return sr.make_endpoints(gateway_keys, node_keys)
