from pigeon.crypto.ed25519 import sign, verify_signature
from pigeon.crypto.keys import generate_keypair, keypair_from_seed


def test_sign_and_verify():
    pub, priv = generate_keypair()
    sig = sign(b"hello", priv)
    assert verify_signature(b"hello", sig, pub)
    assert not verify_signature(b"hello!", sig, pub)


def test_seeded_keys_are_deterministic():
    seed = bytes(range(32))
    a = keypair_from_seed(seed)
    b = keypair_from_seed(seed)
    assert a == b


def test_wrong_key_fails():
    pub1, priv1 = generate_keypair()
    pub2, _priv2 = generate_keypair()
    sig = sign(b"msg", priv1)
    assert not verify_signature(b"msg", sig, pub2)
    assert pub1 != pub2
