#!/usr/bin/python3

import binascii
import hashlib
import unittest

class Email2DomainError(Exception):
    def __init__(self, msg):
        self.msg = msg

def email2domain(email_address: str) -> str:
    """
    Implements RFC 7929, section 3
    https://tools.ietf.org/html/rfc7929#section-3

    :param email_address:
    :return:
    """
    split = email_address.split("@")
    if len(split) == 2:
        local = split[0]
        domain = split[1]
        hash = hashlib.sha256()
        hash.update(local.encode('utf-8'))
        digest = binascii.hexlify(hash.digest()[0:28]).decode("utf-8").lower()
        return digest + "._openpgpkey." + domain
    else:
        raise Email2DomainError("Email address does not contain @ sign.")


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: {} <email-address>".format(sys.argv[0]))
    else:
        print(email2domain(sys.argv[1]))


class Tests(unittest.TestCase):

    def test_basic(self):
        self.assertEqual(email2domain("hugh@example.com"),
                "c93f1e400f26708f98cb19d936620da35eec8f72e57f9eec01c1afd6._openpgpkey.example.com")