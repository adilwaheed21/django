"""
Elastica's Implementation of db base session store.
"""

import base64

from django.core.exceptions import SuspiciousOperation
from django.conf import settings
from django.contrib.sessions.backends.db import SessionStore as DjangoDBSessionStore
from django.utils.crypto import constant_time_compare, salted_hmac
from django.utils.encoding import force_bytes


class SessionStore(DjangoDBSessionStore):
    """
    Implements database session store for Elastica.
    The additional features in this session store implementation are:
    - Able to decode session data using mutliple keys. Note that we don't need to change encode
    function as we'll always encode with latest available key. For decode, however, if we are
    unable to decode with latest key, we'll try rest of the configured keys and only throw error
    if everythin fails.
    """

    def _hash(self, value, secret=None, class_name="SessionStore"):
        key_salt = "django.contrib.sessions" + class_name
        return salted_hmac(key_salt, value, secret).hexdigest()

    def decode(self, session_data):
        encoded_data = base64.b64decode(force_bytes(session_data))
        try:
            # could produce ValueError if there is no ':'
            hash_val, serialized = encoded_data.split(b':', 1)
            # If there's only a single key, use just that
            if not getattr(settings, "SESSION_ENCRYPTION_KEYS", None) or len(settings.SESSION_ENCRYPTION_KEYS) == 1:
                return self._decode_with_single_key(hash_val, serialized)
            # If multiple keys are there, try all of them
            return self._decode_with_multiple_keys(hash_val, serialized)
        except Exception:
            # ValueError, SuspiciousOperation, deserialization exceptions. If
            # any of these happen, just return an empty dictionary (an empty
            # session).
            return {}

    def _decode_with_single_key(self, hash_val, serialized):
        expected_hash = self._hash(serialized)
        if not constant_time_compare(hash_val.decode(), expected_hash):
            raise SuspiciousOperation("Session data corrupted")

        return self.serializer().loads(serialized)

    def _decode_with_multiple_keys(self, hash_val, serialized):
        for key in settings.SESSION_ENCRYPTION_KEYS:
            expected_hash = self._hash(serialized, secret=key)
            if not constant_time_compare(hash_val.decode(), expected_hash):
                continue
            # If here, that means session got decoded
            return self.serializer().loads(serialized)
        # If here, then we've exhausted all the keys, raise Exception
        raise SuspiciousOperation("Session data corrupted")
