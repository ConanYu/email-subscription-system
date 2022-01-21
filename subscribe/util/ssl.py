import hashlib
import time
from typing import Tuple, Optional

import rsa
from readerwriterlock.rwlock import RWLockFairD

from subscribe.util.go import go


class _SSL(object):
    class __RSAKey(object):
        def __init__(self, public: rsa.PublicKey, private: rsa.PrivateKey):
            self.public = public
            self.private = private
            self.value = hashlib.sha512(public.save_pkcs1()).hexdigest()

        def check_same(self, value):
            return self.value == value

    def __init__(self):
        print('SSL object initializing...')
        self.__cache = (self.__new_keys(), self.__new_keys())
        self.__cache_lock = RWLockFairD()
        self.__auto_generate_keys()
        print('SSL object has initialized')

    def __new_keys(self) -> __RSAKey:
        public, private = rsa.newkeys(2048)
        return self.__RSAKey(public, private)

    @go
    def __auto_generate_keys(self):
        while True:
            time.sleep(1800)
            key = self.__new_keys()
            with self.__cache_lock.gen_wlock():
                self.__cache = (key, self.__cache[0])

    def get(self) -> Tuple[str, str]:
        with self.__cache_lock.gen_rlock():
            key = self.__cache[0]
            return key.value, key.public.save_pkcs1().decode()

    def decode(self, value: str, crypto: bytes) -> bytes:
        rsa_key: Optional[_SSL.__RSAKey] = None
        with self.__cache_lock.gen_rlock():
            if self.__cache[0].value == value:
                rsa_key = self.__cache[0]
            elif self.__cache[1].value == value:
                rsa_key = self.__cache[1]
        if rsa_key is None:
            raise rsa.DecryptionError('private key not found')
        return rsa.decrypt(crypto, rsa_key.private)


SSL = _SSL()

if __name__ == '__main__':
    value, public = SSL.get()
    encode = rsa.encrypt(b'hello world', rsa.PublicKey.load_pkcs1(public.encode()))
    print(SSL.decode(value, encode))
