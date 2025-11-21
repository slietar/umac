# UMAC

This project is a Python implementation of the UMAC algorithm defined by RFC 4418.

It supports Python 3.11 and later.


## Installation

This package is available on PyPI under the name `umac`.


## Usage

The API loosely follows the PEP 247 standard.

```py
from umac import UMAC

mac = UMAC(
    digest_size=4, # Using UMAC-32
    key=b"abcdefghijklmnop",
    nonce=b"bcdefghi",
)

mac.update(b"aaa")
digest = mac.digest()

print(digest.hex())
```
