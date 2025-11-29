from typing import Literal


class UMAC:
    """
    A class for computing UMAC hashes.
    """

    def __init__(self, digest_size: Literal[4, 8, 12, 16], key: bytes, nonce: bytes) -> None:
        """
        Initialize a UMAC instance.

        Parameters
        ----------
        digest_size
            The size of the digest in bytes. One of 4, 8, 12 or 16.
        """

    def update(self, data: bytes, /) -> None:
        """
        Update the instance with the given data.

        Parameters
        ----------
        data
            The data to update the UMAC instance with.
        """

    def digest(self) -> bytes:
        """
        Compute the digest.

        The instance may not be used after calling this method.

        Returns
        -------
        bytes
            The computed digest.
        """
