from umac import UMAC


instance = UMAC(
  32,
  key=b"abcdefghijklmnop",
  nonce=b"bcdefghi",
)

instance.update(b"aaa")
print(instance.digest().hex())
