# vavi.crypto.kirk

KIRK is the crypto engine of the PSP, a command processor around AES-128-CBC, AES-CMAC,
SHA-1 and ECDSA whose keys never leave the chip. `vavi.crypto.kirk` wraps the
[libkirk](../../../libkirk) emulation into the standard services (see
[package-info](package-info.java) for the command list).

| service                       | KIRK command      |
|-------------------------------|-------------------|
| `Cipher.KIRK`                 | 0x0/0x1, 0x4/0x7, 0x5/0x8 (the key seed chooses) |
| `SecretKeyFactory.KIRK`       | -                 |
| `MessageDigest.KIRK-SHA1`     | 0xB               |
| `SecureRandom.KIRK-PRNG`      | 0xE               |
| `KeyPairGenerator.KIRK-ECDSA` | 0xC               |
| `Signature.SHA1withKIRKECDSA` | 0xB + 0x10, 0x11  |

## Usage

```java
Security.addProvider(new KirkProvider());

Key key = SecretKeyFactory.getInstance("KIRK").generateSecret(new KirkKeySpec(3));
Cipher cipher = Cipher.getInstance("KIRK", "KIRK");
cipher.init(Cipher.ENCRYPT_MODE, key);
byte[] encrypted = cipher.doFinal(plain); // a whole KIRK block: header + data
```
