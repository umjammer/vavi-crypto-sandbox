/*
 * Copyright (c) 2026 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

/**
 * A JCA/JCE service provider for KIRK, the crypto engine of the PSP.
 * <h2>What is KIRK?</h2>
 * KIRK is the cryptographic co-processor built into the PSP's main SoC (it is memory mapped at
 * {@code 0xBDE00000}, the fuse id it uses as a per console key lives at {@code 0xBC100090}).
 * Sony never documented it, the name and everything known about it comes from the homebrew
 * scene, which reverse engineered it around 2007-2011 (Draan's {@code kirk_engine},
 * later {@code libkirk}).
 * <p>
 * The engine is not a general purpose crypto library, it is a <em>command processor</em>.
 * The CPU fills an input buffer, calls {@code sceUtilsBufferCopyWithRange(out, outSize, in, inSize, cmd)}
 * and the engine reads a header from the beginning of that buffer, performs the requested command
 * and writes the result into the output buffer. Everything is AES-128 (CBC with a zero IV),
 * AES-CMAC, SHA-1 and ECDSA over a 160 bit curve of Sony's own.
 * <p>
 * The point of the design is that the keys never leave the chip: a command names a key by
 * a <em>key seed</em> (an index into an internal key table), or uses the console unique fuse id,
 * or the burnt-in "KIRK1" master key. That is what makes the PSP's encrypted executables
 * ({@code ~PSP} / PRX files), the save data and the UMD/PGD keys work.
 * <h2>Commands</h2>
 * <pre>
 *  cmd  name                     what it does
 *  0x0  ENCRYPT_PRIVATE          AES-128-CBC encrypt + CMAC sign, keys taken from the block header (KIRK1 key)
 *  0x1  DECRYPT_PRIVATE          the inverse of 0x0, this is what decrypts PRX/executables ("CMD1" blocks)
 *  0x2  ENCRYPT_SIGN             like 0x0 but signed with ECDSA (key type 3, blacklisting)
 *  0x3  DECRYPT_SIGN             the inverse of 0x2
 *  0x4  ENCRYPT_IV_0             AES-128-CBC encrypt with a key table key (key seed), zero IV
 *  0x5  ENCRYPT_IV_FUSE          the same but with the console unique fuse id key
 *  0x6  ENCRYPT_IV_USER          the same but with a user supplied IV
 *  0x7  DECRYPT_IV_0             the inverse of 0x4
 *  0x8  DECRYPT_IV_FUSE          the inverse of 0x5
 *  0x9  DECRYPT_IV_USER          the inverse of 0x6
 *  0xA  PRIV_SIGN_CHECK          AES-CMAC check of a CMD1 block header and data
 *  0xB  SHA1_HASH                SHA-1
 *  0xC  ECDSA_GEN_KEYS           generate an ECDSA key pair
 *  0xD  ECDSA_MULTIPLY_POINT     ECDSA point multiplication
 *  0xE  PRNG                     pseudo random numbers (SHA-1 of an internal state + the current time)
 *  0xF  INIT                     engine initialization
 * 0x10  ECDSA_SIGN               ECDSA sign, the private key is given encrypted with the fuse id key
 * 0x11  ECDSA_VERIFY             ECDSA verify
 * 0x12  CERT_VERIFY              certificate check
 * </pre>
 * All the header fields are little endian. A command's input buffer is
 * {@code header || data}, and for the AES-CBC commands the output keeps the header
 * (with its mode field flipped from ENCRYPT_CBC to DECRYPT_CBC) so that the block can
 * be fed back to the decrypt command as is.
 * <h2>The curves</h2>
 * KIRK uses two curves over the same 160 bit prime field
 * ({@code p = FFFFFFFF FFFFFFFF 00000001 FFFFFFFF FFFFFFFF}, {@code a = p - 3}):
 * one for the KIRK1 signature check of CMD1 blocks (with the built in public key
 * {@code Px1}/{@code Py1}), and one for the user facing ECDSA commands 0xC, 0xD, 0x10 and 0x11.
 * The latter is exposed here as {@link vavi.crypto.kirk.Kirk#CURVE}.
 * <h2>What this package provides</h2>
 * The engine emulation itself is {@code libkirk} (ported from Draan's C sources by jpcsp),
 * this package only wraps it into the standard Java security services:
 * <pre>
 *  Cipher.KIRK                       AES-128-CBC through the KIRK commands, the key selects which one
 *  SecretKeyFactory.KIRK             makes a {@link vavi.crypto.kirk.KirkKey} out of a key seed
 *  MessageDigest.KIRK-SHA1           command 0xB
 *  SecureRandom.KIRK-PRNG            command 0xE
 *  KeyPairGenerator.KIRK-ECDSA       command 0xC
 *  Signature.SHA1withKIRKECDSA       commands 0xB + 0x10 (sign) and 0xB + 0x11 (verify)
 * </pre>
 *
 * @author <a href="mailto:umjammer@gmail.com">Naohide Sano</a> (umjammer)
 * @version 0.00 2026/07/27 umjammer initial version <br>
 * @see "https://github.com/jpcsp/jpcsp"
 * @see "https://github.com/ProximaV/kirk-engine-full"
 * @see "https://www.psdevwiki.com/psp/KIRK"
 */
package vavi.crypto.kirk;
