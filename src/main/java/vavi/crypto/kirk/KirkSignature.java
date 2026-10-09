/*
 * Copyright (c) 2026 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package vavi.crypto.kirk;

import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;

import libkirk.KirkEngine;

import static vavi.crypto.kirk.Kirk.ELT_SIZE;


/**
 * The ECDSA commands (0x10 sign, 0x11 verify) of the KIRK engine as a
 * {@link java.security.Signature}, over the SHA-1 of the command 0xB.
 * <p>
 * A signature is the raw {@code r || s} of the engine, 20 bytes each, <em>not</em> the DER
 * encoding the other JCA providers use.
 * <p>
 * The signing command takes the private key encrypted under the console unique fuse id key,
 * that encryption is done here, so a key which was signed with on one console cannot be used
 * on another one, exactly like on the real hardware.
 *
 * @author <a href="mailto:umjammer@gmail.com">Naohide Sano</a> (umjammer)
 * @version 0.00 2026/07/27 umjammer initial version <br>
 */
public final class KirkSignature extends SignatureSpi {

    /** size of the private key as the command 0x10 wants it, 20 bytes and padding */
    private static final int ENCRYPTED_PRIVATE_KEY_SIZE = 0x20;

    /** r || s */
    private static final int SIGNATURE_SIZE = ELT_SIZE * 2;

    /** the data to be hashed */
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    /** the scalar to sign with, or null when initialized for verification */
    private byte[] privateKey;

    /** the point to verify with, or null when initialized for signing */
    private byte[] publicKey;

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof KirkPrivateKey key)) {
            throw new InvalidKeyException("key must be a KirkPrivateKey: " + privateKey);
        }
        this.privateKey = key.getEncoded();
        this.publicKey = null;
        buffer.reset();

        Kirk.init();
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof KirkPublicKey key)) {
            throw new InvalidKeyException("key must be a KirkPublicKey: " + publicKey);
        }
        this.publicKey = key.getEncoded();
        this.privateKey = null;
        buffer.reset();

        Kirk.init();
    }

    @Override
    protected void engineUpdate(byte b) {
        buffer.write(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) {
        buffer.write(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (privateKey == null) {
            throw new SignatureException("not initialized for signing");
        }

        byte[] hash = digest();

        // the engine only signs with a private key which is encrypted for this console
        byte[] decrypted = new byte[ENCRYPTED_PRIVATE_KEY_SIZE];
        System.arraycopy(privateKey, 0, decrypted, 0, ELT_SIZE);
        byte[] encrypted = new byte[ENCRYPTED_PRIVATE_KEY_SIZE];
        KirkEngine.encrypt_kirk16_private(encrypted, decrypted);

        byte[] in = new byte[KirkEngine.KIRK_CMD16_BUFFER.SIZEOF];
        System.arraycopy(encrypted, 0, in, 0, ENCRYPTED_PRIVATE_KEY_SIZE);
        System.arraycopy(hash, 0, in, ENCRYPTED_PRIVATE_KEY_SIZE, ELT_SIZE);

        byte[] out = new byte[SIGNATURE_SIZE];
        Kirk.check(KirkEngine.kirk_CMD16(out, out.length, in, in.length));

        return out;
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (publicKey == null) {
            throw new SignatureException("not initialized for verification");
        }
        if (sigBytes.length != SIGNATURE_SIZE) {
            throw new SignatureException("a KIRK signature is %d bytes: %d".formatted(SIGNATURE_SIZE, sigBytes.length));
        }

        byte[] hash = digest();

        byte[] in = new byte[KirkEngine.KIRK_CMD17_BUFFER.SIZEOF];
        System.arraycopy(publicKey, 0, in, 0, publicKey.length);
        System.arraycopy(hash, 0, in, publicKey.length, ELT_SIZE);
        System.arraycopy(sigBytes, 0, in, publicKey.length + ELT_SIZE, SIGNATURE_SIZE);

        int result = KirkEngine.kirk_CMD17(in, in.length);
        return switch (result) {
            case KirkEngine.KIRK_OPERATION_SUCCESS -> true;
            case KirkEngine.KIRK_SIG_CHECK_INVALID -> false;
            default -> throw new KirkException(result);
        };
    }

    /** the SHA-1 of everything which was fed since the last sign or verify */
    private byte[] digest() {
        byte[] data = buffer.toByteArray();
        buffer.reset();
        return Kirk.sha1(data, 0, data.length);
    }

    @Deprecated
    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new InvalidParameterException("no parameter: " + param);
    }

    @Deprecated
    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new InvalidParameterException("no parameter: " + param);
    }
}
