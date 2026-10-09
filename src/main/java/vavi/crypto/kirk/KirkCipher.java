/*
 * Copyright (c) 2026 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package vavi.crypto.kirk;

import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import libkirk.KirkEngine;

import static libkirk.Utilities.read32;
import static libkirk.Utilities.write32;
import static vavi.crypto.kirk.Kirk.AES128CBC_HEADER_SIZE;
import static vavi.crypto.kirk.Kirk.CMD1_DATA_SIZE_OFFSET;
import static vavi.crypto.kirk.Kirk.CMD1_HEADER_SIZE;
import static vavi.crypto.kirk.Kirk.align16;


/**
 * The AES-128-CBC (zero IV) commands of the KIRK engine as a {@link Cipher}.
 * <p>
 * Which command is used is decided by the {@link KirkKey}:
 * <pre>
 *  key seed             encrypt  decrypt
 *  0 ... n              0x4      0x7      a key of the engine's key table
 *  {@link KirkKeySpec#FUSE}   0x5      0x8      the console unique fuse id key
 *  {@link KirkKeySpec#KIRK1}  0x0      0x1      the burnt in master key, i.e. a "CMD1" block
 * </pre>
 * A ciphertext is always a complete KIRK block, i.e. it carries the command header the
 * engine needs to decrypt it back. For the key table and fuse keys the cipher builds that
 * header itself, so encrypting {@code n} bytes gives {@code 0x14 + n} (rounded up to the
 * AES block size) bytes and decrypting them gives the original {@code n} bytes back, even
 * when {@code n} is not a multiple of the block size, because the header records the exact
 * data size.
 * <p>
 * For {@link KirkKeySpec#KIRK1} the header cannot be built here: it holds the AES and CMAC
 * keys of the block, so the input of an encryption is expected to be a complete {@code 0x90}
 * bytes header (with its AES key, CMAC key, mode, data size and data offset filled in)
 * followed by the data, which is what the PSP's encrypted executables look like.
 *
 * @author <a href="mailto:umjammer@gmail.com">Naohide Sano</a> (umjammer)
 * @version 0.00 2026/07/27 umjammer initial version <br>
 */
public final class KirkCipher extends CipherSpi {

    /** offset of the key seed in the AES-128-CBC command header */
    private static final int KEY_SEED_OFFSET = 0x0C;

    /** offset of the data size in the AES-128-CBC command header */
    private static final int DATA_SIZE_OFFSET = 0x10;

    /** {@link Cipher#ENCRYPT_MODE} or {@link Cipher#DECRYPT_MODE} */
    private int opmode;

    /** @see KirkKeySpec */
    private int keySeed;

    /** the KIRK commands work on a whole block, so everything is buffered until the final */
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if (!mode.equalsIgnoreCase("CBC") && !mode.equalsIgnoreCase("NONE")) {
            throw new NoSuchAlgorithmException("KIRK only does CBC: " + mode);
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (!padding.equalsIgnoreCase("NoPadding")) {
            throw new NoSuchPaddingException("KIRK does not pad: " + padding);
        }
    }

    @Override
    protected int engineGetBlockSize() {
        return 16;
    }

    /** @return the zero IV the KIRK engine always uses */
    @Override
    protected byte[] engineGetIV() {
        return new byte[16];
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        if (opmode == Cipher.ENCRYPT_MODE) {
            return keySeed == KirkKeySpec.KIRK1 ? inputLen : AES128CBC_HEADER_SIZE + align16(inputLen);
        } else {
            // the plain data is always shorter than its block
            return inputLen;
        }
    }

    @Override
    protected int engineGetKeySize(Key key) throws InvalidKeyException {
        if (!(key instanceof KirkKey)) {
            throw new InvalidKeyException("key must be a KirkKey: " + key);
        }
        return 128;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        if (opmode != Cipher.ENCRYPT_MODE && opmode != Cipher.DECRYPT_MODE) {
            throw new InvalidKeyException("KIRK only encrypts and decrypts, mode: " + opmode);
        }
        if (!(key instanceof KirkKey kirkKey)) {
            throw new InvalidKeyException("key must be a KirkKey: " + key);
        }

        this.opmode = opmode;
        this.keySeed = kirkKey.keySpec.keySeed;

        buffer.reset();

        Kirk.init();
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        engineInit(opmode, key, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        engineInit(opmode, key, random);
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        buffer.write(input, inputOffset, inputLen);
        return null; // a KIRK command needs the whole block
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
        engineUpdate(input, inputOffset, inputLen);
        return 0;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException {
        if (input != null && inputLen > 0) {
            buffer.write(input, inputOffset, inputLen);
        }
        byte[] data = buffer.toByteArray();
        buffer.reset();
        return opmode == Cipher.ENCRYPT_MODE ? encrypt(data) : decrypt(data);
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException {
        byte[] result = engineDoFinal(input, inputOffset, inputLen);
        if (output.length - outputOffset < result.length) {
            throw new ShortBufferException("needs %d bytes".formatted(result.length));
        }
        System.arraycopy(result, 0, output, outputOffset, result.length);
        return result.length;
    }

    /** @return the whole KIRK block, i.e. the command header followed by the encrypted data */
    private byte[] encrypt(byte[] data) throws IllegalBlockSizeException {
        if (keySeed == KirkKeySpec.KIRK1) {
            // the caller supplies the header, it contains the keys of the block
            checkBlockSize(data, CMD1_HEADER_SIZE);
            int dataSize = read32(data, CMD1_DATA_SIZE_OFFSET);
            int dataOffset = read32(data, CMD1_DATA_SIZE_OFFSET + 4);
            checkBlockSize(data, CMD1_HEADER_SIZE + dataOffset + align16(dataSize));
            byte[] out = new byte[data.length];
            Kirk.check(KirkEngine.kirk_CMD0(out, data, data.length, true));
            return out;
        }

        byte[] in = new byte[AES128CBC_HEADER_SIZE + align16(data.length)];
        write32(in, 0, KirkEngine.KIRK_MODE_ENCRYPT_CBC);
        write32(in, KEY_SEED_OFFSET, keySeed);
        write32(in, DATA_SIZE_OFFSET, data.length);
        System.arraycopy(data, 0, in, AES128CBC_HEADER_SIZE, data.length);

        byte[] out = new byte[in.length];
        Kirk.check(keySeed == KirkKeySpec.FUSE ?
                KirkEngine.kirk_CMD5(out, in, in.length) :
                KirkEngine.kirk_CMD4(out, in, in.length));

        if (keySeed == KirkKeySpec.FUSE) {
            // unlike command 0x4, command 0x5 leaves the header alone
            System.arraycopy(in, 0, out, 0, AES128CBC_HEADER_SIZE);
            write32(out, 0, KirkEngine.KIRK_MODE_DECRYPT_CBC);
        }

        return out;
    }

    /** @param block the whole KIRK block, i.e. the command header followed by the encrypted data */
    private byte[] decrypt(byte[] block) throws IllegalBlockSizeException {
        int headerSize = keySeed == KirkKeySpec.KIRK1 ? CMD1_HEADER_SIZE : AES128CBC_HEADER_SIZE;
        checkBlockSize(block, headerSize);

        int dataSize;
        byte[] out;
        if (keySeed == KirkKeySpec.KIRK1) {
            dataSize = read32(block, CMD1_DATA_SIZE_OFFSET);
            int dataOffset = read32(block, CMD1_DATA_SIZE_OFFSET + 4);
            checkBlockSize(block, headerSize + dataOffset + align16(dataSize));
            out = new byte[align16(dataSize)];
            Kirk.check(KirkEngine.kirk_CMD1(out, block, block.length));
        } else {
            dataSize = read32(block, DATA_SIZE_OFFSET);
            checkBlockSize(block, headerSize + align16(dataSize));
            out = new byte[align16(dataSize)];
            Kirk.check(keySeed == KirkKeySpec.FUSE ?
                    KirkEngine.kirk_CMD8(out, block, block.length) :
                    KirkEngine.kirk_CMD7(out, block, block.length));
        }

        return out.length == dataSize ? out : Arrays.copyOf(out, dataSize);
    }

    /** @throws IllegalBlockSizeException when the block is shorter than what its header says */
    private static void checkBlockSize(byte[] block, int size) throws IllegalBlockSizeException {
        if (size < 0 || block.length < size) {
            throw new IllegalBlockSizeException("truncated KIRK block: %d bytes, needs %d".formatted(block.length, size));
        }
    }
}
