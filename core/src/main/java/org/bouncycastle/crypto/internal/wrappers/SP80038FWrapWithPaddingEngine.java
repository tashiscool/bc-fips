package org.bouncycastle.crypto.internal.wrappers;

import org.bouncycastle.crypto.internal.BlockCipher;
import org.bouncycastle.crypto.internal.InvalidCipherTextException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * an implementation of the AES Key Wrapper from the NIST Key Wrap
 * Specification as described in RFC 3394/SP800-38F.
 * <p>
 * For further details see: <a href="http://www.ietf.org/rfc/rfc3394.txt">http://www.ietf.org/rfc/rfc3394.txt</a>
 * and  <a href="http://csrc.nist.gov/encryption/kms/key-wrap.pdf">http://csrc.nist.gov/encryption/kms/key-wrap.pdf</a>.
 */
public final class SP80038FWrapWithPaddingEngine
    extends SP80038FWrapper
{
    /**
     * Create a RFC 3394 WrapEngine specifying the direction for wrapping and unwrapping..
     *
     * @param engine the block cipher to be used for wrapping.
     * @param useReverseDirection true if engine should be used in decryption mode for wrapping, false otherwise.
     */
    public SP80038FWrapWithPaddingEngine(BlockCipher engine, boolean useReverseDirection)
    {
        super(engine, ivKWP, useReverseDirection);
    }

    public String getAlgorithmName()
    {
        return engine.getAlgorithmName() + "/KWP";
    }

    public byte[] wrap(
        byte[]  in,
        int     inOff,
        int     inLen)
    {
        if (!forWrapping)
        {
            throw new IllegalStateException("not set for wrapping");
        }

        int     n = (inLen + 7) / 8;
        int     padLen = n * 8 - inLen;
        byte[]  block = new byte[inLen + iv.length + 4 + padLen];
        byte[]  pLen = Pack.intToBigEndian(inLen);

        System.arraycopy(iv, 0, block, 0, iv.length);
        System.arraycopy(pLen, 0, block, iv.length, pLen.length);
        System.arraycopy(in, inOff, block, iv.length + 4, inLen);

        if (n == 1)
        {
            engine.init(wrapCipherMode, param);

            // if the padded plaintext contains exactly 8 octets,
            // then prepend iv and encrypt using AES in ECB mode.

            engine.processBlock(block, 0, block, 0);

            return block;
        }
        else
        {
            return W(n, block);
        }
    }

    public byte[] unwrap(
        byte[]  in,
        int     inOff,
        int     inLen)
        throws InvalidCipherTextException
    {
        if (forWrapping)
        {
            throw new IllegalStateException("not set for unwrapping");
        }

        int     n = inLen / 8;

        if ((n * 8) != inLen)
        {
            throw new InvalidCipherTextException("unwrap data must be a multiple of 8 bytes");
        }

        byte[]  a = new byte[iv.length + 4];
        byte[]  b = new byte[inLen - a.length];

        if (n == 2)
        {
            byte[]  buf = new byte[engine.getBlockSize()];

            engine.init(!wrapCipherMode, param);

            engine.processBlock(in, inOff, buf, 0);

            System.arraycopy(buf, 0, a, 0, a.length);
            System.arraycopy(buf, a.length, b, 0, b.length);
        }
        else
        {
            System.arraycopy(in, inOff, a, 0, a.length);
            System.arraycopy(in, inOff + a.length, b, 0, inLen - a.length);

            invW(n, b, a);
        }

        byte[]  recIv = new byte[iv.length];

        System.arraycopy(a, 0, recIv, 0, recIv.length);

        int pLen = Pack.bigEndianToInt(a, 4);
        int padLen = 8 * (n - 1) - pLen;

        if (!Arrays.constantTimeAreEqual(recIv, iv))
        {
            throw new InvalidCipherTextException("checksum failed");
        }

        if (padLen < 0 || padLen > 7)
        {
            throw new InvalidCipherTextException("unwrap data has incorrect padding length");
        }

        byte[] block = new byte[pLen];

        System.arraycopy(b, 0, block, 0, pLen);

        boolean failed = false;
        for (int i = 1; i <= padLen; i++)
        {
            if (b[b.length - i] != 0)
            {
                failed = true;
            }
        }

        if (failed)
        {
            throw new InvalidCipherTextException("unwrap data has incorrect padding");
        }

        return block;
    }
}
