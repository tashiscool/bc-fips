package org.bouncycastle.crypto.internal.wrappers;

import org.bouncycastle.crypto.internal.BlockCipher;
import org.bouncycastle.crypto.internal.DataLengthException;
import org.bouncycastle.crypto.internal.InvalidCipherTextException;
import org.bouncycastle.util.Arrays;

/**
 * an implementation of the AES Key Wrapper from the NIST Key Wrap
 * Specification as described in RFC 3394/SP800-38F.
 * <p>
 * For further details see: <a href="http://www.ietf.org/rfc/rfc3394.txt">http://www.ietf.org/rfc/rfc3394.txt</a>
 * and  <a href="http://csrc.nist.gov/encryption/kms/key-wrap.pdf">http://csrc.nist.gov/encryption/kms/key-wrap.pdf</a>.
 */
public final class SP80038FWrapEngine
    extends SP80038FWrapper
{
    /**
     * Create a RFC 3394 WrapEngine specifying the direction for wrapping and unwrapping..
     *
     * @param engine the block cipher to be used for wrapping.
     * @param useReverseDirection true if engine should be used in decryption mode for wrapping, false otherwise.
     */
    public SP80038FWrapEngine(BlockCipher engine, boolean useReverseDirection)
    {
        super(engine, ivKW, useReverseDirection);
    }

    public String getAlgorithmName()
    {
        return engine.getAlgorithmName() + "/KW";
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

        int     n = inLen / delta;

        if ((n * delta) != inLen)
        {
            throw new DataLengthException("wrap data must be a multiple of " + delta + " bytes");
        }

        byte[]  block = new byte[inLen + iv.length];

        System.arraycopy(iv, 0, block, 0, iv.length);
        System.arraycopy(in, inOff, block, iv.length, inLen);

        return W(n, block);
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

        int     n = inLen / delta;

        if ((n * delta) != inLen)
        {
            throw new InvalidCipherTextException("unwrap data must be a multiple of " + delta + " bytes");
        }

        byte[]  block = new byte[inLen - iv.length];
        byte[]  a = new byte[iv.length];

        System.arraycopy(in, inOff, a, 0, iv.length);
        System.arraycopy(in, inOff + iv.length, block, 0, inLen - iv.length);

        invW(n, block, a);

        if (!Arrays.constantTimeAreEqual(a, iv))
        {
            throw new InvalidCipherTextException("checksum failed");
        }

        return block;
    }
}
