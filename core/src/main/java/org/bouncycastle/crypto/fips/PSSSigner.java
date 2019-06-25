/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.fips;

import java.security.SecureRandom;

import org.bouncycastle.crypto.InvalidSignatureException;
import org.bouncycastle.crypto.internal.AsymmetricBlockCipher;
import org.bouncycastle.crypto.internal.CipherParameters;
import org.bouncycastle.crypto.internal.CryptoException;
import org.bouncycastle.crypto.internal.DataLengthException;
import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.Signer;
import org.bouncycastle.crypto.internal.params.ParametersWithRandom;
import org.bouncycastle.crypto.internal.params.RsaKeyParameters;

/**
 * RSA-PSS as described in PKCS# 1 v 2.1.
 * <p>
 * Note: the usual value for the salt length is the number of
 * bytes in the hash function.
 */
class PSSSigner
    implements Signer
{
    static final public byte   TRAILER_IMPLICIT    = (byte)0xBC;

    private Digest                      contentDigest;
    private Digest                      mgfDigest;
    private AsymmetricBlockCipher       cipher;
    private SecureRandom                random;

    private int                         hLen;
    private int                         mgfhLen;
    private int                         sLen;
    private boolean                     sSet;
    private int                         emBits;
    private byte[]                      salt;
    private byte[]                      mDash;
    private byte[]                      block;
    private int                         trailer;

    public PSSSigner(
        AsymmetricBlockCipher   cipher,
        Digest                  contentDigest,
        Digest                  mgfDigest,
        int                     sLen,
        int                    trailer)
    {
        this.cipher = cipher;
        this.contentDigest = contentDigest;
        this.mgfDigest = mgfDigest;
        this.hLen = contentDigest.getDigestSize();
        this.mgfhLen = mgfDigest.getDigestSize();
        this.sLen = sLen;
        this.sSet = false;
        this.salt = new byte[sLen];
        this.mDash = new byte[8 + sLen + hLen];
        this.trailer = trailer;
    }

    public PSSSigner(
        AsymmetricBlockCipher   cipher,
        Digest                  contentDigest,
        Digest                  mgfDigest,
        byte[]                  salt,
        int                     trailer)
    {
        this.cipher = cipher;
        this.contentDigest = contentDigest;
        this.mgfDigest = mgfDigest;
        this.hLen = contentDigest.getDigestSize();
        this.mgfhLen = mgfDigest.getDigestSize();
        this.sLen = salt.length;
        this.sSet = true;
        this.salt = salt;
        this.mDash = new byte[8 + sLen + hLen];
        this.trailer = trailer;
    }

    public void init(
        boolean                 forSigning,
        CipherParameters        param)
    {
        CipherParameters  params;

        if (param instanceof ParametersWithRandom)
        {
            ParametersWithRandom    p = (ParametersWithRandom)param;

            params = p.getParameters();
            random = p.getRandom();
        }
        else
        {
            params = param;
            if (forSigning && salt != null)
            {
                throw new IllegalArgumentException("No random provided where one required.");
            }
        }

        cipher.init(forSigning, param);

        RsaKeyParameters kParam;

        if (params instanceof RsaBlindingParameters)
        {
            kParam = ((RsaBlindingParameters)params).getPublicKey();
        }
        else
        {
            kParam = (RsaKeyParameters)params;
        }
        
        emBits = kParam.getModulus().bitLength() - 1;

        if (emBits < (8 * hLen + 8 * sLen + 9))
        {
            throw new IllegalArgumentException("key too small for specified hash and salt lengths");
        }

        block = new byte[(emBits + 7) / 8];

        reset();
    }

    /**
     * clear possible sensitive data
     */
    private void clearBlock(
        byte[]  block)
    {
        for (int i = 0; i != block.length; i++)
        {
            block[i] = 0;
        }
    }

    /**
     * update the internal digest with the byte b
     */
    public void update(
        byte    b)
    {
        contentDigest.update(b);
    }

    /**
     * update the internal digest with the byte array in
     */
    public void update(
        byte[]  in,
        int     off,
        int     len)
    {
        contentDigest.update(in, off, len);
    }

    /**
     * reset the internal state
     */
    public void reset()
    {
        contentDigest.reset();
    }

    /**
     * generate a signature for the message we've been loaded with using
     * the key we were initialised with.
     */
    public byte[] generateSignature()
        throws CryptoException, DataLengthException
    {
        contentDigest.doFinal(mDash, mDash.length - hLen - sLen);

        if (sLen != 0)
        {
            if (!sSet)
            {
                random.nextBytes(salt);
            }

            System.arraycopy(salt, 0, mDash, mDash.length - sLen, sLen);
        }

        byte[]  h = new byte[hLen];

        contentDigest.update(mDash, 0, mDash.length);

        contentDigest.doFinal(h, 0);

        block[block.length - sLen - 1 - hLen - 1] = 0x01;
        System.arraycopy(salt, 0, block, block.length - sLen - hLen - 1, sLen);

        byte[] dbMask = maskGeneratorFunction1(h, 0, h.length, block.length - hLen - 1);
        for (int i = 0; i != dbMask.length; i++)
        {
            block[i] ^= dbMask[i];
        }

        block[0] &= (0xff >> ((block.length * 8) - emBits));

        System.arraycopy(h, 0, block, block.length - hLen - 1, hLen);

        block[block.length - 1] = (byte)trailer;     // TODO: accomodate longer trailers

        byte[]  b = cipher.processBlock(block, 0, block.length);

        clearBlock(block);

        return b;
    }

    /**
     * return true if the internal state represents the signature described
     * in the passed in array.
     */
    public boolean verifySignature(
        byte[]      signature)
        throws InvalidSignatureException
    {
        contentDigest.doFinal(mDash, mDash.length - hLen - sLen);

        try
        {
            byte[] b = cipher.processBlock(signature, 0, signature.length);
            System.arraycopy(b, 0, block, block.length - b.length, b.length);
        }
        catch (Exception e)
        {
            throw new InvalidSignatureException("Unable to process signature: " + e.getMessage(), e);
        }

        if (block[block.length - 1] != trailer)
        {
            clearBlock(block);
            return false;
        }

        byte[] dbMask = maskGeneratorFunction1(block, block.length - hLen - 1, hLen, block.length - hLen - 1);

        for (int i = 0; i != dbMask.length; i++)
        {
            block[i] ^= dbMask[i];
        }

        block[0] &= (0xff >> ((block.length * 8) - emBits));

        for (int i = 0; i != block.length - hLen - sLen - 2; i++)
        {
            if (block[i] != 0)
            {
                clearBlock(block);
                return false;
            }
        }

        if (block[block.length - hLen - sLen - 2] != 0x01)
        {
            clearBlock(block);
            return false;
        }

        if (sSet)
        {
            System.arraycopy(salt, 0, mDash, mDash.length - sLen, sLen);
        }
        else
        {
            System.arraycopy(block, block.length - sLen - hLen - 1, mDash, mDash.length - sLen, sLen);
        }

        contentDigest.update(mDash, 0, mDash.length);
        contentDigest.doFinal(mDash, mDash.length - hLen);

        for (int i = block.length - hLen - 1, j = mDash.length - hLen;
                                                 j != mDash.length; i++, j++)
        {
            if ((block[i] ^ mDash[j]) != 0)
            {
                clearBlock(mDash);
                clearBlock(block);
                return false;
            }
        }

        clearBlock(mDash);
        clearBlock(block);

        return true;
    }

    /**
     * int to octet string.
     */
    private void ItoOSP(
        int     i,
        byte[]  sp)
    {
        sp[0] = (byte)(i >>> 24);
        sp[1] = (byte)(i >>> 16);
        sp[2] = (byte)(i >>> 8);
        sp[3] = (byte)(i >>> 0);
    }

    /**
     * mask generator function, as described in PKCS1v2.
     */
    private byte[] maskGeneratorFunction1(
        byte[]  Z,
        int     zOff,
        int     zLen,
        int     length)
    {
        byte[]  mask = new byte[length];
        byte[]  hashBuf = new byte[mgfhLen];
        byte[]  C = new byte[4];
        int     counter = 0;

        mgfDigest.reset();

        while (counter < (length / mgfhLen))
        {
            ItoOSP(counter, C);

            mgfDigest.update(Z, zOff, zLen);
            mgfDigest.update(C, 0, C.length);
            mgfDigest.doFinal(hashBuf, 0);

            System.arraycopy(hashBuf, 0, mask, counter * mgfhLen, mgfhLen);

            counter++;
        }

        if ((counter * mgfhLen) < length)
        {
            ItoOSP(counter, C);

            mgfDigest.update(Z, zOff, zLen);
            mgfDigest.update(C, 0, C.length);
            mgfDigest.doFinal(hashBuf, 0);

            System.arraycopy(hashBuf, 0, mask, counter * mgfhLen, mask.length - (counter * mgfhLen));
        }

        return mask;
    }
}
