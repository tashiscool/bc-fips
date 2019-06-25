package org.bouncycastle.crypto.general;

import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.internal.CipherParameters;
import org.bouncycastle.crypto.internal.Mac;
import org.bouncycastle.crypto.internal.PBEParametersGenerator;
import org.bouncycastle.crypto.internal.params.KeyParameterImpl;
import org.bouncycastle.crypto.internal.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

/**
 * Generator for PBE derived keys and ivs as defined by PKCS 5 V2.0 Scheme 2.
 * This generator uses a SHA-1 HMac as the calculation function.
 * <p>
 * The document this implementation is based on can be found at
 * <a href=http://www.rsasecurity.com/rsalabs/pkcs/pkcs-5/index.html>
 * RSA's PKCS5 Page</a>
 */
class PKCS5S2ParametersGenerator<T extends Parameters>
    extends PBEParametersGenerator<T>
{
    private Mac hMac;
    private byte[] state;

    public PKCS5S2ParametersGenerator(T parameters, Mac hMac)
    {
        super(parameters);

        this.hMac = hMac;
        this.state = new byte[hMac.getMacSize()];
    }

    private void F(
        byte[]  S,
        int     c,
        byte[]  iBuf,
        byte[]  out,
        int     outOff)
    {
        if (c == 0)
        {
            throw new IllegalArgumentException("iteration count must be at least 1.");
        }

        if (S != null)
        {
            hMac.update(S, 0, S.length);
        }

        hMac.update(iBuf, 0, iBuf.length);
        hMac.doFinal(state, 0);

        System.arraycopy(state, 0, out, outOff, state.length);

        for (int count = 1; count < c; count++)
        {
            hMac.update(state, 0, state.length);
            hMac.doFinal(state, 0);

            for (int j = 0; j != state.length; j++)
            {
                out[outOff + j] ^= state[j];
            }
        }
    }

    private byte[] generateDerivedKey(
        int dkLen)
    {
        int     hLen = hMac.getMacSize();
        int     l = (dkLen + hLen - 1) / hLen;
        byte[]  iBuf = new byte[4];
        byte[]  outBytes = new byte[l * hLen];
        int     outPos = 0;

        CipherParameters param = new KeyParameterImpl(password);

        hMac.init(param);

        for (int i = 1; i <= l; i++)
        {
            // Increment the value in 'iBuf'
            int pos = 3;
            while (++iBuf[pos] == 0)
            {
                --pos;
            }

            F(salt, iterationCount, iBuf, outBytes, outPos);
            outPos += hLen;
        }

        return outBytes;
    }

    /**
     * Generate a key parameter derived from the password, salt, and iteration
     * count we are currently initialised with.
     *
     * @param keySize the size of the key we want (in bits)
     * @return a KeyParameter object.
     */
    public CipherParameters generateDerivedParameters(
        int keySize)
    {
        keySize = keySize / 8;

        byte[] material = deriveKey(KeyType.CIPHER, keySize);

        return new KeyParameterImpl(material);
    }

    /**
     * Generate a key with initialisation vector parameter derived from
     * the password, salt, and iteration count we are currently initialised
     * with.
     *
     * @param keySize the size of the key we want (in bits)
     * @param ivSize the size of the iv we want (in bits)
     * @return a ParametersWithIV object.
     */
    public CipherParameters generateDerivedParameters(
        int     keySize,
        int     ivSize)
    {
        keySize = keySize / 8;
        ivSize = ivSize / 8;

        byte[][] material = deriveKeyAndIV(KeyType.CIPHER, keySize, ivSize);

        return new ParametersWithIV(new KeyParameterImpl(material[0]), material[1], keySize, ivSize);
    }

    /**
     * Generate a key parameter for use with a MAC derived from the password,
     * salt, and iteration count we are currently initialised with.
     *
     * @param keySize the size of the key we want (in bits)
     * @return a KeyParameter object.
     */
    public CipherParameters generateDerivedMacParameters(
        int keySize)
    {
        return generateDerivedParameters(keySize);
    }

    public byte[] deriveKey(KeyType keyType, int keySizeInBytes)
    {
        switch (keyType)
        {
        case CIPHER:
        case MAC:
            return Arrays.copyOfRange(generateDerivedKey(keySizeInBytes), 0, keySizeInBytes);
        default:
            throw new IllegalStateException("Unknown type in deriveKey: " + keyType.name());
        }
    }

    public byte[][] deriveKeyAndIV(KeyType keyType, int keySizeInBytes, int ivSizeInBytes)
    {
        byte[][] rv = new byte[2][];

        byte[]  dKey = generateDerivedKey(keySizeInBytes + ivSizeInBytes);

        switch (keyType)
        {
        case CIPHER:
        case MAC:
            rv[0] = Arrays.copyOfRange(dKey, 0, keySizeInBytes);
            break;
        default:
            throw new IllegalStateException("Unknown type in deriveKeyAndIV: " + keyType.name());
        }

        rv[1] = Arrays.copyOfRange(dKey, keySizeInBytes, keySizeInBytes + ivSizeInBytes);

        return rv;
    }
}
