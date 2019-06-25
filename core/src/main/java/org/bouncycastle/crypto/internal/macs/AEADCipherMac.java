package org.bouncycastle.crypto.internal.macs;

import org.bouncycastle.crypto.internal.CipherParameters;
import org.bouncycastle.crypto.internal.DataLengthException;
import org.bouncycastle.crypto.internal.InvalidCipherTextException;
import org.bouncycastle.crypto.internal.Mac;
import org.bouncycastle.crypto.internal.modes.AEADBlockCipher;
import org.bouncycastle.crypto.internal.params.AEADParameters;
import org.bouncycastle.crypto.internal.params.KeyParameter;
import org.bouncycastle.crypto.internal.params.ParametersWithIV;

public class AEADCipherMac
    implements Mac
{
    private final AEADBlockCipher aeadCipher;
    private final int macLenInBits;

    public AEADCipherMac(AEADBlockCipher aeadCipher, int macLenInBits)
    {
        this.aeadCipher = aeadCipher;
        this.macLenInBits = macLenInBits;
    }

    public void init(CipherParameters params)
        throws IllegalArgumentException
    {
        if (params instanceof ParametersWithIV)
        {
            ParametersWithIV p = (ParametersWithIV)params;

            aeadCipher.init(true, new AEADParameters((KeyParameter)p.getParameters(), macLenInBits, p.getIV()));
        }
        else
        {
            throw new IllegalArgumentException("AEAD cipher based MAC needs nonce/IV");
        }
    }

    public String getAlgorithmName()
    {
        return aeadCipher.getAlgorithmName() + "MAC";
    }

    public int getMacSize()
    {
        return (macLenInBits + 7) / 8;
    }

    public void update(byte in)
        throws IllegalStateException
    {
        aeadCipher.processAADByte(in);
    }

    public void update(byte[] in, int inOff, int len)
        throws DataLengthException, IllegalStateException
    {
        aeadCipher.processAADBytes(in, inOff, len);
    }

    public int doFinal(byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {
        try
        {
            return aeadCipher.doFinal(out, outOff);
        }
        catch (InvalidCipherTextException e)
        {
            throw new IllegalStateException("Unable to create MAC tag:" + e.getMessage(), e);
        }
    }

    public void reset()
    {
        aeadCipher.reset();
    }
}
