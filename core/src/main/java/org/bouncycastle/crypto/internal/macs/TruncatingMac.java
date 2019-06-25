package org.bouncycastle.crypto.internal.macs;

import org.bouncycastle.crypto.internal.CipherParameters;
import org.bouncycastle.crypto.internal.DataLengthException;
import org.bouncycastle.crypto.internal.Mac;

public class TruncatingMac
    implements Mac
{
    private final Mac mac;
    private final int macSizeInBits;

    public TruncatingMac(Mac mac, int macSizeInBits)
    {
        this.mac = mac;
        this.macSizeInBits = macSizeInBits;
    }

    public void init(CipherParameters params)
        throws IllegalArgumentException
    {
        mac.init(params);
    }

    public String getAlgorithmName()
    {
        return mac.getAlgorithmName();
    }

    public int getMacSize()
    {
        return macSizeInBits / 8;
    }

    public void update(byte in)
        throws IllegalStateException
    {
        mac.update(in);
    }

    public void update(byte[] in, int inOff, int len)
        throws DataLengthException, IllegalStateException
    {
        mac.update(in, inOff, len);
    }

    public int doFinal(byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {
        byte[] res = new byte[mac.getMacSize()];

        mac.doFinal(res, 0);

        System.arraycopy(res, 0, out, outOff, macSizeInBits / 8);

        return macSizeInBits / 8;
    }

    public void reset()
    {

    }
}
