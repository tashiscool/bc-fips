package org.bouncycastle.crypto.general;

import org.bouncycastle.crypto.EntropySource;
import org.bouncycastle.crypto.fips.FipsStatus;
import org.bouncycastle.util.Arrays;

class ContinuousTestingEntropySource
    implements EntropySource
{
    private final EntropySource entropySource;

    private byte[] buf;

    public ContinuousTestingEntropySource(EntropySource entropySource)
    {
        this.entropySource = entropySource;
    }

    public boolean isPredictionResistant()
    {
        return entropySource.isPredictionResistant();
    }

    public byte[] getEntropy()
    {
        synchronized (this)
        {
            byte[] nxt;

            if (buf == null)
            {
                buf = entropySource.getEntropy();
            }

            nxt = entropySource.getEntropy();

            if (Arrays.areEqual(nxt, buf))
            {
                throw new IllegalStateException("Duplicate block detected in EntropySource output");
            }

            System.arraycopy(nxt, 0, buf, 0, buf.length);

            return nxt;
        }
    }

    public int entropySize()
    {
        return entropySource.entropySize();
    }
}
