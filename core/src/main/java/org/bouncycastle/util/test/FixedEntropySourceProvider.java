package org.bouncycastle.util.test;

import org.bouncycastle.crypto.EntropySource;
import org.bouncycastle.crypto.EntropySourceProvider;

/**
 * An "entropy" provider which returns pre-defined data on request.
 */
public class FixedEntropySourceProvider
    implements EntropySourceProvider
{
    private final byte[] data;
    private final boolean isPredictionResistant;

    /**
     * Base constructor.
     *
     * @param data the data that will be returned by EntropySources created by this provider.
     * @param isPredictionResistant true if the EntropySource should be marked as prediction resistant, false otherwise.
     */
    public FixedEntropySourceProvider(byte[] data, boolean isPredictionResistant)
    {
        this.data = data;
        this.isPredictionResistant = isPredictionResistant;
    }

    /**
     * Return an EntropySource based on the data provided to this object.
     *
     * @param bitsRequired the size of the block of entropy required.
     * @return a new EntropySource.
     */
    public EntropySource get(final int bitsRequired)
    {
        return new EntropySource()
        {
            boolean first = true;
            int index = 0;

            public boolean isPredictionResistant()
            {
                return isPredictionResistant;
            }

            public byte[] getEntropy()
            {
                byte[] rv = new byte[(bitsRequired + 7) / 8];

                System.arraycopy(data, index, rv, 0, rv.length);

                // we assume continuous testing
                if (first)
                {
                    for (int i = 0; i != rv.length; i++)
                    {
                        rv[i] ^= 0xff;
                    }
                    first = false;
                }
                else
                {
                    index += (bitsRequired + 7) / 8;
                }

                return rv;
            }

            public int entropySize()
            {
                return bitsRequired;
            }
        };
    }
}
