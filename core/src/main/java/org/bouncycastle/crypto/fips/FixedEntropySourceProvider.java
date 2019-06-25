package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.EntropySource;
import org.bouncycastle.crypto.EntropySourceProvider;

class FixedEntropySourceProvider
        implements EntropySourceProvider
    {
        private final byte[] data;
        private final boolean isPredictionResistant;

        protected FixedEntropySourceProvider(byte[] data, boolean isPredictionResistant)
        {
            this.data = data;
            this.isPredictionResistant = isPredictionResistant;
        }

        public EntropySource get(final int bitsRequired)
        {
            return new EntropySource()
            {
                int index = 0;

                public boolean isPredictionResistant()
                {
                    return isPredictionResistant;
                }

                public byte[] getEntropy()
                {
                    byte[] rv = new byte[(bitsRequired + 7) / 8];

                    System.arraycopy(data, index, rv, 0, rv.length);

                    index += (bitsRequired + 7) / 8;

                    return rv;
                }

                public int entropySize()
                {
                    return bitsRequired;
                }
            };
        }
    }
