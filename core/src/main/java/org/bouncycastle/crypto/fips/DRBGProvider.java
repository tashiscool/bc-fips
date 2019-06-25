package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.EntropySource;

interface DRBGProvider
{
    DRBG get(EntropySource entropySource);
}
