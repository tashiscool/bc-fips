package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.DigestAlgorithm;

/**
 * Marker class for a FIPS approved digest algorithm
 */
public class FipsDigestAlgorithm
    extends FipsAlgorithm
    implements DigestAlgorithm
{
    FipsDigestAlgorithm(String name, Enum basicVariation)
    {
        super(name, basicVariation);
    }
}
