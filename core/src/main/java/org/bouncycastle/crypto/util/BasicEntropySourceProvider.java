package org.bouncycastle.crypto.util;

import java.security.SecureRandom;

import org.bouncycastle.crypto.EntropySource;
import org.bouncycastle.crypto.EntropySourceProvider;
import org.bouncycastle.crypto.fips.FipsSecureRandom;
import org.bouncycastle.crypto.general.GeneralSecureRandom;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

/**
 * An EntropySourceProvider where entropy generation is based on a SecureRandom output using SecureRandom.generateSeed() in
 * the case of a JDK SecureRandom or SecureRandom.nextBytes() in the case of a FipsSecureRandom, or a GeneralSecureRandom.
 */
public class BasicEntropySourceProvider
    implements EntropySourceProvider
{
    private final SecureRandom _sr;
    private final boolean      _predictionResistant;

    /**
     * Create a entropy source provider based on the passed in SecureRandom.
     *
     * @param random the SecureRandom to base EntropySource construction on.
     * @param isPredictionResistant boolean indicating if the SecureRandom is based on prediction resistant entropy or not (true if it is).
     */
    public BasicEntropySourceProvider(SecureRandom random, boolean isPredictionResistant)
    {
        _sr = random;
        _predictionResistant = isPredictionResistant;
    }

    /**
     * Return an entropy source that will create bitsRequired bits of entropy on
     * each invocation of getEntropy().
     *
     * @param bitsRequired size (in bits) of entropy to be created by the provided source.
     * @return an EntropySource that generates bitsRequired bits of entropy on each call to its getEntropy() method.
     */
    public EntropySource get(final int bitsRequired)
    {
        return new EntropySource()
        {
            public boolean isPredictionResistant()
            {
                return _predictionResistant;
            }

            public byte[] getEntropy()
            {
                // is our RNG suitable for use for seeding?
                if (_sr instanceof FipsSecureRandom || _sr instanceof GeneralSecureRandom || _sr.getProvider() instanceof BouncyCastleFipsProvider)
                {
                    byte[] rv = new byte[(bitsRequired + 7) / 8];

                    _sr.nextBytes(rv);

                    return rv;
                }

                // fall back to the seed generator
                return _sr.generateSeed((bitsRequired + 7) / 8);
            }

            public int entropySize()
            {
                return bitsRequired;
            }
        };
    }
}
