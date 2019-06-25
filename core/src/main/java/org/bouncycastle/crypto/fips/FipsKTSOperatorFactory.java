package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.KTSOperatorFactory;
import org.bouncycastle.crypto.Key;

/**
 * Base class for the approved mode KTSOperatorFactory implementations.
 *
 * @param <T> the parameters type associated with the final implementation of this factory.
 */
public abstract class FipsKTSOperatorFactory<T extends FipsParameters>
    implements KTSOperatorFactory<T>
{
    // protect constructor
    FipsKTSOperatorFactory()
    {
        FipsStatus.isReady();
    }

    public abstract FipsEncapsulatingSecretGenerator<T> createGenerator(Key key, T parameters);

    public abstract FipsEncapsulatedSecretExtractor<T> createExtractor(Key key, T parameters);
}
