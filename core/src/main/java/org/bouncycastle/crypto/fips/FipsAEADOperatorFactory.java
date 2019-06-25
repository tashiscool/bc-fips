package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.AEADOperatorFactory;
import org.bouncycastle.crypto.SymmetricKey;

/**
 * Base class for the approved mode AEADOperatorFactory implementations.
 *
 * @param <T> the parameters type associated with the final implementation of this factory.
 */
public abstract class FipsAEADOperatorFactory<T extends FipsParameters>
    implements AEADOperatorFactory<T>
{
    // package protect constructor
    FipsAEADOperatorFactory()
    {
        FipsStatus.isReady();
    }

    public abstract FipsOutputAEADEncryptor<T> createOutputAEADEncryptor(SymmetricKey key, T parameter);

    public abstract FipsOutputAEADDecryptor<T> createOutputAEADDecryptor(SymmetricKey key, T parameter);

    public abstract FipsInputAEADDecryptor<T> createInputAEADDecryptor(SymmetricKey key, T parameter);
}
