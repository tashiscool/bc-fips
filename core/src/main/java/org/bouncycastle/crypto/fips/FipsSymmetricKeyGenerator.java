package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.SymmetricKeyGenerator;
import org.bouncycastle.crypto.SymmetricSecretKey;

/**
 * Base class for the FIPS approved mode SymmetricKeyGenerator implementations.
 *
 * @param <T> the parameters type associated with the final implementation of this generator.
 */
public abstract class FipsSymmetricKeyGenerator<T extends SymmetricSecretKey>
    implements SymmetricKeyGenerator<T>
{
    // package protect constructor
    FipsSymmetricKeyGenerator()
    {
       FipsStatus.isReady();
    }
}
