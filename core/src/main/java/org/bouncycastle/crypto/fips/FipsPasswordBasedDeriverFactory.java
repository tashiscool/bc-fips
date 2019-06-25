package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.PasswordBasedDeriverFactory;

/**
 * Base class for the approved mode PasswordBasedDeriverFactory implementations.
 *
 * @param <T> the parameters type associated with the final implementation of this factory.
 */
public abstract class FipsPasswordBasedDeriverFactory<T extends FipsParameters>
    implements PasswordBasedDeriverFactory<T>
{
    // package protect constructor.
    FipsPasswordBasedDeriverFactory()
    {
        FipsStatus.isReady();
    }

}
