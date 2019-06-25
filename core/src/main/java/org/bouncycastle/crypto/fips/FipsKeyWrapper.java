package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.KeyWrapper;
import org.bouncycastle.crypto.Parameters;

/**
 * Base class for the approved mode KeyWrapper implementations.
 *
 * @param <T> the parameters type associated with the final implementation of this key wrapper.
 */
public abstract class FipsKeyWrapper<T extends Parameters>
    implements KeyWrapper<T>
{
    // protect constructor
    FipsKeyWrapper()
    {

    }
}
