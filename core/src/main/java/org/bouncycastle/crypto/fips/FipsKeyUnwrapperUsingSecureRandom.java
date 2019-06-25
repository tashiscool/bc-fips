package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.KeyUnwrapperUsingSecureRandom;
import org.bouncycastle.crypto.Parameters;

/**
 * Base class for the approved mode KeyUnwrapper implementations which need a SecureRandom.
 *
 * @param <T> the parameters type associated with the final implementation of this key unwrapper.
 */
public abstract class FipsKeyUnwrapperUsingSecureRandom<T extends Parameters>
    extends FipsKeyUnwrapper<T>
    implements KeyUnwrapperUsingSecureRandom<T>
{
    // protect constructor
    FipsKeyUnwrapperUsingSecureRandom()
    {

    }
}
