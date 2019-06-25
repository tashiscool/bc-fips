package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.EncapsulatingSecretGenerator;

/**
 * Base class for the approved mode EncapsulatingSecretGenerator implementations.
 *
 * @param <T> the parameters type associated with the final implementation of this generator.
 */
public abstract class FipsEncapsulatingSecretGenerator<T extends FipsParameters>
    implements EncapsulatingSecretGenerator<T>
{
    // protect constructor
    FipsEncapsulatingSecretGenerator()
    {
    }
}
