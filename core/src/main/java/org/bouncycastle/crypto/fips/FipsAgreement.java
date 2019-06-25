package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.Agreement;
import org.bouncycastle.crypto.AsymmetricPublicKey;
import org.bouncycastle.crypto.Parameters;

/**
 * Base class for the FIPS approved mode Agreement implementations.
 *
 * @param <T> the parameters type associated with the final implementation of this key agreement.
 */
public abstract class FipsAgreement<T extends Parameters>
    implements Agreement<T>
{
    // package protect construction
    FipsAgreement()
    {
    }

    public abstract T getParameters();

    public abstract byte[] calculate(AsymmetricPublicKey key);
}
