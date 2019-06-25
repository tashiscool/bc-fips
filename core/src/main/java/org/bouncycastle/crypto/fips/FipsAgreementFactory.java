package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.AgreementFactory;
import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.Parameters;

/**
 * Base class for the approved mode AgreementFactory implementations.
 *
 * @param <T> the parameters type associated with the final implementation of this factory.
 */
public abstract class FipsAgreementFactory<T extends Parameters>
    implements AgreementFactory<T>
{
    // package protect constructor
    FipsAgreementFactory()
    {
        FipsStatus.isReady();
    }

    public abstract FipsAgreement<T> createAgreement(AsymmetricPrivateKey key, T parameters);
}
