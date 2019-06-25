package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.AsymmetricKeyPairGenerator;
import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.AsymmetricPublicKey;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.asymmetric.AsymmetricKeyPair;

/**
 * Base class for the FIPS approved mode AsymmetricKeyPairGenerator implementations.
 *
 * @param <T> the parameters type associated with the final implementation of this generator.
 */
public abstract class FipsAsymmetricKeyPairGenerator<T extends Parameters, P extends AsymmetricPublicKey, S extends AsymmetricPrivateKey>
    implements AsymmetricKeyPairGenerator
{
    private T parameters;

    // package protect construction
    FipsAsymmetricKeyPairGenerator(T parameters)
    {
        this.parameters = parameters;
    }

    public final T getParameters()
    {
        return parameters;
    }

    public abstract AsymmetricKeyPair<P,S> generateKeyPair();
}
