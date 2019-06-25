package org.bouncycastle.crypto.general;

import org.bouncycastle.crypto.AsymmetricKeyPairGenerator;
import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.AsymmetricPublicKey;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.asymmetric.AsymmetricKeyPair;
import org.bouncycastle.crypto.fips.FipsStatus;
import org.bouncycastle.crypto.fips.FipsUnapprovedOperationError;

abstract class GuardedAsymmetricKeyPairGenerator<T extends Parameters, P extends AsymmetricPublicKey, S extends AsymmetricPrivateKey>
    implements AsymmetricKeyPairGenerator<T, P, S>
{
    private T parameters;

    // package protect construction
    GuardedAsymmetricKeyPairGenerator(T parameters)
    {
        FipsStatus.isReady();
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved factory in approved only mode");
        }

        this.parameters = parameters;
    }

    public final T getParameters()
    {
        return parameters;
    }

    public final AsymmetricKeyPair<P, S> generateKeyPair()
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to generate key for unapproved algorithm in approved only mode");
        }

        return doGenerateKeyPair();
    }

    protected abstract AsymmetricKeyPair<P, S> doGenerateKeyPair();
}
