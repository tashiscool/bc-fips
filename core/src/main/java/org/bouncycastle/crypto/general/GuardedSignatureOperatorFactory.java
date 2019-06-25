package org.bouncycastle.crypto.general;

import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.AsymmetricPublicKey;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.OutputSigner;
import org.bouncycastle.crypto.OutputVerifier;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.SignatureOperatorFactory;
import org.bouncycastle.crypto.fips.FipsStatus;
import org.bouncycastle.crypto.fips.FipsUnapprovedOperationError;

abstract class GuardedSignatureOperatorFactory<T extends Parameters>
    implements SignatureOperatorFactory<T>
{
    // package protect constructor
    GuardedSignatureOperatorFactory()
    {
        FipsStatus.isReady();
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved factory in approved only mode");
        }
    }

    public final OutputSigner<T> createSigner(AsymmetricPrivateKey key, T parameters)
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved algorithm in approved only mode", parameters.getAlgorithm());
        }

        return doCreateSigner(key, parameters);
    }

    public final OutputVerifier<T> createVerifier(AsymmetricPublicKey key, T parameters)
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved algorithm in approved only mode", parameters.getAlgorithm());
        }

        return doCreateVerifier(key, parameters);
    }

    protected abstract OutputSigner<T> doCreateSigner(AsymmetricPrivateKey key, T parameter);

    protected abstract OutputVerifier<T> doCreateVerifier(AsymmetricPublicKey key, T parameter);
}
