package org.bouncycastle.crypto.general;

import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.AsymmetricPublicKey;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.OutputSignerWithMessageRecovery;
import org.bouncycastle.crypto.OutputVerifierWithMessageRecovery;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.SignatureWithMessageRecoveryOperatorFactory;
import org.bouncycastle.crypto.fips.FipsStatus;
import org.bouncycastle.crypto.fips.FipsUnapprovedOperationError;

abstract class GuardedSignatureWithMessageRecoveryOperatorFactory<T extends Parameters>
    implements SignatureWithMessageRecoveryOperatorFactory<T>
{
    // package protect constructor
    GuardedSignatureWithMessageRecoveryOperatorFactory()
    {
        FipsStatus.isReady();
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved factory in approved only mode");
        }
    }

    public final OutputSignerWithMessageRecovery<T> createSigner(AsymmetricPrivateKey key, T parameters)
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved algorithm in approved only mode", parameters.getAlgorithm());
        }

        return doCreateSigner(key, parameters);
    }

    public final OutputVerifierWithMessageRecovery<T> createVerifier(AsymmetricPublicKey key, T parameters)
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved algorithm in approved only mode", parameters.getAlgorithm());
        }

        return doCreateVerifier(key, parameters);
    }

    protected abstract OutputSignerWithMessageRecovery<T> doCreateSigner(AsymmetricPrivateKey key, T parameter);

    protected abstract OutputVerifierWithMessageRecovery<T> doCreateVerifier(AsymmetricPublicKey key, T parameter);
}
