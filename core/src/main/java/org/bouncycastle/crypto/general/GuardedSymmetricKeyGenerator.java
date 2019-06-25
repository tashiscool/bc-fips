package org.bouncycastle.crypto.general;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.SymmetricKey;
import org.bouncycastle.crypto.SymmetricKeyGenerator;
import org.bouncycastle.crypto.fips.FipsStatus;
import org.bouncycastle.crypto.fips.FipsUnapprovedOperationError;

abstract class GuardedSymmetricKeyGenerator<T extends Parameters>
    implements SymmetricKeyGenerator
{
    // package protect constructor
    GuardedSymmetricKeyGenerator()
    {
        FipsStatus.isReady();
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved factory in approved only mode");
        }
    }

    public final SymmetricKey generateKey()
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to generate key for unapproved algorithm in approved only mode");
        }

        return doGenerateKey();
    }

    protected abstract SymmetricKey doGenerateKey();
}
