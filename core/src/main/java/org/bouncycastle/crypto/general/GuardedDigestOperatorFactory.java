package org.bouncycastle.crypto.general;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DigestOperatorFactory;
import org.bouncycastle.crypto.OutputDigestCalculator;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.fips.FipsStatus;
import org.bouncycastle.crypto.fips.FipsUnapprovedOperationError;

abstract class GuardedDigestOperatorFactory<T extends Parameters>
    implements DigestOperatorFactory<T>
{
    // package protect constructor
    GuardedDigestOperatorFactory()
    {
        FipsStatus.isReady();
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved factory in approved only mode");
        }
    }

    public abstract OutputDigestCalculator<T> createOutputDigestCalculator(final T parameter);
}
