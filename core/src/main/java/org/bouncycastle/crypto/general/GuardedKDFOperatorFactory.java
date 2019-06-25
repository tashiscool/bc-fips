package org.bouncycastle.crypto.general;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.KDFOperatorFactory;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.fips.FipsStatus;
import org.bouncycastle.crypto.fips.FipsUnapprovedOperationError;

abstract class GuardedKDFOperatorFactory<T extends Parameters>
    implements KDFOperatorFactory<T>
{
    // package protect constructor
    GuardedKDFOperatorFactory()
    {
        FipsStatus.isReady();
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved factory in approved only mode");
        }
    }
}
