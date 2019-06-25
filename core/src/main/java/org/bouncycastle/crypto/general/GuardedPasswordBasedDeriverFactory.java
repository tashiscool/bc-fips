package org.bouncycastle.crypto.general;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.PasswordBasedDeriverFactory;
import org.bouncycastle.crypto.fips.FipsStatus;
import org.bouncycastle.crypto.fips.FipsUnapprovedOperationError;

abstract class GuardedPasswordBasedDeriverFactory<T extends Parameters>
    implements PasswordBasedDeriverFactory<T>
{
    GuardedPasswordBasedDeriverFactory()
    {
        FipsStatus.isReady();
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to create unapproved factory in approved only mode");
        }
    }
}
