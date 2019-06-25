package org.bouncycastle.crypto.internal.io;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.fips.FipsOperationError;
import org.bouncycastle.crypto.fips.FipsStatus;
import org.bouncycastle.crypto.fips.FipsUnapprovedOperationError;

class Utils
{
    static void approvedModeCheck(boolean approvedMode, String algorithmName)
    {
        if (approvedMode != CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            if (approvedMode)
            {
                throw new FipsUnapprovedOperationError("Attempt to use approved implementation in unapproved thread: " + algorithmName);
            }
            else
            {
                throw new FipsUnapprovedOperationError("Attempt to use unapproved implementation in approved thread: " + algorithmName);
            }
        }
        if (FipsStatus.isErrorStatus())
        {
            throw new FipsOperationError(FipsStatus.getStatusMessage());
        }
    }
}
