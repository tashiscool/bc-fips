package org.bouncycastle.crypto.general;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.fips.FipsAlgorithm;
import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.Mac;

class Register
{
    private Register()
    {

    }

    static Digest createDigest(Algorithm algorithm)
    {
        if (algorithm instanceof FipsAlgorithm)
        {
            return (Digest)FipsRegister.getProvider((FipsAlgorithm)algorithm).createEngine();
        }

        return SecureHash.createDigest((GeneralDigestAlgorithm)algorithm);
    }

    static Mac createHMac(Algorithm algorithm)
    {
        if (algorithm instanceof FipsAlgorithm)
        {
            return (Mac)FipsRegister.getProvider((FipsAlgorithm)algorithm).createEngine();
        }

        return SecureHash.createHMac((GeneralDigestAlgorithm)algorithm);
    }
}
