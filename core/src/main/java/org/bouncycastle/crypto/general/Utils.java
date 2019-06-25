package org.bouncycastle.crypto.general;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.IllegalKeyException;
import org.bouncycastle.crypto.fips.FipsUnapprovedOperationError;
import org.bouncycastle.crypto.internal.ValidatedSymmetricKey;
import org.bouncycastle.crypto.internal.params.KeyParameter;
import org.bouncycastle.crypto.internal.params.KeyParameterImpl;

class Utils
{
    static final SecureRandom testRandom = new SecureRandom();

    static void approveModeCheck(Algorithm algorithm)
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            throw new FipsUnapprovedOperationError("Attempt to use unapproved algorithm in approved only mode", algorithm);
        }
    }

    static KeyParameter getKeyParameter(ValidatedSymmetricKey sKey)
    {
        return new KeyParameterImpl(sKey.getKeyBytes());
    }

    static void checkKeyAlgorithm(ValidatedSymmetricKey key, Algorithm generalAlgorithm, Algorithm paramAlgorithm)
    {
        Algorithm keyAlgorithm = key.getAlgorithm();

        if (!keyAlgorithm.equals(generalAlgorithm))
        {
            if (!keyAlgorithm.equals(paramAlgorithm))
            {
                throw new IllegalKeyException("Key not for appropriate algorithm");
            }
        }
    }

    static int bitsToBytes(int bits)
    {
        return (bits + 7) / 8;
    }

    static int getDefaultMacSize(Algorithm algorithm, int blockSize)
    {
        if (algorithm.getName().endsWith("GMAC") || algorithm.getName().endsWith("/CMAC")
            || algorithm.getName().endsWith("GCM") || algorithm.getName().endsWith("OCB")
            || algorithm.getName().endsWith("ISO979ALG3"))
        {
            return blockSize;
        }

        return blockSize / 2;
    }
}
