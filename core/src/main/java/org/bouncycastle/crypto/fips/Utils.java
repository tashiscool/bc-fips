package org.bouncycastle.crypto.fips;

import java.security.AccessController;
import java.security.Permission;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import java.util.concurrent.atomic.AtomicLong;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.internal.ValidatedSymmetricKey;
import org.bouncycastle.crypto.internal.params.AEADParameters;
import org.bouncycastle.crypto.internal.params.KeyParameter;
import org.bouncycastle.crypto.internal.params.KeyParameterImpl;
import org.bouncycastle.crypto.internal.params.ParametersWithIV;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.Pack;

class Utils
{
    // DRBG used by KAT tests
    static final SecureRandom testRandom = new TestSecureRandom();

    private static class TestSecureRandom
        extends SecureRandom
    {
        public TestSecureRandom()
        {
            super(new RandomSpi(), new RandomProvider());
        }

        private static class RandomSpi
            extends SecureRandomSpi
        {
            private final AtomicLong counter = new AtomicLong(System.currentTimeMillis());

            @Override
            protected void engineSetSeed(byte[] bytes)
            {
                // ignore
            }

            @Override
            protected void engineNextBytes(byte[] bytes)
            {
                SHA256Digest digest = new SHA256Digest();
                byte[] digestBuf = new byte[digest.getDigestSize()];
                byte[] counterBytes = new byte[8];
                int required = bytes.length;
                int offset = 0;

                while (required > 0)
                {
                    Pack.longToBigEndian(counter.getAndIncrement(), counterBytes, 0);

                    digest.update(counterBytes, 0, counterBytes.length);

                    digest.doFinal(digestBuf, 0);

                    if (required > digestBuf.length)
                    {
                        System.arraycopy(digestBuf, 0, bytes, offset, digestBuf.length);
                    }
                    else
                    {
                        System.arraycopy(digestBuf, 0, bytes, offset, required);
                    }

                    offset += digestBuf.length;
                    required -= digestBuf.length;
                }
            }

            @Override
            protected byte[] engineGenerateSeed(int numBytes)
            {
                byte[] rv = new byte[numBytes];

                engineNextBytes(rv);

                return rv;
            }
        }

        private static class RandomProvider
            extends Provider
        {
            RandomProvider()
            {
                super("BCFIPS_TEST_RNG", 1.0, "BCFIPS Test Secure Random Provider");
            }
        }
    }

    static void validateRandom(SecureRandom random, String message)
    {
        if (!(random instanceof FipsSecureRandom) && !(random.getProvider() instanceof BouncyCastleFipsProvider))
        {
            throw new FipsUnapprovedOperationError(message);
        }
    }

    static void validateRandom(SecureRandom random, FipsAlgorithm algorithm, String message)
    {
        if (!(random instanceof FipsSecureRandom) && !(random.getProvider() instanceof BouncyCastleFipsProvider))
        {
            throw new FipsUnapprovedOperationError(message, algorithm);
        }
    }

    static void validateRandom(SecureRandom random, int securityStrength, FipsAlgorithm algorithm, String message)
    {
        if (random instanceof FipsSecureRandom)
        {
            if (((FipsSecureRandom)random).getSecurityStrength() < securityStrength)
            {
                throw new FipsUnapprovedOperationError("FIPS SecureRandom security strength not as high as required for operation", algorithm);
            }
        }
        else if (random.getProvider() instanceof BouncyCastleFipsProvider)
        {
            if (((BouncyCastleFipsProvider)random.getProvider()).getDefaultRandomSecurityStrength() < securityStrength)
            {
                throw new FipsUnapprovedOperationError("FIPS SecureRandom security strength not as high as required for operation", algorithm);
            }
        }
        else
        {
            throw new FipsUnapprovedOperationError(message, algorithm);
        }

    }

    static void validateKeyGenRandom(SecureRandom random, int securityStrength, FipsAlgorithm algorithm)
    {
        validateRandom(random, securityStrength, algorithm, "Attempt to create key with unapproved RNG");
    }

    static void validateKeyPairGenRandom(SecureRandom random, int securityStrength, FipsAlgorithm algorithm)
    {
        validateRandom(random, securityStrength, algorithm, "Attempt to create key pair with unapproved RNG");
    }

    static void checkPermission(final Permission permission)
    {
        final SecurityManager securityManager = System.getSecurityManager();

        if (securityManager != null)
        {
            AccessController.doPrivileged(new PrivilegedAction<Object>()
            {
                public Object run()
                {
                    securityManager.checkPermission(permission);

                    return null;
                }
            });
        }
    }

    static void approvedModeCheck(boolean approvedMode, FipsAlgorithm algorithm)
    {
        if (approvedMode != CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            if (approvedMode)
            {
                throw new FipsUnapprovedOperationError("Attempt to use approved implementation in unapproved thread", algorithm);
            }
            else
            {
                throw new FipsUnapprovedOperationError("Attempt to use unapproved implementation in approved thread", algorithm);
            }
        }
    }

    static int getDefaultMacSize(Algorithm algorithm, int blockSize)
    {
        if (algorithm.getName().endsWith("GMAC") || algorithm.getName().endsWith("CMAC")
            || algorithm.getName().endsWith("GCM"))
        {
            return blockSize;
        }

        return blockSize / 2;
    }

    static KeyParameter getKeyParameter(ValidatedSymmetricKey sKey)
    {
        return new KeyParameterImpl(sKey.getKeyBytes());
    }

    static ParametersWithIV getParametersWithIV(ValidatedSymmetricKey sKey, byte[] iv)
    {
        return new ParametersWithIV(new KeyParameterImpl(sKey.getKeyBytes()), iv);
    }

    static AEADParameters getAEADParameters(ValidatedSymmetricKey sKey, byte[] nonce, int tagLen)
    {
        return new AEADParameters(new KeyParameterImpl(sKey.getKeyBytes()), tagLen, nonce);
    }

    public static int getAsymmetricSecurityStrength(int sizeInBits)
    {
        if (sizeInBits >= 15360)
        {
            return 256;
        }
        if (sizeInBits >= 7680)
        {
            return 192;
        }
        if (sizeInBits >= 3072)
        {
            return 128;
        }
        if (sizeInBits >= 2048)
        {
            return 112;
        }
        if (sizeInBits >= 1024)
        {
            return 80;
        }

        throw new FipsUnapprovedOperationError("Requested security strength unknown");
    }

    public static int getECCurveSecurityStrength(ECCurve curve)
    {
        int fieldSizeInBits = curve.getFieldSize();

        if (fieldSizeInBits >= 512)
        {
            return 256;
        }
        if (fieldSizeInBits >= 384)
        {
            return 192;
        }
        if (fieldSizeInBits >= 256)
        {
            return 128;
        }
        if (fieldSizeInBits >= 224)
        {
            return 112;
        }
        if (fieldSizeInBits >= 160)
        {
            return 80;
        }

        throw new FipsUnapprovedOperationError("Requested security strength unknown");
    }
}
