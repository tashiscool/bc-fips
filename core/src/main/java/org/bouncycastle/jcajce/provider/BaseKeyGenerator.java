package org.bouncycastle.jcajce.provider;

import java.security.AccessController;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.PrivilegedAction;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;

import org.bouncycastle.crypto.SymmetricKey;
import org.bouncycastle.crypto.SymmetricKeyGenerator;
import org.bouncycastle.crypto.internal.ValidatedSymmetricKey;

final class BaseKeyGenerator
    extends KeyGeneratorSpi
{
    private final BouncyCastleFipsProvider fipsProvider;
    private final String                   algorithmName;
    private final KeyGeneratorCreator      keyGeneratorCreator;
    private final int                      defaultKeySize;
    private final boolean                  fixedKeySize;

    private SymmetricKeyGenerator   engine;

    BaseKeyGenerator(
        BouncyCastleFipsProvider fipsProvider,
        String algorithmName,
        int defaultKeySize,
        KeyGeneratorCreator keyGeneratorCreator)
    {
        this(fipsProvider, algorithmName, defaultKeySize, false, keyGeneratorCreator);
    }

    BaseKeyGenerator(
        BouncyCastleFipsProvider fipsProvider,
        String algorithmName,
        int defaultKeySize,
        boolean fixedKeySize,
        KeyGeneratorCreator keyGeneratorCreator)
    {
        this.fipsProvider = fipsProvider;
        this.algorithmName = algorithmName;
        this.defaultKeySize = defaultKeySize;
        this.keyGeneratorCreator = keyGeneratorCreator;
        this.fixedKeySize = fixedKeySize;
    }

    protected void engineInit(
        AlgorithmParameterSpec params,
        SecureRandom random)
    throws InvalidAlgorithmParameterException
    {
        throw new InvalidAlgorithmParameterException("No AlgorithmParameterSpec are supported");
    }

    protected void engineInit(
        SecureRandom random)
    {
        if (random != null)
        {
            engine = keyGeneratorCreator.createInstance(defaultKeySize, random);
        }
    }

    protected void engineInit(
        int          keySize,
        SecureRandom random)
    {
        if (fixedKeySize && keySize != defaultKeySize)
        {
            throw new InvalidParameterException("Attempt to change keysize for fixed size key generator");
        }

        try
        {
            if (random == null)
            {
                random = fipsProvider.getDefaultSecureRandom();
            }
            engine = keyGeneratorCreator.createInstance(keySize, random);
        }
        catch (IllegalArgumentException e)
        {
            throw new InvalidParameterException(e.getMessage());
        }
    }

    protected SecretKey engineGenerateKey()
    {
        if (engine == null)
        {
            engine = keyGeneratorCreator.createInstance(defaultKeySize, fipsProvider.getDefaultSecureRandom());
        }

        final SymmetricKey symmetricKey = engine.generateKey();

        return AccessController.doPrivileged(new PrivilegedAction<SecretKey>()
        {
            public SecretKey run()
            {
                return new ProvSecretKeySpec(new ValidatedSymmetricKey(symmetricKey.getAlgorithm(), symmetricKey.getKeyBytes()), algorithmName);
            }
        });
    }
}
