package org.bouncycastle.jcajce.provider;

import java.security.AlgorithmParameterGeneratorSpi;
import java.security.SecureRandom;

abstract class BaseAlgorithmParameterGenerator
    extends AlgorithmParameterGeneratorSpi
{
    protected final BouncyCastleFipsProvider fipsProvider;

    protected SecureRandom random;
    protected int          strength = -1;

    BaseAlgorithmParameterGenerator(BouncyCastleFipsProvider fipsProvider, int strength)
    {
        this.fipsProvider = fipsProvider;
        this.strength = strength;
        this.random = fipsProvider.getDefaultSecureRandom();
    }

    protected void engineInit(
        int             strength,
        SecureRandom random)
    {
        this.strength = strength;
        this.random = random;
    }
}
