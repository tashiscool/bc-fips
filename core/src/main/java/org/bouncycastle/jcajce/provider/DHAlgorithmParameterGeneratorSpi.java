package org.bouncycastle.jcajce.provider;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.DHGenParameterSpec;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.asymmetric.DHDomainParameters;
import org.bouncycastle.crypto.fips.FipsDH;
import org.bouncycastle.jcajce.spec.DHDomainParameterSpec;

class DHAlgorithmParameterGeneratorSpi
        extends java.security.AlgorithmParameterGeneratorSpi
{
    private final String algorithm;
    protected SecureRandom random;
    protected int strength = DHUtils.MIN_FIPS_SIZE;

    private int l = 0;

    private final BouncyCastleFipsProvider fipsProvider;

    public DHAlgorithmParameterGeneratorSpi(BouncyCastleFipsProvider fipsProvider, String algorithm)
    {
        this.fipsProvider = fipsProvider;
        this.algorithm = algorithm;
    }

    protected void engineInit(
        int strength,
        SecureRandom random)
    {
        this.strength = strength;
        this.random = random;
        if (CryptoServicesRegistrar.isInApprovedOnlyMode() && strength < DHUtils.MIN_FIPS_SIZE)
        {
            throw new InvalidParameterException("Attempt to initialize parameter generation of less than 2048 bits in approved mode");
        }
    }

    protected void engineInit(
        AlgorithmParameterSpec genParamSpec,
        SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        if (!(genParamSpec instanceof DHGenParameterSpec))
        {
            throw new InvalidAlgorithmParameterException(algorithm + " parameter generator requires a DHGenParameterSpec for initialization");
        }
        DHGenParameterSpec spec = (DHGenParameterSpec)genParamSpec;

        this.strength = spec.getPrimeSize();
        if (CryptoServicesRegistrar.isInApprovedOnlyMode() && strength < DHUtils.MIN_FIPS_SIZE)
        {
            throw new InvalidAlgorithmParameterException("Attempt to initialize parameter generation of less than 2048 bits in approved mode");
        }
        this.l = spec.getExponentSize();
        this.random = random;
    }

    protected AlgorithmParameters engineGenerateParameters()
    {
        FipsDH.DomainParametersGenerator pGen;

        if (random != null)
        {
            pGen = new FipsDH.DomainParametersGenerator(new FipsDH.DomainGenParameters(strength), random);
        }
        else
        {
            pGen = new FipsDH.DomainParametersGenerator(new FipsDH.DomainGenParameters(strength), fipsProvider.getDefaultSecureRandom());
        }

        DHDomainParameters p = pGen.generateDomainParameters();

        AlgorithmParameters params;

        try
        {
            params = AlgorithmParameters.getInstance(algorithm, fipsProvider);
            params.init(new DHDomainParameterSpec(p.getP(), p.getQ(), p.getG(), p.getJ(), l, p.getValidationParameters()));
        }
        catch (Exception e)
        {
            throw new IllegalStateException(e.getMessage(), e);
        }

        return params;
    }
}
