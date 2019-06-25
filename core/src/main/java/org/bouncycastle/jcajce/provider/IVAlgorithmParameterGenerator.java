package org.bouncycastle.jcajce.provider;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.IvParameterSpec;

class IVAlgorithmParameterGenerator
    extends BaseAlgorithmParameterGenerator
{
    private final String algorithm;
    private final int ivLength;

    IVAlgorithmParameterGenerator(BouncyCastleFipsProvider fipsProvider, String algorithm, int ivLength)
    {
        super(fipsProvider, 0);
        this.algorithm = algorithm;
        this.ivLength = ivLength;
    }

    protected void engineInit(
        AlgorithmParameterSpec genParamSpec,
        SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for " + algorithm + " parameter generation");
    }

    protected AlgorithmParameters engineGenerateParameters()
    {
        byte[]  iv = new byte[ivLength];

        random.nextBytes(iv);

        AlgorithmParameters params;

        try
        {
            params = AlgorithmParameters.getInstance(algorithm, fipsProvider);
            params.init(new IvParameterSpec(iv));
        }
        catch (Exception e)
        {
            throw new IllegalStateException(e.getMessage(), e);
        }

        return params;
    }
}
