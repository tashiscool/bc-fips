package org.bouncycastle.crypto.fips;

abstract class VariantInternalKatTest
{
    protected final FipsAlgorithm algorithm;

    protected VariantInternalKatTest(FipsAlgorithm algorithm)
    {
        this.algorithm = algorithm;
    }

    void fail(String message)
    {
        throw new SelfTestExecutor.TestFailedException(message);
    }

    abstract void evaluate() throws Exception;

    public FipsAlgorithm getAlgorithm()
    {
        return algorithm;
    }
}
