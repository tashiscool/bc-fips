package org.bouncycastle.crypto.general;

abstract class VariantKatTest<T>
{
    void fail(String message)
    {
        throw new SelfTestExecutor.TestFailedException(message);
    }

    abstract void evaluate(T engine) throws Exception;
}
