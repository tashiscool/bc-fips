package org.bouncycastle.crypto.internal.test;

public interface BasicKatTest<T>
{
    boolean hasTestPassed(T engine) throws Exception;
}
