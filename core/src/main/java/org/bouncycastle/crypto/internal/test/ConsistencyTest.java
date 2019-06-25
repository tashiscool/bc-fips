package org.bouncycastle.crypto.internal.test;

public interface ConsistencyTest<T>
{
    boolean hasTestPassed(T parameters) throws Exception;
}
