package org.bouncycastle.crypto.internal;

public interface EngineProvider<T>
{
    T createEngine();
}
