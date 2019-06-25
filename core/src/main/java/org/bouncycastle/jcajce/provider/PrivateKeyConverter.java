package org.bouncycastle.jcajce.provider;

import java.security.InvalidKeyException;
import java.security.PrivateKey;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricPrivateKey;

interface PrivateKeyConverter<T extends AsymmetricPrivateKey>
{
    T convertKey(Algorithm algorithm, PrivateKey key)
        throws InvalidKeyException;
}
