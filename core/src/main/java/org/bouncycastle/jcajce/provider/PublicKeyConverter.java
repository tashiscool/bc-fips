package org.bouncycastle.jcajce.provider;

import java.security.InvalidKeyException;
import java.security.PublicKey;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricPublicKey;

interface PublicKeyConverter<T extends AsymmetricPublicKey>
{
    T convertKey(Algorithm algorithm, PublicKey key)
        throws InvalidKeyException;
}
