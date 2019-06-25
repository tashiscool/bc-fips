package org.bouncycastle.jcajce.provider;

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;

abstract class BaseKDFSecretKeyFactory
    extends SecretKeyFactorySpi
{
    @Override
    protected KeySpec engineGetKeySpec(SecretKey secretKey, Class aClass)
        throws InvalidKeySpecException
    {
        throw new InvalidKeySpecException("Key Deriving SecretKeyFactory only supports generateSecret");
    }

    @Override
    protected SecretKey engineTranslateKey(SecretKey secretKey)
        throws InvalidKeyException
    {
        throw new InvalidKeyException("Key Deriving SecretKeyFactory only supports generateSecret");
    }
}
