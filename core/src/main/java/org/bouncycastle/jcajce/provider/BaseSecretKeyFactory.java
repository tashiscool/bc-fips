package org.bouncycastle.jcajce.provider;

import java.lang.reflect.Constructor;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.PasswordConverter;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.crypto.internal.ValidatedSymmetricKey;

class BaseSecretKeyFactory
    extends SecretKeyFactorySpi
{
    interface Validator
    {
        byte[] validated(byte[] keyBytes)
            throws InvalidKeySpecException;
    }

    protected final String algorithmName;
    protected final Algorithm algorithm;
    protected final Validator validator;

    BaseSecretKeyFactory(String algorithmName, Algorithm algorithm, Validator validator)
    {
        this.algorithmName = algorithmName;
        this.algorithm = algorithm;
        this.validator = validator;
    }

    @Override
    protected KeySpec engineGetKeySpec(
        SecretKey key,
        Class keySpec)
    throws InvalidKeySpecException
    {
        if (keySpec == null)
        {
            throw new InvalidKeySpecException("keySpec parameter is null");
        }

        if (key == null)
        {
            throw new InvalidKeySpecException("key parameter is null");
        }

        return genericGetKeySpec(key, keySpec);
    }

    protected KeySpec genericGetKeySpec(SecretKey key, Class keySpec)
        throws InvalidKeySpecException
    {
        if (SecretKeySpec.class.isAssignableFrom(keySpec))
        {
            return new SecretKeySpec(key.getEncoded(), algorithmName);
        }

        if (KeySpec.class.isAssignableFrom(keySpec))
        {
            // if the spec has a single byte[] constructor we take a punt...
            try
            {
                Class[] parameters = {byte[].class};

                Constructor c = keySpec.getConstructor(parameters);

                Object[] p = new Object[1];

                p[0] = validator.validated(key.getEncoded());

                return (KeySpec)c.newInstance(p);
            }
            catch (NoSuchMethodException e)
            {
                throw new InvalidKeySpecException("Unable to transform encoded key to KeySpec: " + keySpec.getName());
            }
            catch (Exception e)
            {
                throw new InvalidKeySpecException("Exception transforming to KeySpec: " + e.toString(), e);
            }
        }

        throw new InvalidKeySpecException("Passed in class is not a KeySpec: " + keySpec.getName());
    }

    @Override
    protected SecretKey engineTranslateKey(SecretKey secretKey)
        throws InvalidKeyException
    {
        if (secretKey == null)
        {
            throw new InvalidKeyException("Secret key parameter cannot be null");
        }

        try
        {
            return new SecretKeySpec(validator.validated(secretKey.getEncoded()), algorithmName);
        }
        catch (InvalidKeySpecException e)
        {
            throw new InvalidKeyException(e.getMessage());
        }
    }

    protected SecretKey engineGenerateSecret(
        KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof SecretKeySpec)
        {
            SecretKeySpec secKeySpec = (SecretKeySpec)keySpec;
            return new ProvSecretKeySpec(new ValidatedSymmetricKey(algorithm, validator.validated(secKeySpec.getEncoded())), algorithmName);
        }
        if (keySpec instanceof PBEKeySpec)
        {
            ProvPBEPBKDF2.BasePBKDF2 fact = new ProvPBEPBKDF2.BasePBKDF2(algorithmName, PasswordConverter.UTF8, FipsSHS.Algorithm.SHA256_HMAC);

            SecretKey key = fact.engineGenerateSecret(keySpec);
            return new ProvSecretKeySpec(new ValidatedSymmetricKey(algorithm, validator.validated(key.getEncoded())), algorithmName);
        }

        if (keySpec == null)
        {
            throw new InvalidKeySpecException("null KeySpec passed to SecretKeyFactory");
        }

        throw new InvalidKeySpecException("Unknown KeySpec passed to SecretKeyFactory: " + keySpec.getClass().getName());
    }
}

