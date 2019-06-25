package org.bouncycastle.jcajce.provider;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

abstract class BaseKeyFactory
    extends java.security.KeyFactorySpi
    implements AsymmetricKeyInfoConverter
{
    protected PrivateKey engineGeneratePrivate(
        KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof PKCS8EncodedKeySpec)
        {
            try
            {
                return generatePrivate(PrivateKeyInfo.getInstance(((PKCS8EncodedKeySpec)keySpec).getEncoded()));
            }
            catch (Exception e)
            {
                throw new InvalidKeySpecException(e.getMessage(), e);
            }
        }
        else if (keySpec != null)
        {
            throw new InvalidKeySpecException("keySpec for PrivateKey not recognized: " + keySpec.getClass().getName());
        }
        else
        {
            throw new InvalidKeySpecException("null keySpec passed for PrivateKey");
        }
    }

    protected PublicKey engineGeneratePublic(
        KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof X509EncodedKeySpec)
        {
            try
            {
                return generatePublic(SubjectPublicKeyInfo.getInstance(((X509EncodedKeySpec)keySpec).getEncoded()));
            }
            catch (Exception e)
            {
                throw new InvalidKeySpecException(e.getMessage(), e);
            }
        }
        else if (keySpec != null)
        {
            throw new InvalidKeySpecException("keySpec for PublicKey not recognized: " + keySpec.getClass().getName());
        }
        else
        {
            throw new InvalidKeySpecException("null keySpec passed for PublicKey");
        }
    }

    protected KeySpec engineGetKeySpec(
        Key key,
        Class spec)
        throws InvalidKeySpecException
    {
        if (spec.isAssignableFrom(PKCS8EncodedKeySpec.class) && key.getFormat().equals("PKCS#8"))
        {
            return new PKCS8EncodedKeySpec(key.getEncoded());
        }
        else if (spec.isAssignableFrom(X509EncodedKeySpec.class) && key.getFormat().equals("X.509"))
        {
            return new X509EncodedKeySpec(key.getEncoded());
        }

        throw new InvalidKeySpecException("Unable to transform key to KeySpec: " + spec.getName());
    }
}
