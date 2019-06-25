package org.bouncycastle.jcajce.provider;

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.ShortBufferException;

import org.bouncycastle.jcajce.KTSKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KTSExtractKeySpec;
import org.bouncycastle.jcajce.spec.KTSGenerateKeySpec;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.util.Arrays;

class KtsCipherSpi
    extends CipherSpi
{
    private final BouncyCastleFipsProvider fipsProvider;
    private final String algorithmName;
    private SecretKeyFactory kemFact;
    private KTSParameterSpec ktsParameterSpec;
    private RSAPublicKey wrapKey;
    private RSAPrivateKey unwrapKey;
    private SecureRandom random;

    private AlgorithmParameters engineParams;

    KtsCipherSpi(BouncyCastleFipsProvider fipsProvider, String algorithmName)
        throws NoSuchAlgorithmException
    {
        this.fipsProvider = fipsProvider;
        this.algorithmName = algorithmName;
        this.kemFact = SecretKeyFactory.getInstance("RSA-KAS-KEM", fipsProvider);
    }

    @Override
    protected void engineSetMode(String mode)
        throws NoSuchAlgorithmException
    {
        throw new NoSuchAlgorithmException("Cannot support mode " + mode);
    }

    @Override
    protected void engineSetPadding(String padding)
        throws NoSuchPaddingException
    {
        throw new NoSuchPaddingException("Padding " + padding + " unknown");
    }

    protected int engineGetKeySize(
        Key key)
    {
        if (key instanceof RSAKey)
        {
            RSAKey k = (RSAKey)key;

            return k.getModulus().bitLength();
        }

        throw new IllegalArgumentException("not an valid key!");
    }

    @Override
    protected int engineGetBlockSize()
    {
        return 0;
    }

    @Override
    protected int engineGetOutputSize(int i)
    {
        return -1;        // can't use with update/doFinal
    }

    @Override
    protected byte[] engineGetIV()
    {
        return null;
    }

    @Override
    protected AlgorithmParameters engineGetParameters()
    {
        if (engineParams == null)
        {
            try
            {
                engineParams = AlgorithmParameters.getInstance(algorithmName, fipsProvider);

                engineParams.init(ktsParameterSpec);
            }
            catch (Exception e)
            {
                throw new IllegalStateException(e.toString(), e);
            }
        }

        return engineParams;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random)
        throws InvalidKeyException
    {
        try
        {
            engineInit(opmode, key, (AlgorithmParameterSpec)null, random);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec paramSpec, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (random == null)
        {
            this.random = fipsProvider.getDefaultSecureRandom();
        }

        if (paramSpec == null)
        {
            ktsParameterSpec = new KTSParameterSpec.Builder("AES", 128).build();
        }
        else
        {
            if (!(paramSpec instanceof KTSParameterSpec))
            {
                throw new InvalidAlgorithmParameterException(algorithmName + " can only accept KTSParameterSpec");
            }

            ktsParameterSpec = (KTSParameterSpec)paramSpec;
        }

        if (opmode == Cipher.WRAP_MODE)
        {
            if (key instanceof RSAPublicKey)
            {
                wrapKey = (RSAPublicKey)key;
            }
            else
            {
                throw new InvalidKeyException("Only an RSA public key can be used for wrapping");
            }
        }
        else if (opmode == Cipher.UNWRAP_MODE)
        {
            if (key instanceof RSAPrivateKey)
            {
                unwrapKey = (RSAPrivateKey)key;
            }
            else
            {
                throw new InvalidKeyException("Only an RSA private key can be used for unwrapping");
            }
        }
        else
        {
            throw new InvalidParameterException("Cipher only valid for wrapping/unwrapping");
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters algorithmParameters, SecureRandom secureRandom)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        AlgorithmParameterSpec paramSpec = null;

        if (algorithmParameters != null)
        {
            try
            {
                paramSpec = algorithmParameters.getParameterSpec(KTSParameterSpec.class);
            }
            catch (Exception e)
            {
                throw new InvalidAlgorithmParameterException("can't handle parameter " + algorithmParameters.toString());
            }
        }

        engineInit(opmode, key, paramSpec, random);
    }

    @Override
    protected byte[] engineUpdate(byte[] bytes, int i, int i1)
    {
        throw new IllegalStateException("Not supported in a wrapping mode");
    }

    @Override
    protected int engineUpdate(byte[] bytes, int i, int i1, byte[] bytes1, int i2)
        throws ShortBufferException
    {
        throw new IllegalStateException("Not supported in a wrapping mode");
    }

    @Override
    protected byte[] engineDoFinal(byte[] bytes, int i, int i1)
        throws IllegalBlockSizeException, BadPaddingException
    {
        throw new IllegalStateException("Not supported in a wrapping mode");
    }

    @Override
    protected int engineDoFinal(byte[] bytes, int i, int i1, byte[] bytes1, int i2)
        throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
    {
        throw new IllegalStateException("Not supported in a wrapping mode");
    }

    protected byte[] engineWrap(
        Key key)
        throws IllegalBlockSizeException, InvalidKeyException
    {
        byte[] encoded = key.getEncoded();
        if (encoded == null)
        {
            throw new InvalidKeyException("Cannot wrap key, null encoding.");
        }

        try
        {
            KTSGenerateKeySpec genSpec = new KTSGenerateKeySpec.Builder(wrapKey, ktsParameterSpec.getKeyAlgorithmName(),
                ktsParameterSpec.getKeySize(), ktsParameterSpec.getOtherInfo())
                .withKdfAlgorithm(ktsParameterSpec.getKdfAlgorithm())
                .withSecureRandom(random)
                .withParameterSpec(ktsParameterSpec.getParameterSpec()).build();

            KTSKeyWithEncapsulation ktsKey = (KTSKeyWithEncapsulation)kemFact.generateSecret(genSpec);

            Cipher wrapCipher = Cipher.getInstance(ktsParameterSpec.getKeyAlgorithmName(), fipsProvider);

            wrapCipher.init(Cipher.WRAP_MODE, ktsKey, random);

            return Arrays.concatenate(ktsKey.getEncapsulation(), wrapCipher.wrap(key));
        }
        catch (InvalidKeyException e)
        {
            throw e;
        }
        catch (GeneralSecurityException e)
        {
            throw new IllegalBlockSizeException("Unable to generate KTS secret: " + e.getMessage());
        }
        catch (IllegalArgumentException e)
        {
            throw new IllegalBlockSizeException("Unable to generate KTS secret: " + e.getMessage());
        }
    }

    protected Key engineUnwrap(
        byte[] wrappedKey,
        String wrappedKeyAlgorithm,
        int wrappedKeyType)
        throws InvalidKeyException, NoSuchAlgorithmException
    {
        try
        {
            byte[] encapsulation = new byte[(unwrapKey.getModulus().bitLength() + 7) / 8];
            System.arraycopy(wrappedKey, 0, encapsulation, 0, encapsulation.length);

            KTSExtractKeySpec extSpec = new KTSExtractKeySpec.Builder(unwrapKey, encapsulation,
                ktsParameterSpec.getKeyAlgorithmName(), ktsParameterSpec.getKeySize(), ktsParameterSpec.getOtherInfo())
                .withKdfAlgorithm(ktsParameterSpec.getKdfAlgorithm())
                .withParameterSpec(ktsParameterSpec.getParameterSpec()).build();

            KTSKeyWithEncapsulation ktsKey = (KTSKeyWithEncapsulation)kemFact.generateSecret(extSpec);

            Cipher wrapCipher = Cipher.getInstance(ktsParameterSpec.getKeyAlgorithmName(), fipsProvider);

            wrapCipher.init(Cipher.UNWRAP_MODE, ktsKey, random);

            byte[] encodedKey = new byte[wrappedKey.length - encapsulation.length];
            System.arraycopy(wrappedKey, encapsulation.length, encodedKey, 0, encodedKey.length);

            return wrapCipher.unwrap(encodedKey, wrappedKeyAlgorithm, wrappedKeyType);
        }
        catch (InvalidKeyException e)
        {
            throw e;
        }
        catch (GeneralSecurityException e)
        {
            if (e instanceof NoSuchAlgorithmException)
            {
                throw (NoSuchAlgorithmException)e;
            }
            throw new NoSuchAlgorithmException("Unable to generate KTS secret: " + e.getMessage());
        }
        catch (IllegalArgumentException e)
        {
            throw new NoSuchAlgorithmException("Unable to generate KTS secret: " + e.getMessage());
        }
    }
}
