package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricKeyPairGenerator;
import org.bouncycastle.crypto.asymmetric.AsymmetricGOST3410PrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricGOST3410PublicKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricKeyPair;
import org.bouncycastle.crypto.asymmetric.GOST3410DomainParameters;
import org.bouncycastle.crypto.asymmetric.GOST3410Parameters;
import org.bouncycastle.crypto.general.GOST3410;
import org.bouncycastle.jcajce.interfaces.GOST3410PrivateKey;
import org.bouncycastle.jcajce.interfaces.GOST3410PublicKey;
import org.bouncycastle.jcajce.spec.GOST3410DomainParameterSpec;
import org.bouncycastle.jcajce.spec.GOST3410ParameterSpec;
import org.bouncycastle.jcajce.spec.GOST3410PrivateKeySpec;
import org.bouncycastle.jcajce.spec.GOST3410PublicKeySpec;

class ProvGOST3410
    extends AsymmetricAlgorithmProvider
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".gost.";

    private static final PublicKeyConverter<AsymmetricGOST3410PublicKey> publicKeyConverter = new PublicKeyConverter<AsymmetricGOST3410PublicKey>()
    {
        public AsymmetricGOST3410PublicKey convertKey(Algorithm algorithm, PublicKey key)
            throws InvalidKeyException
        {
            if (key instanceof GOST3410PublicKey)
            {
                if (key instanceof ProvGOST3410PublicKey)
                {
                    return ((ProvGOST3410PublicKey)key).getBaseKey();
                }

                return new ProvGOST3410PublicKey(algorithm, (GOST3410PublicKey)key).getBaseKey();
            }
            else
            {
                // see if we can build a key from key.getEncoded()
                try
                {
                    return new AsymmetricGOST3410PublicKey(algorithm, SubjectPublicKeyInfo.getInstance(Utils.getKeyEncoding(key)));
                }
                catch (Exception e)
                {
                    throw new InvalidKeyException("Cannot identify GOST3410 public key: " + e.getMessage(), e);
                }
            }
        }
    };

    private static final PrivateKeyConverter<AsymmetricGOST3410PrivateKey> privateKeyConverter = new PrivateKeyConverter<AsymmetricGOST3410PrivateKey>()
    {
        public AsymmetricGOST3410PrivateKey convertKey(Algorithm algorithm, PrivateKey key)
            throws InvalidKeyException
        {
            if (key instanceof GOST3410PrivateKey)
            {
                if (key instanceof ProvGOST3410PrivateKey)
                {
                    return ((ProvGOST3410PrivateKey)key).getBaseKey();
                }

                return new ProvGOST3410PrivateKey(algorithm, (GOST3410PrivateKey)key).getBaseKey();
            }
            else
            {
                // see if we can build a key from key.getEncoded()
                try
                {
                    return new AsymmetricGOST3410PrivateKey(algorithm, PrivateKeyInfo.getInstance(Utils.getKeyEncoding(key)));
                }
                catch (Exception e)
                {
                    throw new InvalidKeyException("Cannot identify GOST3410 private key: " + e.getMessage(), e);
                }
            }
        }
    };

    public void configure(final BouncyCastleFipsProvider provider)
    {
        provider.addAlgorithmImplementation("KeyPairGenerator.GOST3410", PREFIX + "KeyPairGeneratorSpi", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyPairGenerator(provider);
            }
        }));
        provider.addAlias("Alg.Alias.KeyPairGenerator.GOST-3410", "GOST3410");
        provider.addAlias("Alg.Alias.KeyPairGenerator.GOST-3410-94", "GOST3410");

        provider.addAlgorithmImplementation("KeyFactory.GOST3410", PREFIX + "KeyFactorySpi", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new GOST3410KeyFactory();
            }
        }));

        provider.addAlias("Alg.Alias.KeyFactory.GOST-3410", "GOST3410");
        provider.addAlias("Alg.Alias.KeyFactory.GOST-3410-94", "GOST3410");

        registerOid(provider, CryptoProObjectIdentifiers.gostR3410_94, "GOST3410", new GOST3410KeyFactory());

        provider.addAlgorithmImplementation("Signature.GOST3410", PREFIX + "SignatureSpi", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, new GOST3410.SignatureOperatorFactory(), publicKeyConverter, privateKeyConverter, GOST3410.GOST3410);
            }
        }));

        provider.addAlias("Signature", "GOST3410", "GOST3411WITHGOST3410", "GOST-3410", "GOST-3410-94");
        provider.addAlias("Signature", "GOST3410", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94);
    }

    static class KeyPairGenerator
        extends java.security.KeyPairGenerator
    {
        private final BouncyCastleFipsProvider fipsProvider;
        private GOST3410Parameters<GOST3410DomainParameters> params;
        private AsymmetricKeyPairGenerator engine;

        private SecureRandom random;
        private boolean initialised = false;

        public KeyPairGenerator(BouncyCastleFipsProvider fipsProvider)
        {
            super("GOST3410");
            this.fipsProvider = fipsProvider;
            this.random = fipsProvider.getDefaultSecureRandom();
        }

        public void initialize(
            int strength)
        {
            initialize(strength, fipsProvider.getDefaultSecureRandom());
        }

        public void initialize(
            int strength,
            SecureRandom random)
        {
            throw new InvalidParameterException("GOST3410 KeyPairGenerator needs to be initialized with a GOST3410ParameterSpec");
        }

        private void init(
            GOST3410ParameterSpec gParams,
            SecureRandom random)
        {
            params = GOST3410Util.convertToParams((GOST3410ParameterSpec<GOST3410DomainParameterSpec>)gParams);
            engine = new GOST3410.KeyPairGenerator(new GOST3410.KeyGenParameters(params), random);
            initialised = true;
        }

        public void initialize(
            AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException
        {
            initialize(params, fipsProvider.getDefaultSecureRandom());
        }

        public void initialize(
            AlgorithmParameterSpec params,
            SecureRandom random)
            throws InvalidAlgorithmParameterException
        {
            if (!(params instanceof GOST3410ParameterSpec))
            {
                throw new InvalidAlgorithmParameterException("AlgorithmParameterSpec not recognized: " + params.getClass().getName());
            }

            init((GOST3410ParameterSpec)params, random);
        }

        public KeyPair generateKeyPair()
        {
            if (!initialised)
            {
                init(new GOST3410ParameterSpec(new GOST3410Parameters<GOST3410DomainParameters>(CryptoProObjectIdentifiers.gostR3410_94_CryptoPro_A, CryptoProObjectIdentifiers.gostR3411)), random);
            }

            AsymmetricKeyPair pair = engine.generateKeyPair();
            AsymmetricGOST3410PublicKey pub = (AsymmetricGOST3410PublicKey)pair.getPublicKey();
            AsymmetricGOST3410PrivateKey priv = (AsymmetricGOST3410PrivateKey)pair.getPrivateKey();

            return new KeyPair(new ProvGOST3410PublicKey(pub), new ProvGOST3410PrivateKey(priv));
        }
    }

    static class GOST3410KeyFactory
        extends BaseKeyFactory
    {
        public GOST3410KeyFactory()
        {
        }

        protected KeySpec engineGetKeySpec(
            Key key,
            Class spec)
            throws InvalidKeySpecException
        {
            if (spec == null)
            {
                throw new InvalidKeySpecException("null spec is invalid");
            }

            if (spec.isAssignableFrom(GOST3410PublicKeySpec.class) && key instanceof GOST3410PublicKey)
            {
                GOST3410PublicKey k = (GOST3410PublicKey)key;

                return new GOST3410PublicKeySpec(k.getY(), k.getParams());
            }
            else if (spec.isAssignableFrom(GOST3410PrivateKeySpec.class) && key instanceof GOST3410PrivateKey)
            {
                GOST3410PrivateKey k = (GOST3410PrivateKey)key;

                return new GOST3410PrivateKeySpec(k.getX(), k.getParams());
            }

            return super.engineGetKeySpec(key, spec);
        }

        protected Key engineTranslateKey(
            Key key)
            throws InvalidKeyException
        {
            if (key instanceof PublicKey)
            {
                return new ProvGOST3410PublicKey(publicKeyConverter.convertKey(GOST3410.ALGORITHM, (PublicKey)key));
            }
            else if (key instanceof PrivateKey)
            {
                return new ProvGOST3410PrivateKey(privateKeyConverter.convertKey(GOST3410.ALGORITHM, (PrivateKey)key));
            }

            if (key != null)
            {
                throw new InvalidKeyException("Key type unrecognized: " + key.getClass().getName());
            }

            throw new InvalidKeyException("Key is null");
        }

        protected PrivateKey engineGeneratePrivate(
            KeySpec keySpec)
            throws InvalidKeySpecException
        {
            if (keySpec instanceof GOST3410PrivateKeySpec)
            {
                return new ProvGOST3410PrivateKey(GOST3410.ALGORITHM, (GOST3410PrivateKeySpec)keySpec);
            }

            return super.engineGeneratePrivate(keySpec);
        }

        protected PublicKey engineGeneratePublic(
            KeySpec keySpec)
            throws InvalidKeySpecException
        {
            if (keySpec instanceof GOST3410PublicKeySpec)
            {
                return new ProvGOST3410PublicKey(GOST3410.ALGORITHM, (GOST3410PublicKeySpec)keySpec);
            }

            return super.engineGeneratePublic(keySpec);
        }

        public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
            throws IOException
        {
            return new ProvGOST3410PrivateKey(new AsymmetricGOST3410PrivateKey(GOST3410.ALGORITHM, keyInfo));
        }

        public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
            throws IOException
        {
            return new ProvGOST3410PublicKey(new AsymmetricGOST3410PublicKey(GOST3410.ALGORITHM, keyInfo));
        }
    }
}
