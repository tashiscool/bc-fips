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

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.ua.UAObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricKeyPairGenerator;
import org.bouncycastle.crypto.asymmetric.AsymmetricDSTU4145PrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricDSTU4145PublicKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricKeyPair;
import org.bouncycastle.crypto.asymmetric.DSTU4145Parameters;
import org.bouncycastle.crypto.general.DSTU4145;
import org.bouncycastle.jcajce.interfaces.DSTU4145PrivateKey;
import org.bouncycastle.jcajce.interfaces.DSTU4145PublicKey;
import org.bouncycastle.jcajce.spec.DSTU4145ParameterSpec;
import org.bouncycastle.jcajce.spec.DSTU4145PrivateKeySpec;
import org.bouncycastle.jcajce.spec.DSTU4145PublicKeySpec;

class ProvDSTU4145
    extends AsymmetricAlgorithmProvider
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".dstu4145.";

    private static final PublicKeyConverter<AsymmetricDSTU4145PublicKey> publicKeyConverter = new PublicKeyConverter<AsymmetricDSTU4145PublicKey>()
    {
        public AsymmetricDSTU4145PublicKey convertKey(Algorithm algorithm, PublicKey key)
            throws InvalidKeyException
        {
            if (key instanceof DSTU4145PublicKey)
            {
                if (key instanceof ProvDSTU4145PublicKey)
                {
                    return ((ProvDSTU4145PublicKey)key).getBaseKey();
                }

                return new ProvDSTU4145PublicKey(algorithm, (DSTU4145PublicKey)key).getBaseKey();
            }
            else
            {
                // see if we can build a key from key.getEncoded()
                try
                {
                    return new AsymmetricDSTU4145PublicKey(algorithm, SubjectPublicKeyInfo.getInstance(Utils.getKeyEncoding(key)));
                }
                catch (InvalidKeyException e)
                {
                    throw e;
                }
                catch (Exception e)
                {
                    throw new InvalidKeyException("Cannot identify DSTU4145 public key: " + e.getMessage(), e);
                }
            }
        }
    };

    private static final PrivateKeyConverter<AsymmetricDSTU4145PrivateKey> privateKeyConverter = new PrivateKeyConverter<AsymmetricDSTU4145PrivateKey>()
    {
        public AsymmetricDSTU4145PrivateKey convertKey(Algorithm algorithm, PrivateKey key)
            throws InvalidKeyException
        {
            if (key instanceof DSTU4145PrivateKey)
            {
                if (key instanceof ProvDSTU4145PrivateKey)
                {
                    return ((ProvDSTU4145PrivateKey)key).getBaseKey();
                }

                return new ProvDSTU4145PrivateKey(algorithm, (DSTU4145PrivateKey)key).getBaseKey();
            }
            else
            {
                // see if we can build a key from key.getEncoded()
                try
                {
                    return new AsymmetricDSTU4145PrivateKey(algorithm, PrivateKeyInfo.getInstance(Utils.getKeyEncoding(key)));
                }
                catch (InvalidKeyException e)
                {
                    throw e;
                }
                catch (Exception e)
                {
                    throw new InvalidKeyException("Cannot identify DSTU4145 private key: " + e.getMessage(), e);
                }
            }
        }
    };

    public void configure(final BouncyCastleFipsProvider provider)
    {
        provider.addAlgorithmImplementation("KeyFactory.DSTU4145", PREFIX + "KeyFactorySpi", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyFactorySpi();
            }
        }));
        provider.addAlias("Alg.Alias.KeyFactory.DSTU-4145-2002", "DSTU4145");
        provider.addAlias("Alg.Alias.KeyFactory.DSTU4145-3410", "DSTU4145");

        provider.addAlgorithmImplementation("KeyPairGenerator.DSTU4145", PREFIX + "KeyPairGeneratorSpi", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyPairGenerator(provider);
            }
        }));
        provider.addAlias("Alg.Alias.KeyPairGenerator.DSTU-4145", "DSTU4145");
        provider.addAlias("Alg.Alias.KeyPairGenerator.DSTU-4145-2002", "DSTU4145");

        registerOid(provider, UAObjectIdentifiers.dstu4145le, "DSTU4145", new KeyFactorySpi());
        registerOid(provider, UAObjectIdentifiers.dstu4145be, "DSTU4145", new KeyFactorySpi());

        provider.addAlgorithmImplementation("Signature.DSTU4145", PREFIX + "SignatureSpi", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, new DSTU4145.SignatureOperatorFactory(), publicKeyConverter, privateKeyConverter, DSTU4145.DSTU4145);
            }
        }));
        provider.addAlias("Alg.Alias.Signature.DSTU-4145", "DSTU4145");
        provider.addAlias("Alg.Alias.Signature.DSTU-4145-2002", "DSTU4145");

        addSignatureAlgorithm(provider, "GOST3411", "DSTU4145LE", PREFIX + "SignatureSpiLe", UAObjectIdentifiers.dstu4145le, new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, new DSTU4145.LittleEndianSignatureOperatorFactory(), publicKeyConverter, privateKeyConverter, DSTU4145.DSTU4145);
            }
        }));
        provider.addAlias("Alg.Alias.Signature.DSTU4145LE", "GOST3411WITHDSTU4145LE");

        addSignatureAlgorithm(provider, "GOST3411", "DSTU4145", PREFIX + "SignatureSpiBe", UAObjectIdentifiers.dstu4145be, new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, new DSTU4145.SignatureOperatorFactory(), publicKeyConverter, privateKeyConverter, DSTU4145.DSTU4145);
            }
        }));
    }

    static class KeyFactorySpi
        extends BaseKeyFactory
    {
        public KeyFactorySpi()
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

            if (spec.isAssignableFrom(DSTU4145PublicKeySpec.class) && key instanceof DSTU4145PublicKey)
            {
                DSTU4145PublicKey k = (DSTU4145PublicKey)key;

                return new DSTU4145PublicKeySpec(k.getW(), k.getParams());
            }
            else if (spec.isAssignableFrom(DSTU4145PrivateKeySpec.class) && key instanceof DSTU4145PrivateKey)
            {
                DSTU4145PrivateKey k = (DSTU4145PrivateKey)key;

                return new DSTU4145PrivateKeySpec(k.getS(), k.getParams());
            }

            return super.engineGetKeySpec(key, spec);
        }

        protected Key engineTranslateKey(
            Key key)
            throws InvalidKeyException
        {
            if (key instanceof PublicKey)
            {
                return new ProvDSTU4145PublicKey(publicKeyConverter.convertKey(DSTU4145.ALGORITHM, (PublicKey)key));
            }
            else if (key instanceof PrivateKey)
            {
                return new ProvDSTU4145PrivateKey(privateKeyConverter.convertKey(DSTU4145.ALGORITHM, (PrivateKey)key));
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
            if (keySpec instanceof DSTU4145PrivateKeySpec)
            {
                return new ProvDSTU4145PrivateKey(DSTU4145.ALGORITHM, (DSTU4145PrivateKeySpec)keySpec);
            }

            return super.engineGeneratePrivate(keySpec);
        }

        protected PublicKey engineGeneratePublic(
            KeySpec keySpec)
            throws InvalidKeySpecException
        {
            if (keySpec instanceof DSTU4145PublicKeySpec)
            {
                return new ProvDSTU4145PublicKey(DSTU4145.ALGORITHM, (DSTU4145PublicKeySpec)keySpec);
            }

            return super.engineGeneratePublic(keySpec);
        }

        public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
            throws IOException
        {
            return new ProvDSTU4145PrivateKey(new AsymmetricDSTU4145PrivateKey(DSTU4145.ALGORITHM, keyInfo));
        }

        public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
            throws IOException
        {
            return new ProvDSTU4145PublicKey(new AsymmetricDSTU4145PublicKey(DSTU4145.ALGORITHM, keyInfo));
        }
    }

    static class KeyPairGenerator
        extends java.security.KeyPairGenerator
    {
        private final BouncyCastleFipsProvider fipsProvider;
        private DSTU4145Parameters params;
        private AsymmetricKeyPairGenerator engine;

        private boolean initialised = false;

        public KeyPairGenerator(BouncyCastleFipsProvider fipsProvider)
        {
            super("DSTU4145");
            this.fipsProvider = fipsProvider;
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
            throw new InvalidParameterException("DSTU4145 KeyPairGenerator needs to be initialized with a DSTU4145ParameterSpec");
        }

        private void init(
            DSTU4145ParameterSpec dstu4145Params,
            SecureRandom random)
        {
            params = DSTU4145Util.convertToECParams(dstu4145Params);
            engine = new DSTU4145.KeyPairGenerator(new DSTU4145.KeyGenParameters(params), random);
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
            if (!(params instanceof DSTU4145ParameterSpec))
            {
                throw new InvalidAlgorithmParameterException("AlgorithmParameterSpec not recognized: " + params.getClass().getName());
            }

            init((DSTU4145ParameterSpec)params, random);
        }

        public KeyPair generateKeyPair()
        {
            if (!initialised)
            {
                throw new IllegalStateException("DSTU Key Pair Generator not initialised");
            }

            AsymmetricKeyPair pair = engine.generateKeyPair();
            AsymmetricDSTU4145PublicKey pub = (AsymmetricDSTU4145PublicKey)pair.getPublicKey();
            AsymmetricDSTU4145PrivateKey priv = (AsymmetricDSTU4145PrivateKey)pair.getPrivateKey();

            return new KeyPair(new ProvDSTU4145PublicKey(pub), new ProvDSTU4145PrivateKey(priv));
        }
    }
}
