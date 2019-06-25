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
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricKeyPairGenerator;
import org.bouncycastle.crypto.asymmetric.AsymmetricECGOST3410PrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricECGOST3410PublicKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricKeyPair;
import org.bouncycastle.crypto.asymmetric.ECDomainParameters;
import org.bouncycastle.crypto.asymmetric.GOST3410Parameters;
import org.bouncycastle.crypto.general.ECGOST3410;
import org.bouncycastle.jcajce.interfaces.ECGOST3410PrivateKey;
import org.bouncycastle.jcajce.interfaces.ECGOST3410PublicKey;
import org.bouncycastle.jcajce.spec.ECDomainParameterSpec;
import org.bouncycastle.jcajce.spec.ECGOST3410PrivateKeySpec;
import org.bouncycastle.jcajce.spec.ECGOST3410PublicKeySpec;
import org.bouncycastle.jcajce.spec.GOST3410ParameterSpec;

class ProvECGOST3410
    extends AsymmetricAlgorithmProvider
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".ecgost.";

    private static final PublicKeyConverter<AsymmetricECGOST3410PublicKey> publicKeyConverter = new PublicKeyConverter<AsymmetricECGOST3410PublicKey>()
    {
        public AsymmetricECGOST3410PublicKey convertKey(Algorithm algorithm, PublicKey key)
            throws InvalidKeyException
        {
            if (key instanceof ECGOST3410PublicKey)
            {
                if (key instanceof ProvECGOST3410PublicKey)
                {
                    return ((ProvECGOST3410PublicKey)key).getBaseKey();
                }

                return new ProvECGOST3410PublicKey(algorithm, (ECGOST3410PublicKey)key).getBaseKey();
            }
            else
            {
                // see if we can build a key from key.getEncoded()
                try
                {
                    return new AsymmetricECGOST3410PublicKey(algorithm, SubjectPublicKeyInfo.getInstance(Utils.getKeyEncoding(key)));
                }
                catch (Exception e)
                {
                    throw new InvalidKeyException("Cannot identify ECGOST3410 public key: " + e.getMessage(), e);
                }
            }
        }
    };

    private static final PrivateKeyConverter<AsymmetricECGOST3410PrivateKey> privateKeyConverter = new PrivateKeyConverter<AsymmetricECGOST3410PrivateKey>()
    {
        public AsymmetricECGOST3410PrivateKey convertKey(Algorithm algorithm, PrivateKey key)
            throws InvalidKeyException
        {
            if (key instanceof ECGOST3410PrivateKey)
            {
                if (key instanceof ProvECGOST3410PrivateKey)
                {
                    return ((ProvECGOST3410PrivateKey)key).getBaseKey();
                }

                return new ProvECGOST3410PrivateKey(algorithm, (ECGOST3410PrivateKey)key).getBaseKey();
            }
            else
            {
                // see if we can build a key from key.getEncoded()
                try
                {
                    return new AsymmetricECGOST3410PrivateKey(algorithm, PrivateKeyInfo.getInstance(Utils.getKeyEncoding(key)));
                }
                catch (Exception e)
                {
                    throw new InvalidKeyException("Cannot identify ECGOST3410 private key: " + e.getMessage(), e);
                }
            }
        }
    };

    public void configure(final BouncyCastleFipsProvider provider)
    {
        provider.addAlgorithmImplementation("KeyFactory.ECGOST3410", PREFIX + "KeyFactorySpi", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyFactorySpi();
            }
        }));
        provider.addAlias("Alg.Alias.KeyFactory.GOST-3410-2001", "ECGOST3410");
        provider.addAlias("Alg.Alias.KeyFactory.ECGOST-3410", "ECGOST3410");

        provider.addAlgorithmImplementation("KeyPairGenerator.ECGOST3410", PREFIX + "KeyPairGeneratorSpi", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyPairGenerator(provider);
            }
        }));
        provider.addAlias("Alg.Alias.KeyPairGenerator.ECGOST-3410", "ECGOST3410");
        provider.addAlias("Alg.Alias.KeyPairGenerator.GOST-3410-2001", "ECGOST3410");

        registerOid(provider, CryptoProObjectIdentifiers.gostR3410_2001, "ECGOST3410", new KeyFactorySpi());

        addSignatureAlgorithm(provider, "GOST3411", "ECGOST3410", PREFIX + "ECSignatureSpi", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001, new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, new ECGOST3410.SignatureOperatorFactory(), publicKeyConverter, privateKeyConverter, ECGOST3410.GOST3410);
            }
        }));

        provider.addAlias("Alg.Alias.Signature.ECGOST3410", "GOST3411WITHECGOST3410");
        provider.addAlias("Alg.Alias.Signature.ECGOST-3410", "GOST3411WITHECGOST3410");
        provider.addAlias("Alg.Alias.Signature.GOST-3410-2001", "GOST3411WITHECGOST3410");
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

            if (spec.isAssignableFrom(ECGOST3410PublicKeySpec.class) && key instanceof ECGOST3410PublicKey)
            {
                ECGOST3410PublicKey k = (ECGOST3410PublicKey)key;
                if (k.getParams() != null)
                {
                    return new ECGOST3410PublicKeySpec(k.getW(), k.getParams());
                }
            }
            else if (spec.isAssignableFrom(ECGOST3410PrivateKeySpec.class) && key instanceof ECGOST3410PrivateKey)
            {
                ECGOST3410PrivateKey k = (ECGOST3410PrivateKey)key;

                if (k.getParams() != null)
                {
                    return new ECGOST3410PrivateKeySpec(k.getS(), k.getParams());
                }
            }

            return super.engineGetKeySpec(key, spec);
        }

        protected Key engineTranslateKey(
            Key key)
            throws InvalidKeyException
        {
            if (key instanceof PublicKey)
            {
                return new ProvECGOST3410PublicKey(publicKeyConverter.convertKey(ECGOST3410.ALGORITHM, (PublicKey)key));
            }
            else if (key instanceof PrivateKey)
            {
                return new ProvECGOST3410PrivateKey(privateKeyConverter.convertKey(ECGOST3410.ALGORITHM, (PrivateKey)key));
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
            if (keySpec instanceof ECGOST3410PrivateKeySpec)
            {
                return new ProvECGOST3410PrivateKey(ECGOST3410.ALGORITHM, (ECGOST3410PrivateKeySpec)keySpec);
            }

            return super.engineGeneratePrivate(keySpec);
        }

        protected PublicKey engineGeneratePublic(
            KeySpec keySpec)
            throws InvalidKeySpecException
        {
            if (keySpec instanceof ECGOST3410PublicKeySpec)
            {
                return new ProvECGOST3410PublicKey(ECGOST3410.ALGORITHM, (ECGOST3410PublicKeySpec)keySpec);
            }

            return super.engineGeneratePublic(keySpec);
        }

        public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
            throws IOException
        {
            return new ProvECGOST3410PrivateKey(new AsymmetricECGOST3410PrivateKey(ECGOST3410.ALGORITHM, keyInfo));
        }

        public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
            throws IOException
        {
            return new ProvECGOST3410PublicKey(new AsymmetricECGOST3410PublicKey(ECGOST3410.ALGORITHM, keyInfo));
        }
    }

    static class KeyPairGenerator
        extends java.security.KeyPairGenerator
    {
        private final BouncyCastleFipsProvider fipsProvider;
        private GOST3410Parameters<ECDomainParameters> params;
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
            throw new InvalidParameterException("ECGOST3410 KeyPairGenerator needs to be initialized with a GOST3410ParameterSpec");
        }

        private void init(
            GOST3410ParameterSpec gParams,
            SecureRandom random)
        {
            params = GOST3410Util.convertToECParams((GOST3410ParameterSpec<ECDomainParameterSpec>)gParams);
            engine = new ECGOST3410.KeyPairGenerator(new ECGOST3410.KeyGenParameters(params), random);
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
            if (!(params instanceof GOST3410ParameterSpec) && !(params instanceof ECGenParameterSpec))
            {
                throw new InvalidAlgorithmParameterException("AlgorithmParameterSpec not recognized: " + params.getClass().getName());
            }

            GOST3410ParameterSpec paramSpec;

            if (params instanceof ECGenParameterSpec)
            {
                ASN1ObjectIdentifier oid = ECGOST3410NamedCurves.getOID(((ECGenParameterSpec)params).getName());

                paramSpec = new GOST3410ParameterSpec(new GOST3410Parameters(oid));
            }
            else
            {
                paramSpec = (GOST3410ParameterSpec)params;
            }

            init(paramSpec, random);
        }

        public KeyPair generateKeyPair()
        {
            if (!initialised)
            {
                init(new GOST3410ParameterSpec(new GOST3410Parameters<ECDomainParameters>(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_A, CryptoProObjectIdentifiers.gostR3411)), random);
            }

            AsymmetricKeyPair pair = engine.generateKeyPair();
            AsymmetricECGOST3410PublicKey pub = (AsymmetricECGOST3410PublicKey)pair.getPublicKey();
            AsymmetricECGOST3410PrivateKey priv = (AsymmetricECGOST3410PrivateKey)pair.getPrivateKey();

            return new KeyPair(new ProvECGOST3410PublicKey(pub), new ProvECGOST3410PrivateKey(priv));
        }
    }
}
