package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricKeyPairGenerator;
import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.AsymmetricPublicKey;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.OutputSignerUsingSecureRandom;
import org.bouncycastle.crypto.OutputVerifier;
import org.bouncycastle.crypto.SignatureOperatorFactory;
import org.bouncycastle.crypto.asymmetric.AsymmetricDSAPrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricDSAPublicKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricKeyPair;
import org.bouncycastle.crypto.asymmetric.DSADomainParameters;
import org.bouncycastle.crypto.fips.FipsAlgorithm;
import org.bouncycastle.crypto.fips.FipsDSA;
import org.bouncycastle.crypto.fips.FipsDigestAlgorithm;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.crypto.fips.FipsUnapprovedOperationError;
import org.bouncycastle.crypto.general.DSA;
import org.bouncycastle.jcajce.spec.DSADomainParameterSpec;
import org.bouncycastle.jcajce.spec.DSADomainParametersGenerationParameterSpec;

class ProvDSA
    extends AsymmetricAlgorithmProvider
{
    private static final Map<String, String> generalDsaAttributes = new HashMap<String, String>();

    static
    {
        generalDsaAttributes.put("SupportedKeyClasses", "java.security.interfaces.DSAPublicKey|java.security.interfaces.DSAPrivateKey");
        generalDsaAttributes.put("SupportedKeyFormats", "PKCS#8|X.509");
    }

    private static final ASN1ObjectIdentifier[] dsaOids =
        {
            X9ObjectIdentifiers.id_dsa,
            X9ObjectIdentifiers.id_dsa_with_sha1,
            OIWObjectIdentifiers.dsaWithSHA1
        };

    private static final SignatureOperatorFactory fipsDsaFactory = new FipsDSA.OperatorFactory();

    private static SignatureOperatorFactory genDsaFactory;


    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".dsa.";

    private static SignatureOperatorFactory getGeneralDSAFactory()
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            return null;
        }

        if (genDsaFactory == null)
        {
            genDsaFactory = new DSA.OperatorFactory();
        }

        return genDsaFactory;
    }

    private static final PublicKeyConverter<AsymmetricDSAPublicKey> publicKeyConverter = new PublicKeyConverter<AsymmetricDSAPublicKey>()
    {
        public AsymmetricDSAPublicKey convertKey(Algorithm algorithm, PublicKey key)
            throws InvalidKeyException
        {
            if (key instanceof DSAPublicKey)
            {
                if (key instanceof ProvDSAPublicKey)
                {
                    return ((ProvDSAPublicKey)key).getBaseKey();
                }
                return new ProvDSAPublicKey(algorithm, (DSAPublicKey)key).getBaseKey();
            }
            else
            {
                // see if we can build a key from key.getEncoded()
                try
                {
                    return new AsymmetricDSAPublicKey(algorithm, SubjectPublicKeyInfo.getInstance(Utils.getKeyEncoding(key)));
                }
                catch (Exception e)
                {
                    throw new InvalidKeyException("cannot identify DSA public key: " + e.toString(), e);
                }
            }
        }
    };

    private static final PrivateKeyConverter<AsymmetricDSAPrivateKey> privateKeyConverter = new PrivateKeyConverter<AsymmetricDSAPrivateKey>()
    {
        public AsymmetricDSAPrivateKey convertKey(Algorithm algorithm, PrivateKey key)
            throws InvalidKeyException
        {
            if (key instanceof DSAPrivateKey)
            {
                if (key instanceof ProvDSAPrivateKey)
                {
                    return ((ProvDSAPrivateKey)key).getBaseKey();
                }
                return new ProvDSAPrivateKey(algorithm, (DSAPrivateKey)key).getBaseKey();
            }
            else
            {
                // see if we can build a key from key.getEncoded()
                try
                {
                    return new AsymmetricDSAPrivateKey(algorithm, PrivateKeyInfo.getInstance(Utils.getKeyEncoding(key)));
                }
                catch (Exception e)
                {
                    throw new InvalidKeyException("cannot identify DSA private key: " + e.toString(), e);
                }
            }
        }
    };

    public void configure(final BouncyCastleFipsProvider provider)
    {
        provider.addAlgorithmImplementation("AlgorithmParameters.DSA", PREFIX + "AlgorithmParametersSpi", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new DSAAlgorithmParameters();
            }
        });

        provider.addAlgorithmImplementation("AlgorithmParameterGenerator.DSA", PREFIX + "AlgorithmParameterGeneratorSpi", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new DSAAlgorithmParameterGenerator(provider);
            }
        });

        provider.addAlgorithmImplementation("KeyPairGenerator.DSA", PREFIX + "KeyPairGeneratorSpi", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyPairGenerator(provider);
            }
        });
        provider.addAlgorithmImplementation("KeyFactory.DSA", PREFIX + "KeyFactorySpi", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyFactorySpi();
            }
        });

        provider.addAlgorithmImplementation("Signature.SHA1WITHDSA", PREFIX + "DSASigner$stdDSA", generalDsaAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, new AdaptiveSignatureOperatorFactory(), publicKeyConverter, privateKeyConverter, FipsDSA.DSA);
            }
        });
        provider.addAlias("Signature", "SHA1WITHDSA", "DSA", "SHA1/DSA");

        provider.addAlgorithmImplementation("Signature.NONEWITHDSA", PREFIX + "DSASigner$noneDSA", generalDsaAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, new AdaptiveSignatureOperatorFactory(), publicKeyConverter, privateKeyConverter, FipsDSA.DSA.withDigestAlgorithm(null));
            }
        });
        provider.addAlias("Signature", "NONEWITHDSA", "RAWDSA");

        addSignatureAlgorithm(provider, "SHA224", "DSA", PREFIX + "DSASigner$dsa224", NISTObjectIdentifiers.dsa_with_sha224, generalDsaAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, new AdaptiveSignatureOperatorFactory(), publicKeyConverter, privateKeyConverter, FipsDSA.DSA.withDigestAlgorithm(FipsSHS.Algorithm.SHA224));
            }
        });
        addSignatureAlgorithm(provider, "SHA256", "DSA", PREFIX + "DSASigner$dsa256", NISTObjectIdentifiers.dsa_with_sha256, generalDsaAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, new AdaptiveSignatureOperatorFactory(), publicKeyConverter, privateKeyConverter, FipsDSA.DSA.withDigestAlgorithm(FipsSHS.Algorithm.SHA256));
            }
        });
        addSignatureAlgorithm(provider, "SHA384", "DSA", PREFIX + "DSASigner$dsa384", NISTObjectIdentifiers.dsa_with_sha384, generalDsaAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, new AdaptiveSignatureOperatorFactory(), publicKeyConverter, privateKeyConverter, FipsDSA.DSA.withDigestAlgorithm(FipsSHS.Algorithm.SHA384));
            }
        });
        addSignatureAlgorithm(provider, "SHA512", "DSA", PREFIX + "DSASigner$dsa512", NISTObjectIdentifiers.dsa_with_sha512, generalDsaAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, new AdaptiveSignatureOperatorFactory(), publicKeyConverter, privateKeyConverter, FipsDSA.DSA.withDigestAlgorithm(FipsSHS.Algorithm.SHA512));
            }
        });
        addSignatureAlgorithm(provider, "SHA512(224)", "DSA", PREFIX + "DSASigner$dsa512_224", null, generalDsaAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, new AdaptiveSignatureOperatorFactory(), publicKeyConverter, privateKeyConverter, FipsDSA.DSA.withDigestAlgorithm(FipsSHS.Algorithm.SHA512_224));
            }
        });
        addSignatureAlgorithm(provider, "SHA512(256)", "DSA", PREFIX + "DSASigner$dsa512_256", null, generalDsaAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSignature(provider, new AdaptiveSignatureOperatorFactory(), publicKeyConverter, privateKeyConverter, FipsDSA.DSA.withDigestAlgorithm(FipsSHS.Algorithm.SHA512_256));
            }
        });

        if (!CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            provider.addAlgorithmImplementation("Signature.DDSA", PREFIX + "SignatureSpi$ecDetDSA", generalDsaAttributes, new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseSignature(provider, getGeneralDSAFactory(), publicKeyConverter, privateKeyConverter, DSA.DDSA.withDigestAlgorithm(FipsSHS.Algorithm.SHA1));
                }
            }));
            provider.addAlgorithmImplementation("Signature.SHA1WITHDDSA", PREFIX + "SignatureSpi$DetDSA", generalDsaAttributes, new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseSignature(provider, getGeneralDSAFactory(), publicKeyConverter, privateKeyConverter, DSA.DDSA.withDigestAlgorithm(FipsSHS.Algorithm.SHA1));
                }
            }));
            provider.addAlgorithmImplementation("Signature.SHA224WITHDDSA", PREFIX + "SignatureSpi$DetDSA224", generalDsaAttributes, new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseSignature(provider, getGeneralDSAFactory(), publicKeyConverter, privateKeyConverter, DSA.DDSA.withDigestAlgorithm(FipsSHS.Algorithm.SHA224));
                }
            }));
            provider.addAlgorithmImplementation("Signature.SHA256WITHDDSA", PREFIX + "SignatureSpi$DetDSA256", generalDsaAttributes, new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseSignature(provider, getGeneralDSAFactory(), publicKeyConverter, privateKeyConverter, DSA.DDSA.withDigestAlgorithm(FipsSHS.Algorithm.SHA256));
                }
            }));
            provider.addAlgorithmImplementation("Signature.SHA384WITHDDSA", PREFIX + "SignatureSpi$DetDSA384", generalDsaAttributes, new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseSignature(provider, getGeneralDSAFactory(), publicKeyConverter, privateKeyConverter, DSA.DDSA.withDigestAlgorithm(FipsSHS.Algorithm.SHA384));
                }
            }));
            provider.addAlgorithmImplementation("Signature.SHA512WITHDDSA", PREFIX + "SignatureSpi$DetDSA512", generalDsaAttributes, new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseSignature(provider, getGeneralDSAFactory(), publicKeyConverter, privateKeyConverter, DSA.DDSA.withDigestAlgorithm(FipsSHS.Algorithm.SHA512));
                }
            }));
            provider.addAlgorithmImplementation("Signature.SHA512(224)WITHDDSA", PREFIX + "SignatureSpi$DetDSA512_224", generalDsaAttributes, new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseSignature(provider, getGeneralDSAFactory(), publicKeyConverter, privateKeyConverter, DSA.DDSA.withDigestAlgorithm(FipsSHS.Algorithm.SHA512_224));
                }
            }));
            provider.addAlgorithmImplementation("Signature.SHA512(256)WITHDDSA", PREFIX + "SignatureSpi$DetDSA512_256", generalDsaAttributes, new GuardedEngineCreator(new EngineCreator()
            {
                public Object createInstance(Object constructorParameter)
                {
                    return new BaseSignature(provider, getGeneralDSAFactory(), publicKeyConverter, privateKeyConverter, DSA.DDSA.withDigestAlgorithm(FipsSHS.Algorithm.SHA512_256));
                }
            }));

            provider.addAlias("Signature", "DDSA", "DETDSA");
            provider.addAlias("Signature", "SHA1WITHDDSA", "SHA1WITHDETDSA");
            provider.addAlias("Signature", "SHA224WITHDDSA", "SHA224WITHDETDSA");
            provider.addAlias("Signature", "SHA256WITHDDSA", "SHA256WITHDETDSA");
            provider.addAlias("Signature", "SHA384WITHDDSA", "SHA384WITHDETDSA");
            provider.addAlias("Signature", "SHA512WITHDDSA", "SHA512WITHDETDSA");
            provider.addAlias("Signature", "SHA512(224)WITHDDSA", "SHA512(224)WITHDETDSA");
            provider.addAlias("Signature", "SHA512(256)WITHDDSA", "SHA512(256)WITHDETDSA");
        }

        AsymmetricKeyInfoConverter keyFact = new KeyFactorySpi();

        provider.addAlias("Signature", "SHA1WITHDSA", dsaOids);

        for (int i = 0; i != dsaOids.length; i++)
        {
            registerOid(provider, dsaOids[i], "DSA", keyFact);
            registerOidAlgorithmParameters(provider, dsaOids[i], "DSA");
        }
    }

    private static class AdaptiveSignatureOperatorFactory<T extends org.bouncycastle.crypto.Parameters>
        implements SignatureOperatorFactory<FipsDSA.Parameters>
    {
        public final OutputSignerUsingSecureRandom createSigner(AsymmetricPrivateKey key, FipsDSA.Parameters parameters)
        {
            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                return (OutputSignerUsingSecureRandom)fipsDsaFactory.createSigner(key, parameters);
            }
            else
            {
                AsymmetricDSAPrivateKey k = (AsymmetricDSAPrivateKey)key;

                int keyStrength = k.getDomainParameters().getP().bitLength();
                if (keyStrength < 2048 || keyStrength > 3072)
                {
                    DSA.Parameters params = DSA.DSA.withDigestAlgorithm(parameters.getDigestAlgorithm());

                    return (OutputSignerUsingSecureRandom)getGeneralDSAFactory().createSigner(key, params);
                }
                else
                {
                    return (OutputSignerUsingSecureRandom)fipsDsaFactory.createSigner(key, parameters);
                }
            }
        }

        public final OutputVerifier createVerifier(AsymmetricPublicKey key, FipsDSA.Parameters parameters)
        {
            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                return fipsDsaFactory.createVerifier(key, parameters);
            }
            else
            {
                AsymmetricDSAPublicKey k = (AsymmetricDSAPublicKey)key;

                int keyStrength = k.getDomainParameters().getP().bitLength();
                if (keyStrength < 2048 || keyStrength > 3072)
                {
                    DSA.Parameters params = DSA.DSA.withDigestAlgorithm(parameters.getDigestAlgorithm());

                    return getGeneralDSAFactory().createVerifier(key, params);
                }
                else
                {
                    return fipsDsaFactory.createVerifier(key, parameters);
                }
            }
        }
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

            if (spec.isAssignableFrom(DSAPublicKeySpec.class) && key instanceof DSAPublicKey)
            {
                DSAPublicKey k = (DSAPublicKey)key;

                return new DSAPublicKeySpec(k.getY(), k.getParams().getP(), k.getParams().getQ(), k.getParams().getG());
            }
            else if (spec.isAssignableFrom(DSAPrivateKeySpec.class) && key instanceof DSAPrivateKey)
            {
                DSAPrivateKey k = (DSAPrivateKey)key;

                return new DSAPrivateKeySpec(k.getX(), k.getParams().getP(), k.getParams().getQ(), k.getParams().getG());
            }

            return super.engineGetKeySpec(key, spec);
        }

        protected Key engineTranslateKey(
            Key key)
            throws InvalidKeyException
        {
            if (key instanceof PublicKey)
            {
                return new ProvDSAPublicKey(publicKeyConverter.convertKey(FipsDSA.ALGORITHM, (PublicKey)key));
            }
            else if (key instanceof PrivateKey)
            {
                return new ProvDSAPrivateKey(privateKeyConverter.convertKey(FipsDSA.ALGORITHM, (PrivateKey)key));
            }

            if (key != null)
            {
                throw new InvalidKeyException("Key type unrecognized: " + key.getClass().getName());
            }

            throw new InvalidKeyException("Key is null");
        }

        public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
            throws IOException
        {
            return new ProvDSAPrivateKey(new AsymmetricDSAPrivateKey(FipsDSA.ALGORITHM, keyInfo));
        }

        public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
            throws IOException
        {
            return new ProvDSAPublicKey(new AsymmetricDSAPublicKey(FipsDSA.ALGORITHM, keyInfo));
        }

        protected PrivateKey engineGeneratePrivate(
            KeySpec keySpec)
            throws InvalidKeySpecException
        {
            if (keySpec instanceof DSAPrivateKeySpec)
            {
                return new ProvDSAPrivateKey(FipsDSA.ALGORITHM, (DSAPrivateKeySpec)keySpec);
            }

            return super.engineGeneratePrivate(keySpec);
        }

        protected PublicKey engineGeneratePublic(
            KeySpec keySpec)
            throws InvalidKeySpecException
        {
            if (keySpec instanceof DSAPublicKeySpec)
            {
                try
                {
                    return new ProvDSAPublicKey(FipsDSA.ALGORITHM, (DSAPublicKeySpec)keySpec);
                }
                catch (Exception e)
                {
                    throw new InvalidKeySpecException("invalid KeySpec: " + e.getMessage(), e);
                }
            }

            return super.engineGeneratePublic(keySpec);
        }
    }

    static class KeyPairGenerator
        extends java.security.KeyPairGenerator
    {
        private final BouncyCastleFipsProvider fipsProvider;

        AsymmetricKeyPairGenerator engine;
        int strength = 2048;
        private SecureRandom random;
        boolean initialised = false;

        public KeyPairGenerator(BouncyCastleFipsProvider fipsProvider)
        {
            super("DSA");
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
            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                if (strength != 2048 && strength != 3072)
                {
                    throw new InvalidParameterException("strength must be 2048 or 3072");
                }
            }
            else
            {
                if (strength < 512|| strength > 4096 || strength % 64 != 0)
                {
                    throw new InvalidParameterException("strength must be from 512 - 4096 and a multiple of 64");
                }
            }

            this.strength = strength;
            this.random = random;
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
            if (!(params instanceof DSAParameterSpec))
            {
                throw new InvalidAlgorithmParameterException("AlgorithmParameterSpec not recognized: " + params.getClass().getName());
            }
            DSAParameterSpec dsaParams = (DSAParameterSpec)params;

            try
            {
                if (dsaParams.getP().bitLength() < 2048)
                {
                    engine = new DSA.KeyPairGenerator(new DSA.KeyGenParameters(new DSADomainParameters(dsaParams.getP(), dsaParams.getQ(), dsaParams.getG())), random);
                }
                else
                {
                    engine = new FipsDSA.KeyPairGenerator(new FipsDSA.KeyGenParameters(new DSADomainParameters(dsaParams.getP(), dsaParams.getQ(), dsaParams.getG())), random);
                }
            }
            catch (FipsUnapprovedOperationError e)
            {
                throw new InvalidAlgorithmParameterException(e.getMessage(), e);
            }

            initialised = true;
        }

        public KeyPair generateKeyPair()
        {
            if (!initialised)
            {
                DSADomainParameters params;
                if (strength < 2048)
                {
                    params = CryptoServicesRegistrar.getSizedProperty(CryptoServicesRegistrar.Property.DSA_DEFAULT_PARAMS, strength);

                    if (params == null)
                    {
                        DSA.DomainParametersGenerator pGen = new DSA.DomainParametersGenerator(new DSA.DomainGenParameters(strength), random);

                        params = pGen.generateDomainParameters();
                    }

                    engine = new DSA.KeyPairGenerator(new DSA.KeyGenParameters(params), random);
                }
                else
                {
                    params = CryptoServicesRegistrar.getSizedProperty(CryptoServicesRegistrar.Property.DSA_DEFAULT_PARAMS, strength);

                    if (params == null)
                    {
                        FipsDSA.DomainParametersGenerator pGen = new FipsDSA.DomainParametersGenerator(new FipsDSA.DomainGenParameters(strength), random);

                        params = pGen.generateDomainParameters();
                    }

                    engine = new FipsDSA.KeyPairGenerator(new FipsDSA.KeyGenParameters(params), random);
                }

                initialised = true;
            }

            AsymmetricKeyPair pair = engine.generateKeyPair();

            return new KeyPair(new ProvDSAPublicKey((AsymmetricDSAPublicKey)pair.getPublicKey()), new ProvDSAPrivateKey((AsymmetricDSAPrivateKey)pair.getPrivateKey()));
        }
    }

    static class DSAAlgorithmParameterGenerator
        extends java.security.AlgorithmParameterGeneratorSpi
    {
        protected SecureRandom random;
        protected int strength = 1024;
        private final BouncyCastleFipsProvider fipsProvider;

        private DSA.DomainParametersGenerator genGen;
        private FipsDSA.DomainParametersGenerator fipsGen;

        DSAAlgorithmParameterGenerator(BouncyCastleFipsProvider fipsProvider)
        {
            this.fipsProvider = fipsProvider;
        }

        protected void engineInit(
            int strength,
            SecureRandom random)
        {
            if (strength < 512 || strength > 3072)
            {
                throw new InvalidParameterException("strength must be from 512 - 3072");
            }

            if (strength <= 1024 && strength % 64 != 0)
            {
                throw new InvalidParameterException("strength must be a multiple of 64 below 1024 bits.");
            }

            if (strength > 1024 && strength % 1024 != 0)
            {
                throw new InvalidParameterException("strength must be a multiple of 1024 above 1024 bits.");
            }

            this.strength = strength;
            this.random = random;

            if (strength < 2048)
            {
                if (CryptoServicesRegistrar.isInApprovedOnlyMode())
                {
                    throw new InvalidParameterException("Attempt to create unapproved parameters in approved only mode");
                }

                genGen = new DSA.DomainParametersGenerator(new DSA.DomainGenParameters(strength), random);
                fipsGen = null;
            }
            else
            {
                fipsGen = new FipsDSA.DomainParametersGenerator(new FipsDSA.DomainGenParameters(strength), random);
                genGen = null;
            }
        }

        protected void engineInit(
            AlgorithmParameterSpec genParamSpec,
            SecureRandom random)
            throws InvalidAlgorithmParameterException
        {
            if (genParamSpec instanceof DSADomainParametersGenerationParameterSpec)
            {
                DSADomainParametersGenerationParameterSpec spec = (DSADomainParametersGenerationParameterSpec)genParamSpec;

                if (!(spec.getDigestAlgorithm() instanceof FipsAlgorithm))
                {
                    throw new InvalidAlgorithmParameterException("Digest algorithm must be a FIPS algorithm");
                }

                if (spec.getP() != null)
                {
                    fipsGen = new FipsDSA.DomainParametersGenerator((FipsDigestAlgorithm)spec.getDigestAlgorithm(), new FipsDSA.DomainGenParameters(spec.getP(), spec.getQ(), spec.getSeed(), spec.getUsageIndex()), random);
                }
                else
                {
                    fipsGen = new FipsDSA.DomainParametersGenerator((FipsDigestAlgorithm)spec.getDigestAlgorithm(), new FipsDSA.DomainGenParameters(spec.getL(), spec.getN(), spec.getCertainty(), spec.getUsageIndex()), random);
                }

                genGen = null;
            }
            else if (genParamSpec != null)
            {
                throw new InvalidAlgorithmParameterException("Unknown AlgorithmParameterSpec passed to DSA parameters generator: " + genParamSpec.getClass().getName());
            }
            else
            {
                throw new InvalidAlgorithmParameterException("null AlgorithmParameterSpec passed to DSA parameters generator");
            }
        }

        protected AlgorithmParameters engineGenerateParameters()
        {
            if (random == null)
            {
                random = fipsProvider.getDefaultSecureRandom();
            }

            DSADomainParameters p;
            if (fipsGen != null)
            {
                p = fipsGen.generateDomainParameters();
            }
            else if (genGen != null)
            {
                p = genGen.generateDomainParameters();
            }
            else
            {
                fipsGen = new FipsDSA.DomainParametersGenerator(new FipsDSA.DomainGenParameters(strength), random);
                p = fipsGen.generateDomainParameters();
            }

            AlgorithmParameters params;

            try
            {
                params = AlgorithmParameters.getInstance("DSA", fipsProvider);
                params.init(new DSADomainParameterSpec(p.getP(), p.getQ(), p.getG(), p.getValidationParameters()));
            }
            catch (Exception e)
            {
                throw new IllegalStateException(e.getMessage());
            }

            return params;
        }
    }

    static class DSAAlgorithmParameters
        extends X509AlgorithmParameters
    {
        DSADomainParameterSpec currentSpec;

        protected boolean isASN1FormatString(String format)
        {
            return format == null || format.equals("ASN.1");
        }

        /**
         * Return the X.509 ASN.1 structure DSAParameter.
         * <p/>
         * <pre>
         *  DSAParameter ::= SEQUENCE {
         *                   prime INTEGER, -- p
         *                   subprime INTEGER, -- q
         *                   base INTEGER, -- g}
         * </pre>
         */
        protected byte[] localGetEncoded()
            throws IOException
        {
            DSAParameter dsaP = new DSAParameter(currentSpec.getP(), currentSpec.getQ(), currentSpec.getG());

            return dsaP.getEncoded(ASN1Encoding.DER);
        }

        protected AlgorithmParameterSpec localEngineGetParameterSpec(
            Class paramSpec)
            throws InvalidParameterSpecException
        {
            if (paramSpec == DSAParameterSpec.class || paramSpec == DSADomainParameterSpec.class || paramSpec == AlgorithmParameterSpec.class)
            {
                return currentSpec;
            }

            throw new InvalidParameterSpecException("AlgorithmParameterSpec not recognized: " + paramSpec.getName());
        }

        protected void engineInit(
            AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException
        {
            if (!(paramSpec instanceof DSAParameterSpec))
            {
                throw new InvalidParameterSpecException("DSAParameterSpec required to initialise a DSA algorithm parameters object");
            }

            if (paramSpec instanceof DSADomainParameterSpec)
            {
                this.currentSpec = (DSADomainParameterSpec)paramSpec;
            }
            else
            {
                DSAParameterSpec spec = (DSAParameterSpec)paramSpec;
                this.currentSpec = new DSADomainParameterSpec(spec.getP(), spec.getQ(), spec.getG());
            }
        }

        protected void localInit(
            byte[] params)
            throws IOException
        {
            DSAParameter dsaP = DSAParameter.getInstance(ASN1Primitive.fromByteArray(params));

            currentSpec = new DSADomainParameterSpec(dsaP.getP(), dsaP.getQ(), dsaP.getG());
        }

        protected String engineToString()
        {
            return "DSA Parameters";
        }
    }
}
