package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.pkcs.DHParameter;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.DomainParameters;
import org.bouncycastle.asn1.x9.ValidationParams;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.AgreementFactory;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.asymmetric.AsymmetricDHPrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricDHPublicKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricKeyPair;
import org.bouncycastle.crypto.asymmetric.DHDomainParameters;
import org.bouncycastle.crypto.asymmetric.DHValidationParameters;
import org.bouncycastle.crypto.fips.FipsDH;
import org.bouncycastle.crypto.fips.FipsKDF;
import org.bouncycastle.crypto.fips.FipsUnapprovedOperationError;
import org.bouncycastle.jcajce.spec.DHDomainParameterSpec;
import org.bouncycastle.jcajce.spec.MQVParameterSpec;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;

class ProvDH
    extends AsymmetricAlgorithmProvider
{
    private static final Map<String, String> generalDhAttributes = new HashMap<String, String>();

    static
    {
        generalDhAttributes.put("SupportedKeyClasses", "javax.crypto.interfaces.DHPublicKey|javax.crypto.interfaces.DHPrivateKey");
        generalDhAttributes.put("SupportedKeyFormats", "PKCS#8|X.509");
    }

    static final PublicKeyConverter<AsymmetricDHPublicKey> publicKeyConverter = new PublicKeyConverter<AsymmetricDHPublicKey>()
    {
        public AsymmetricDHPublicKey convertKey(Algorithm algorithm, PublicKey key)
            throws InvalidKeyException
        {
            if (key instanceof DHPublicKey)
            {
                if (key instanceof ProvDHPublicKey)
                {
                    return ((ProvDHPublicKey)key).getBaseKey();
                }
                return new ProvDHPublicKey(algorithm, (DHPublicKey)key).getBaseKey();
            }
            else
            {
                // see if we can build a key from key.getEncoded()
                try
                {
                    return new AsymmetricDHPublicKey(algorithm, SubjectPublicKeyInfo.getInstance(Utils.getKeyEncoding(key)));
                }
                catch (Exception e)
                {
                    throw new InvalidKeyException("Cannot identify DH public key: " + e.getMessage(), e);
                }
            }
        }
    };

    static final PrivateKeyConverter<AsymmetricDHPrivateKey> privateKeyConverter = new PrivateKeyConverter<AsymmetricDHPrivateKey>()
    {
        public AsymmetricDHPrivateKey convertKey(Algorithm algorithm, PrivateKey key)
            throws InvalidKeyException
        {
            if (key instanceof DHPrivateKey)
            {
                if (key instanceof ProvDHPrivateKey)
                {
                    return ((ProvDHPrivateKey)key).getBaseKey();
                }
                return new ProvDHPrivateKey(algorithm, (DHPrivateKey)key).getBaseKey();
            }
            else
            {
                // see if we can build a key from key.getEncoded()
                try
                {
                    return new AsymmetricDHPrivateKey(algorithm, PrivateKeyInfo.getInstance(Utils.getKeyEncoding(key)));
                }
                catch (Exception e)
                {
                    throw new InvalidKeyException("Cannot identify DH private key: " + e.getMessage(), e);
                }
            }
        }
    };

    static class KeyFactorySpi
        extends BaseKeyFactory
    {
        public KeyFactorySpi()
        {
        }

        protected PrivateKey engineGeneratePrivate(
            KeySpec keySpec)
            throws InvalidKeySpecException
        {
            if (keySpec instanceof DHPrivateKeySpec)
            {
                return new ProvDHPrivateKey(FipsDH.ALGORITHM, (DHPrivateKeySpec)keySpec);
            }

            return super.engineGeneratePrivate(keySpec);
        }

        protected PublicKey engineGeneratePublic(
            KeySpec keySpec)
            throws InvalidKeySpecException
        {
            if (keySpec instanceof DHPublicKeySpec)
            {
                try
                {
                    return new ProvDHPublicKey(FipsDH.ALGORITHM, (DHPublicKeySpec)keySpec);
                }
                catch (Exception e)
                {
                    throw new InvalidKeySpecException("invalid KeySpec: " + e.getMessage(), e);
                }
            }
            return super.engineGeneratePublic(keySpec);
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

            if (spec.isAssignableFrom(DHPrivateKeySpec.class) && key instanceof DHPrivateKey)
            {
                DHPrivateKey k = (DHPrivateKey)key;

                return new DHPrivateKeySpec(k.getX(), k.getParams().getP(), k.getParams().getG());
            }
            else if (spec.isAssignableFrom(DHPublicKeySpec.class) && key instanceof DHPublicKey)
            {
                DHPublicKey k = (DHPublicKey)key;

                return new DHPublicKeySpec(k.getY(), k.getParams().getP(), k.getParams().getG());
            }

            return super.engineGetKeySpec(key, spec);
        }

        protected Key engineTranslateKey(
            Key key)
            throws InvalidKeyException
        {
            if (key instanceof PublicKey)
            {
                return new ProvDHPublicKey(publicKeyConverter.convertKey(FipsDH.ALGORITHM, (PublicKey)key));
            }
            else if (key instanceof PrivateKey)
            {
                return new ProvDHPrivateKey(privateKeyConverter.convertKey(FipsDH.ALGORITHM, (PrivateKey)key));
            }

            if (key != null)
            {
                throw new InvalidKeyException("Key type unrecognized: " + key.getClass().getName());
            }

            throw new InvalidKeyException("Key is null");
        }

        public PrivateKey generatePrivate(PrivateKeyInfo info)
            throws IOException
        {
            return new ProvDHPrivateKey(new AsymmetricDHPrivateKey(FipsDH.ALGORITHM, info));
        }

        public PublicKey generatePublic(SubjectPublicKeyInfo info)
            throws IOException
        {
            return new ProvDHPublicKey(new AsymmetricDHPublicKey(FipsDH.ALGORITHM, info));
        }
    }

    static class KeyPairGeneratorSpi
        extends java.security.KeyPairGenerator
    {
        private final BouncyCastleFipsProvider fipsProvider;
        private FipsDH.KeyGenParameters param;
        private FipsDH.KeyPairGenerator engine;

        private int strength = DHUtils.MIN_FIPS_SIZE;
        private SecureRandom random = null;
        private boolean initialised = false;

        public KeyPairGeneratorSpi(BouncyCastleFipsProvider fipsProvider)
        {
            super("DH");
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
            if (!(params instanceof DHParameterSpec))
            {
                throw new InvalidAlgorithmParameterException("AlgorithmParameterSpec not recognized: " + params.getClass().getName());
            }

            DHParameterSpec dhParams = (DHParameterSpec)params;

            if (dhParams instanceof DHDomainParameterSpec)
            {
                param = new FipsDH.KeyGenParameters(new DHDomainParameters(dhParams.getP(), ((DHDomainParameterSpec)dhParams).getQ(), dhParams.getG(), dhParams.getL()));
            }
            else
            {
                param = new FipsDH.KeyGenParameters(new DHDomainParameters(dhParams.getP(), null, dhParams.getG(), dhParams.getL()));
            }

            try
            {
                engine = new FipsDH.KeyPairGenerator(param, random);
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
                DHDomainParameters dhParams = CryptoServicesRegistrar.getSizedProperty(CryptoServicesRegistrar.Property.DH_DEFAULT_PARAMS, strength);

                if (dhParams != null)
                {
                    param = new FipsDH.KeyGenParameters(dhParams);
                }
                else
                {
                    FipsDH.DomainParametersGenerator gen = new FipsDH.DomainParametersGenerator(new FipsDH.DomainGenParameters(strength), random);

                    param = new FipsDH.KeyGenParameters(gen.generateDomainParameters());
                }

                engine = new FipsDH.KeyPairGenerator(param, random);
                initialised = true;
            }

            AsymmetricKeyPair pair = engine.generateKeyPair();
            AsymmetricDHPublicKey pub = (AsymmetricDHPublicKey)pair.getPublicKey();
            AsymmetricDHPrivateKey priv = (AsymmetricDHPrivateKey)pair.getPrivateKey();

            return new KeyPair(new ProvDHPublicKey(pub), new ProvDHPrivateKey(priv));
        }
    }

    static class AlgorithmParametersSpi
        extends DHAlgorithmParametersSpi
    {
        AlgorithmParametersSpi()
        {
            super("DH");
        }

        /**
         * Return the X.509 ASN.1 structure DHParameter.
         * <p/>
         * <pre>
         *  DHParameter ::= SEQUENCE {
         *                   prime INTEGER, -- p
         *                   base INTEGER, -- g}
         * </pre>
         */
        protected byte[] localGetEncoded()
            throws IOException
        {
            ASN1Encodable param = new DHParameter(currentSpec.getP(), currentSpec.getG(), currentSpec.getL());

            return param.toASN1Primitive().getEncoded(ASN1Encoding.DER);
        }

        protected void localInit(
            byte[] params)
            throws IOException
        {
            DHParameter param = DHParameter.getInstance(params);

            if (param.getL() == null)
            {
                currentSpec = new DHDomainParameterSpec(param.getP(), null, param.getG());
            }
            else
            {
                currentSpec = new DHDomainParameterSpec(param.getP(), null, param.getG(), param.getL().intValue());
            }
        }

        protected String engineToString()
        {
            return "DH Parameters";
        }
    }

    static class MQVAlgorithmParametersSpi
        extends DHAlgorithmParametersSpi
    {
        MQVAlgorithmParametersSpi()
        {
            super("MQV");
        }

        /**
         * Return DomainParameters from X9
         */
        protected byte[] localGetEncoded()
            throws IOException
        {
            ASN1Encodable param;

            DHDomainParameterSpec domainParameterSpec = this.currentSpec;
            DHValidationParameters dhValidationParameters = domainParameterSpec.getValidationParameters();

            try
            {
                if (dhValidationParameters != null)
                {
                    param = new DomainParameters(this.currentSpec.getP(), this.currentSpec.getG(), domainParameterSpec.getQ(), domainParameterSpec.getJ(), new ValidationParams(dhValidationParameters.getSeed(), dhValidationParameters.getCounter()));
                }
                else
                {
                    param = new DomainParameters(this.currentSpec.getP(), this.currentSpec.getG(), domainParameterSpec.getQ(), domainParameterSpec.getJ(), null);
                }
            }
            catch (Exception e)
            {
                throw new ProvIOException("Exception creating parameters: " + e.getMessage(), e);
            }

            return param.toASN1Primitive().getEncoded(ASN1Encoding.DER);
        }

        protected void engineInit(
            AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException
        {
            if (!(paramSpec instanceof DHDomainParameterSpec))
            {
                throw new InvalidParameterSpecException("DHDomainParameterSpec required to initialise a MQV/X9 AlgorithmParameters");
            }

            this.currentSpec = (DHDomainParameterSpec)paramSpec;
        }

        protected void localInit(
            byte[] params)
            throws IOException
        {
            DomainParameters param = DomainParameters.getInstance(params);

            if (param.getValidationParams() != null)
            {
                currentSpec = new DHDomainParameterSpec(param.getP(), param.getQ(), param.getG(), param.getJ(), 0,
                    new DHValidationParameters(param.getValidationParams().getSeed(), param.getValidationParams().getPgenCounter().intValue()));
            }
            else
            {
                currentSpec = new DHDomainParameterSpec(param.getP(), param.getQ(), param.getG(), param.getJ(), 0, null);
            }
        }

        protected String engineToString()
        {
            return "MQV/X9 DH Parameters";
        }
    }

    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".dh.";

    private static final AgreementFactory fipsDHFactory = new FipsDH.DHAgreementFactory();
    private static final AgreementFactory fipsMQVFactory = new FipsDH.MQVAgreementFactory();

    private static final ParametersCreator mqvParametersCreator = new ParametersCreator()
    {

        public Parameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
            throws InvalidAlgorithmParameterException
        {
            try
            {
                if (!(spec instanceof MQVParameterSpec))
                {
                    throw new InvalidAlgorithmParameterException("MQV can only take an MQVParameterSpec");
                }

                MQVParameterSpec mqvSpec = (MQVParameterSpec)spec;

                if (mqvSpec.getEphemeralPublicKey() != null)
                {
                    return FipsDH.MQV.using(publicKeyConverter.convertKey(FipsDH.MQV.getAlgorithm(), mqvSpec.getEphemeralPublicKey()),
                        privateKeyConverter.convertKey(FipsDH.MQV.getAlgorithm(), mqvSpec.getEphemeralPrivateKey()),
                        publicKeyConverter.convertKey(FipsDH.MQV.getAlgorithm(), mqvSpec.getOtherPartyEphemeralKey()));
                }
                else
                {
                    return FipsDH.MQV.using(
                        privateKeyConverter.convertKey(FipsDH.MQV.getAlgorithm(), mqvSpec.getEphemeralPrivateKey()),
                        publicKeyConverter.convertKey(FipsDH.MQV.getAlgorithm(), mqvSpec.getOtherPartyEphemeralKey()));
                }
            }
            catch (InvalidKeyException e)
            {
                throw new InvalidAlgorithmParameterException("Unable to convert keys in MQVParameterSpec: " + e.getMessage(), e);
            }
        }
    };

    private static final ParametersCreator parametersCreator = new ParametersCreator()
    {

        public Parameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
            throws InvalidAlgorithmParameterException
        {
            if (spec != null && !(spec instanceof UserKeyingMaterialSpec))
            {
                throw new InvalidAlgorithmParameterException("DH can only take a UserKeyingMaterialSpec");
            }
            return FipsDH.DH;
        }
    };

    public void configure(final BouncyCastleFipsProvider provider)
    {
        provider.addAlgorithmImplementation("KeyPairGenerator.DH", PREFIX + "KeyPairGeneratorSpi", generalDhAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyPairGeneratorSpi(provider);
            }
        });
        provider.addAlias("Alg.Alias.KeyPairGenerator.DIFFIEHELLMAN", "DH");
        provider.addAlias("Alg.Alias.KeyPairGenerator.MQV", "DH");

        provider.addAlgorithmImplementation("KeyAgreement.DH", PREFIX + "KeyAgreementSpi", generalDhAttributes, new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseAgreement(new FipsDH.DHAgreementFactory(), publicKeyConverter, privateKeyConverter, parametersCreator);
            }
        });
        provider.addAlias("Alg.Alias.KeyAgreement.DIFFIEHELLMAN", "DH");

        provider.addAlgorithmImplementation("KeyFactory.DH", PREFIX + "KeyFactorySpi", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyFactorySpi();
            }
        });
        provider.addAlias("Alg.Alias.KeyFactory.DIFFIEHELLMAN", "DH");
        provider.addAlias("Alg.Alias.KeyFactory.MQV", "DH");

        AsymmetricKeyInfoConverter converter = new KeyFactorySpi();

        registerOid(provider, X9ObjectIdentifiers.dhpublicnumber, "DH", converter);
        registerOid(provider, PKCSObjectIdentifiers.dhKeyAgreement, "DH", converter);

        provider.addAlgorithmImplementation("AlgorithmParameters.DH", PREFIX + "AlgorithmParametersSpi", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new AlgorithmParametersSpi();
            }
        });
        provider.addAlias("Alg.Alias.AlgorithmParameters.DIFFIEHELLMAN", "DH");

        provider.addAlgorithmImplementation("AlgorithmParameterGenerator.DH", PREFIX + "AlgorithmParameterGeneratorSpi", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new DHAlgorithmParameterGeneratorSpi(provider, "DH");
            }
        });
        provider.addAlias("Alg.Alias.AlgorithmParameterGenerator.DIFFIEHELLMAN", "DH");

        provider.addAlgorithmImplementation("AlgorithmParameters.MQV", PREFIX + "MQVAlgorithmParametersSpi", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new MQVAlgorithmParametersSpi();
            }
        });
        provider.addAlgorithmImplementation("AlgorithmParameterGenerator.MQV", PREFIX + "MQVAlgorithmParameterGeneratorSpi", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new DHAlgorithmParameterGeneratorSpi(provider, "MQV");
            }
        });

        addX963DHAlgorithm(provider, "SHA1", FipsKDF.AgreementKDFPRF.SHA1);
        addX963DHAlgorithm(provider, "SHA224", FipsKDF.AgreementKDFPRF.SHA224);
        addX963DHAlgorithm(provider, "SHA256", FipsKDF.AgreementKDFPRF.SHA256);
        addX963DHAlgorithm(provider, "SHA384", FipsKDF.AgreementKDFPRF.SHA384);
        addX963DHAlgorithm(provider, "SHA512", FipsKDF.AgreementKDFPRF.SHA512);
        addX963DHAlgorithm(provider, "SHA512(224)", FipsKDF.AgreementKDFPRF.SHA512_224);
        addX963DHAlgorithm(provider, "SHA512(256)", FipsKDF.AgreementKDFPRF.SHA512_256);

        addX963MQVAlgorithm(provider, "SHA1", FipsKDF.AgreementKDFPRF.SHA1);
        addX963MQVAlgorithm(provider, "SHA224", FipsKDF.AgreementKDFPRF.SHA224);
        addX963MQVAlgorithm(provider, "SHA256", FipsKDF.AgreementKDFPRF.SHA256);
        addX963MQVAlgorithm(provider, "SHA384", FipsKDF.AgreementKDFPRF.SHA384);
        addX963MQVAlgorithm(provider, "SHA512", FipsKDF.AgreementKDFPRF.SHA512);
        addX963MQVAlgorithm(provider, "SHA512(224)", FipsKDF.AgreementKDFPRF.SHA512_224);
        addX963MQVAlgorithm(provider, "SHA512(256)", FipsKDF.AgreementKDFPRF.SHA512_256);

        addConcatDHAlgorithm(provider, "SHA1", FipsKDF.AgreementKDFPRF.SHA1);
        addConcatDHAlgorithm(provider, "SHA224", FipsKDF.AgreementKDFPRF.SHA224);
        addConcatDHAlgorithm(provider, "SHA256", FipsKDF.AgreementKDFPRF.SHA256);
        addConcatDHAlgorithm(provider, "SHA384", FipsKDF.AgreementKDFPRF.SHA384);
        addConcatDHAlgorithm(provider, "SHA512", FipsKDF.AgreementKDFPRF.SHA512);
        addConcatDHAlgorithm(provider, "SHA512(224)", FipsKDF.AgreementKDFPRF.SHA512_224);
        addConcatDHAlgorithm(provider, "SHA512(256)", FipsKDF.AgreementKDFPRF.SHA512_256);

        addConcatMQVAlgorithm(provider, "SHA1", FipsKDF.AgreementKDFPRF.SHA1);
        addConcatMQVAlgorithm(provider, "SHA224", FipsKDF.AgreementKDFPRF.SHA224);
        addConcatMQVAlgorithm(provider, "SHA256", FipsKDF.AgreementKDFPRF.SHA256);
        addConcatMQVAlgorithm(provider, "SHA384", FipsKDF.AgreementKDFPRF.SHA384);
        addConcatMQVAlgorithm(provider, "SHA512", FipsKDF.AgreementKDFPRF.SHA512);
        addConcatMQVAlgorithm(provider, "SHA512(224)", FipsKDF.AgreementKDFPRF.SHA512_224);
        addConcatMQVAlgorithm(provider, "SHA512(256)", FipsKDF.AgreementKDFPRF.SHA512_256);
    }

    private void addX963DHAlgorithm(BouncyCastleFipsProvider provider, String digest, final FipsKDF.AgreementKDFPRF prf)
    {
        addKeyAgreementAlgorithm(provider, "DHWITH" + digest + "KDF", PREFIX + "KeyAgreementSpi$DH" + digest + "KDF", generalDhAttributes, new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                return new BaseAgreement(fipsDHFactory, publicKeyConverter, privateKeyConverter, parametersCreator, FipsKDF.X963.withPRF(prf));
            }
        });
    }

    private void addX963MQVAlgorithm(BouncyCastleFipsProvider provider, String digest, final FipsKDF.AgreementKDFPRF prf)
    {
        addKeyAgreementAlgorithm(provider, "MQVWITH" + digest + "KDF", PREFIX + "KeyAgreementSpi$MQV" + digest + "KDF", generalDhAttributes, new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                return new BaseAgreement(fipsMQVFactory, publicKeyConverter, privateKeyConverter, mqvParametersCreator, FipsKDF.X963.withPRF(prf));
            }
        });
    }

    private void addConcatDHAlgorithm(BouncyCastleFipsProvider provider, String digest, final FipsKDF.AgreementKDFPRF prf)
    {
        addKeyAgreementAlgorithm(provider, "DHWITH" + digest + "CKDF", PREFIX + "KeyAgreementSpi$DH" + digest + "CKDF", generalDhAttributes, new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                return new BaseAgreement(fipsDHFactory, publicKeyConverter, privateKeyConverter, parametersCreator, FipsKDF.CONCATENATION.withPRF(prf));
            }
        });
    }

    private void addConcatMQVAlgorithm(BouncyCastleFipsProvider provider, String digest, final FipsKDF.AgreementKDFPRF prf)
    {
        addKeyAgreementAlgorithm(provider, "MQVWITH" + digest + "CKDF", PREFIX + "KeyAgreementSpi$MQV" + digest + "CKDF", generalDhAttributes, new EngineCreator()
                {
                    public Object createInstance(Object constructorParameter)
                    {
                return new BaseAgreement(fipsMQVFactory, publicKeyConverter, privateKeyConverter, mqvParametersCreator, FipsKDF.CONCATENATION.withPRF(prf));
            }
        });
    }
}
