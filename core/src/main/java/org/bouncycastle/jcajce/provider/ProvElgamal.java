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
import java.security.spec.KeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.oiw.ElGamalParameter;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DigestAlgorithm;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.asymmetric.AsymmetricDHPrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricDHPublicKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricKeyPair;
import org.bouncycastle.crypto.asymmetric.DHDomainParameters;
import org.bouncycastle.crypto.fips.FipsDH;
import org.bouncycastle.crypto.general.ElGamal;
import org.bouncycastle.jcajce.spec.DHDomainParameterSpec;

/**
 * Elgamal cipher support (yes, that's actually the correct spelling...)
 */
class ProvElgamal
    extends AsymmetricAlgorithmProvider
{
    private static final Map<String, String> generalDhAttributes = new HashMap<String, String>();

    static
    {
        generalDhAttributes.put("SupportedKeyClasses", "javax.crypto.interfaces.DHPublicKey|javax.crypto.interfaces.DHPrivateKey");
        generalDhAttributes.put("SupportedKeyFormats", "PKCS#8|X.509");
    }

    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".elgamal.";

    public void configure(final BouncyCastleFipsProvider provider)
    {
        provider.addAlgorithmImplementation("AlgorithmParameterGenerator.ELGAMAL", PREFIX + "AlgorithmParameterGeneratorSpi", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new DHAlgorithmParameterGeneratorSpi(provider, "ELGAMAL");
            }
        }));

        provider.addAlgorithmImplementation("AlgorithmParameters.ELGAMAL", PREFIX + "AlgorithmParametersSpi", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new AlgorithmParametersSpi();
            }
        }));

        provider.addAlgorithmImplementation("Cipher.ELGAMAL", PREFIX + "CipherSpi", generalDhAttributes, new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSingleBlockCipher.Builder(provider, ElGamal.ALGORITHM, ElGamal.WRAP_PKCS1v1_5.getAlgorithm(), ElGamal.WRAP_OAEP.getAlgorithm())
                    .withGeneralOperators(new ElGamal.OperatorFactory(), new ElGamal.KeyWrapOperatorFactory())
                    .withPublicKeyConverter(ProvDH.publicKeyConverter)
                    .withPrivateKeyConverter(ProvDH.privateKeyConverter)
                    .withParametersCreatorProvider(new ParametersCreatorProvider()
                    {
                        public ParametersCreator get(final Parameters parameters)
                        {
                            return new ParametersCreator()
                            {

                                public Parameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
                                    throws InvalidAlgorithmParameterException
                                {
                                    if (parameters.getAlgorithm() == ElGamal.WRAP_OAEP.getAlgorithm())
                                    {
                                        if (!(spec instanceof OAEPParameterSpec))
                                        {
                                            throw new InvalidAlgorithmParameterException("OAEP can only accept OAEPParameterSpec");
                                        }

                                        OAEPParameterSpec oaepSpec = (OAEPParameterSpec)spec;
                                        DigestAlgorithm digest = Utils.digestNameToAlgMap.get(oaepSpec.getDigestAlgorithm());

                                        MGF1ParameterSpec mgfParams = (MGF1ParameterSpec)oaepSpec.getMGFParameters();
                                        DigestAlgorithm mgfDigest = Utils.digestNameToAlgMap.get(mgfParams.getDigestAlgorithm());

                                        return ElGamal.WRAP_OAEP.withDigest(digest).withMGFDigest(mgfDigest).withEncodingParams(((PSource.PSpecified)oaepSpec.getPSource()).getValue());
                                    }
                                    else if (parameters.getAlgorithm() == ElGamal.WRAP_PKCS1v1_5.getAlgorithm())
                                    {
                                        return ElGamal.WRAP_PKCS1v1_5;
                                    }

                                    return ElGamal.RAW;
                                }
                            };
                        }
                    }).build();
            }
        }));
        provider.addAlias("Cipher", "ELGAMAL", OIWObjectIdentifiers.elGamalAlgorithm);

        provider.addAlgorithmImplementation("KeyFactory.ELGAMAL", PREFIX + "KeyFactorySpi", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyFactorySpi();
            }
        }));
        provider.addAlgorithmImplementation("KeyPairGenerator.ELGAMAL", PREFIX + "KeyPairGeneratorSpi", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new KeyPairGeneratorSpi(provider);
            }
        }));

        AsymmetricKeyInfoConverter keyFact = new KeyFactorySpi();

        registerOid(provider, OIWObjectIdentifiers.elGamalAlgorithm, "ELGAMAL", keyFact);
        registerOidAlgorithmParameters(provider, OIWObjectIdentifiers.elGamalAlgorithm, "ELGAMAL");
    }

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
                return new ProvDHPrivateKey(ElGamal.ALGORITHM, (DHPrivateKeySpec)keySpec);
            }

            return super.engineGeneratePrivate(keySpec);
        }

        protected PublicKey engineGeneratePublic(
            KeySpec keySpec)
            throws InvalidKeySpecException
        {
            if (keySpec instanceof DHPublicKeySpec)
            {
                return new ProvDHPublicKey(ElGamal.ALGORITHM, (DHPublicKeySpec)keySpec);
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
                return new ProvDHPublicKey(ProvDH.publicKeyConverter.convertKey(ElGamal.ALGORITHM, (PublicKey)key));
            }
            else if (key instanceof PrivateKey)
            {
                return new ProvDHPrivateKey(ProvDH.privateKeyConverter.convertKey(ElGamal.ALGORITHM, (PrivateKey)key));
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
            return new ProvDHPrivateKey(new AsymmetricDHPrivateKey(ElGamal.ALGORITHM, info));
        }

        public PublicKey generatePublic(SubjectPublicKeyInfo info)
            throws IOException
        {
            return new ProvDHPublicKey(new AsymmetricDHPublicKey(ElGamal.ALGORITHM, info));
        }
    }

    static class KeyPairGeneratorSpi
        extends java.security.KeyPairGenerator
    {
        private final BouncyCastleFipsProvider provider;
        ElGamal.KeyGenParameters param;
        ElGamal.KeyPairGenerator engine;

        int strength = 2048;
        SecureRandom random;
        boolean initialised = false;

        public KeyPairGeneratorSpi(BouncyCastleFipsProvider provider)
        {
            super("ElGamal");
            this.provider = provider;
        }

        public void initialize(
            int strength)
        {
            initialize(strength, provider.getDefaultSecureRandom());
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
            initialize(params, provider.getDefaultSecureRandom());
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

            param = new ElGamal.KeyGenParameters(new DHDomainParameters(dhParams.getP(), null, dhParams.getG(), dhParams.getL()));
            engine = new ElGamal.KeyPairGenerator(param, random);

            initialised = true;
        }

        public KeyPair generateKeyPair()
        {
            if (!initialised)
            {
                DHDomainParameters dhParams = CryptoServicesRegistrar.getSizedProperty(CryptoServicesRegistrar.Property.DH_DEFAULT_PARAMS, strength);

                if (dhParams != null)
                {
                    param = new ElGamal.KeyGenParameters(dhParams);
                }
                else
                {
                    FipsDH.DomainParametersGenerator gen = new FipsDH.DomainParametersGenerator(new FipsDH.DomainGenParameters(strength), random);

                    param = new ElGamal.KeyGenParameters(gen.generateDomainParameters());
                }

                engine = new ElGamal.KeyPairGenerator(param, random);
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
            super("ELGAMAL");
        }

        /**
         * Return the X.509 ASN.1 structure ElGamalParameter.
         * <p/>
         * <pre>
         *  ElGamalParameter ::= SEQUENCE {
         *                   prime INTEGER, -- p
         *                   base INTEGER, -- g}
         * </pre>
         */
        protected byte[] localGetEncoded()
            throws IOException
        {
            ElGamalParameter elP = new ElGamalParameter(currentSpec.getP(), currentSpec.getG());

            return elP.getEncoded(ASN1Encoding.DER);
        }

        protected void localInit(byte[] params)
            throws IOException
        {
            ElGamalParameter elP = ElGamalParameter.getInstance(params);

            currentSpec = new DHDomainParameterSpec(elP.getP(), null, elP.getG());
        }

        protected String engineToString()
        {
            return "ElGamal Parameters";
        }
    }
}
