package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.misc.CAST5CBCParameters;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.crypto.AuthenticationParametersWithIV;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.ParametersWithIV;
import org.bouncycastle.crypto.SymmetricKeyGenerator;
import org.bouncycastle.crypto.general.CAST5;

final class ProvCAST5
    extends AlgorithmProvider
{
    public static class AlgParamGen
        extends BaseAlgorithmParameterGenerator
    {
        public AlgParamGen(BouncyCastleFipsProvider fipsProvider)
        {
            super(fipsProvider, 128);
        }

        protected void engineInit(
            AlgorithmParameterSpec genParamSpec,
            SecureRandom random)
            throws InvalidAlgorithmParameterException
        {
            throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for CAST5 parameter generation");
        }

        protected AlgorithmParameters engineGenerateParameters()
        {
            byte[] iv = new byte[8];

            random.nextBytes(iv);

            AlgorithmParameters params;

            try
            {
                params = AlgorithmParameters.getInstance("CAST5", fipsProvider);
                params.init(new CAST5CBCParameters(iv, strength).toASN1Primitive().getEncoded());
            }
            catch (Exception e)
            {
                throw new IllegalStateException(e.getMessage(), e);
            }

            return params;
        }
    }

    public static class AlgParams
        extends BaseAlgorithmParameters
    {
        private byte[] iv;
        private int keyLength = 128;

        protected byte[] localGetEncoded()
            throws IOException
        {
            return new CAST5CBCParameters(iv, keyLength).getEncoded();
        }

        protected AlgorithmParameterSpec localEngineGetParameterSpec(
            Class paramSpec)
            throws InvalidParameterSpecException
        {
            if (paramSpec == IvParameterSpec.class || paramSpec == AlgorithmParameterSpec.class)
            {
                return new IvParameterSpec(iv);
            }

            throw new InvalidParameterSpecException("AlgorithmParameterSpec not recognized: " + paramSpec.getName());
        }

        protected void engineInit(
            AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException
        {
            if (paramSpec instanceof IvParameterSpec)
            {
                this.iv = ((IvParameterSpec)paramSpec).getIV();
            }
            else
            {
                throw new InvalidParameterSpecException("IvParameterSpec required to initialise a CAST5 parameters algorithm parameters object");
            }
        }

        protected void localInit(
            byte[] params)
            throws IOException
        {
             ASN1Primitive spec = ASN1Primitive.fromByteArray(params);
             if (spec instanceof ASN1OctetString)
             {
                 this.iv = ASN1OctetString.getInstance(spec).getOctets();
             }
             else if (spec instanceof ASN1Sequence)
             {
                 CAST5CBCParameters cast5Param = CAST5CBCParameters.getInstance(spec);
                 this.iv = cast5Param.getIV();
                 this.keyLength = cast5Param.getKeyLength();
             }
             else
             {
                 throw new IOException("Unable to recognize parameters");
             }
        }

        protected String engineToString()
        {
            return "CAST5 Parameters";
        }
    }

    private static final String PREFIX = ProvCAST5.class.getName();

    private Class[] availableSpecs =
        {
            IvParameterSpec.class,
        };

    private ParametersCreatorProvider<Parameters> generalParametersCreatorProvider = new ParametersCreatorProvider<Parameters>()
    {
        public ParametersCreator get(Parameters parameters)
        {
            if (Utils.isAuthMode(parameters.getAlgorithm()))
            {
                return new AuthParametersCreator((AuthenticationParametersWithIV)parameters);
            }
            return new IvParametersCreator((ParametersWithIV)parameters);
        }
    };

    public void configure(final BouncyCastleFipsProvider provider)
    {
        final Class[] ivOnlySpec = new Class[]{IvParameterSpec.class};

        provider.addAlgorithmImplementation("AlgorithmParameters.CAST5", PREFIX + "$AlgParams", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new AlgParams();
            }
        }));

        provider.addAlias("AlgorithmParameters", "CAST5", MiscObjectIdentifiers.cast5CBC);

        provider.addAlgorithmImplementation("AlgorithmParameterGenerator.CAST5", PREFIX + "$AlgParamGen", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new AlgParamGen(provider);
            }
        }));

        provider.addAlias("AlgorithmParameterGenerator", "CAST5", MiscObjectIdentifiers.cast5CBC);

        provider.addAlgorithmImplementation("Cipher.CAST5", PREFIX + "$ECB", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 64,
                    CAST5.ECBwithPKCS7, CAST5.ECB, CAST5.ECBwithISO10126_2, CAST5.ECBwithISO7816_4, CAST5.ECBwithTBC, CAST5.ECBwithX923,
                    CAST5.CBC, CAST5.CBCwithPKCS7, CAST5.CBCwithISO10126_2, CAST5.CBCwithISO7816_4, CAST5.CBCwithTBC, CAST5.CBCwithX923,
                    CAST5.CBCwithCS1, CAST5.CBCwithCS2, CAST5.CBCwithCS3,
                    CAST5.CTR,
                    CAST5.CFB64, CAST5.CFB8,
                    CAST5.OFB, CAST5.OpenPGPCFB,
                    CAST5.EAX)
                    .withGeneralOperators(generalParametersCreatorProvider, new CAST5.OperatorFactory(), new CAST5.AEADOperatorFactory())
                    .withParameters(availableSpecs).build();
            }
        }));

        provider.addAlgorithmImplementation("Cipher", MiscObjectIdentifiers.cast5CBC, PREFIX + "$CBC", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 64,
                    CAST5.CBCwithPKCS7)
                    .withParameters(ivOnlySpec)
                    .withGeneralOperators(generalParametersCreatorProvider, new CAST5.OperatorFactory(), new CAST5.AEADOperatorFactory())
                    .withParameters(availableSpecs).build();
            }
        }));

        provider.addAlgorithmImplementation("Mac.CAST5CMAC", PREFIX + "$CMAC", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(CAST5.CMAC, new CAST5.MACOperatorFactory(), new AuthParametersCreator(CAST5.CMAC));
            }
        }));
        provider.addAlias("Mac", "CAST5CMAC", "CAST5-CMAC");

        provider.addAlgorithmImplementation("KeyGenerator.CAST5", PREFIX + "$KeyGen", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseKeyGenerator(provider, "CAST5", 128, new KeyGeneratorCreator()
                {
                    public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                    {
                        return new CAST5.KeyGenerator(keySize, random);
                    }
                });
            }
        }));
        provider.addAlias("KeyGenerator", "CAST5", MiscObjectIdentifiers.cast5CBC);

        provider.addAlgorithmImplementation("SecretKeyFactory.CAST5", PREFIX + "$CAST5KFACT", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSecretKeyFactory("CAST5", CAST5.ALGORITHM, new BaseSecretKeyFactory.Validator()
                {
                    public byte[] validated(byte[] keyBytes)
                        throws InvalidKeySpecException
                    {
                        int size = keyBytes.length * 8;
                        if (size < 40 || size > 128)
                        {
                            throw new InvalidKeySpecException("CAST5 key must be of length 40-128 bits");
                        }

                        return keyBytes;
                    }
                });
            }
        }));

    }
}
