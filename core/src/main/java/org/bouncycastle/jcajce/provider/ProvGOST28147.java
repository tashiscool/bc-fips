package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.GOST28147Parameters;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.ParametersWithIV;
import org.bouncycastle.crypto.SymmetricKeyGenerator;
import org.bouncycastle.crypto.general.GOST28147;
import org.bouncycastle.jcajce.spec.GOST28147GenParameterSpec;
import org.bouncycastle.jcajce.spec.GOST28147ParameterSpec;

final class ProvGOST28147
    extends AlgorithmProvider
{
    public static class AlgParamGen
        extends BaseAlgorithmParameterGenerator
    {
        private ASN1ObjectIdentifier sBox;

        public AlgParamGen(BouncyCastleFipsProvider fipsProvider)
        {
            super(fipsProvider, 0);
        }

        protected void engineInit(
            AlgorithmParameterSpec genParamSpec,
            SecureRandom random)
            throws InvalidAlgorithmParameterException
        {
            if (genParamSpec instanceof GOST28147GenParameterSpec)
            {
                String sBoxName = ((GOST28147GenParameterSpec)genParamSpec).getSBoxName();

                try
                {
                    this.sBox = GOST28147.getSBoxOID(sBoxName);
                }
                catch (IllegalArgumentException e)
                {
                    throw new InvalidAlgorithmParameterException("Name " + sBoxName + " does not map to a GOST28147 parameter set");
                }
            }
            else
            {
                throw new InvalidAlgorithmParameterException("GOST28147 requires a GOST28147GenParameterSpec for initialization");
            }
        }

        protected AlgorithmParameters engineGenerateParameters()
        {
            byte[] iv = new byte[8];

            random.nextBytes(iv);

            AlgorithmParameters params;

            try
            {
                params = AlgorithmParameters.getInstance("GOST28147", fipsProvider);

                if (sBox == null)
                {
                    params.init(new IvParameterSpec(iv));
                }
                else
                {
                    params.init(new GOST28147ParameterSpec(sBox, iv));
                }
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
        private ASN1ObjectIdentifier sBox = CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_A_ParamSet;
        private byte[] iv;

        protected byte[] localGetEncoded()
            throws IOException
        {
            return new GOST28147Parameters(iv, sBox).getEncoded();
        }

        protected AlgorithmParameterSpec localEngineGetParameterSpec(
            Class paramSpec)
            throws InvalidParameterSpecException
        {
            if (paramSpec == IvParameterSpec.class)
            {
                return new IvParameterSpec(iv);
            }

            if (paramSpec == GOST28147ParameterSpec.class || paramSpec == AlgorithmParameterSpec.class)
            {
                return new GOST28147ParameterSpec(sBox, iv);
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
            else if (paramSpec instanceof GOST28147ParameterSpec)
            {
                this.iv = ((GOST28147ParameterSpec)paramSpec).getIV();
                try
                {
                    this.sBox = GOST28147.getSBoxOID(((GOST28147ParameterSpec)paramSpec).getSBox());
                }
                catch (IllegalArgumentException e)
                {
                    throw new InvalidParameterSpecException(e.getMessage());
                }
            }
            else
            {
                throw new InvalidParameterSpecException("IvParameterSpec required to initialise a IV parameters algorithm parameters object");
            }
        }

        protected void localInit(
            byte[] params)
            throws IOException
        {
            ASN1Primitive asn1Params = ASN1Primitive.fromByteArray(params);

            if (asn1Params instanceof ASN1OctetString)
            {
                this.iv = ASN1OctetString.getInstance(asn1Params).getOctets();
            }
            else if (asn1Params instanceof ASN1Sequence)
            {
                GOST28147Parameters gParams = GOST28147Parameters.getInstance(asn1Params);

                this.sBox = gParams.getEncryptionParamSet();
                this.iv = gParams.getIV();
            }
            else
            {
                throw new IOException("Unable to recognize parameters");
            }
        }

        protected String engineToString()
        {
            return "IV Parameters";
        }
    }

    private static final String PREFIX = ProvGOST28147.class.getName();

    private Class[] availableSpecs =
        {
            IvParameterSpec.class,
            GOST28147ParameterSpec.class
        };

    private ParametersCreatorProvider<Parameters> generalParametersCreatorProvider = new ParametersCreatorProvider<Parameters>()
    {
        public ParametersCreator get(final Parameters params)
        {
            return new ParametersCreator()
            {

                public Parameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
                {
                    if (spec instanceof IvParameterSpec)
                    {
                        if (Utils.isAuthMode(params.getAlgorithm()))
                        {
                            return ((GOST28147.AuthParameters)params).withIV(((IvParameterSpec)spec).getIV());
                        }
                        return ((GOST28147.Parameters)params).withIV(((IvParameterSpec)spec).getIV());
                    }
                    if (spec instanceof GOST28147ParameterSpec)
                    {
                        GOST28147ParameterSpec parameterSpec = (GOST28147ParameterSpec)spec;

                        if (Utils.isAuthMode(params.getAlgorithm()))
                        {
                            return ((GOST28147.AuthParameters)params).withIV(parameterSpec.getIV()).withSBox(parameterSpec.getSBox());
                        }
                        return ((GOST28147.Parameters)params).withIV(parameterSpec.getIV()).withSBox(parameterSpec.getSBox());
                    }

                    ParametersWithIV baseParameters = (ParametersWithIV)params;

                    if (forEncryption && baseParameters.getAlgorithm().requiresAlgorithmParameters())
                    {
                        return baseParameters.withIV(random);
                    }
                    return baseParameters;
                }
            };
        }
    };

    public void configure(final BouncyCastleFipsProvider provider)
    {
        provider.addAlgorithmImplementation("Cipher.GOST28147", PREFIX + "$ECB", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 64, 
                    GOST28147.ECBwithPKCS7, GOST28147.ECB, GOST28147.ECBwithISO10126_2, GOST28147.ECBwithISO7816_4, GOST28147.ECBwithTBC, GOST28147.ECBwithX923,
                    GOST28147.CBC, GOST28147.CBCwithPKCS7, GOST28147.CBCwithISO10126_2, GOST28147.CBCwithISO7816_4, GOST28147.CBCwithTBC, GOST28147.CBCwithX923,
                    GOST28147.CBCwithCS1, GOST28147.CBCwithCS2, GOST28147.CBCwithCS3,
                    GOST28147.CTR,
                    GOST28147.CFB8, GOST28147.CFB64,
                    GOST28147.OFB,
                    GOST28147.EAX,
                    GOST28147.GCFB, GOST28147.GOFB)
                    .withGeneralOperators(generalParametersCreatorProvider, new GOST28147.OperatorFactory(), new GOST28147.AEADOperatorFactory())
                    .withParameters(availableSpecs).build();
            }
        }));
        provider.addAlias("Alg.Alias.Cipher.GOST", "GOST28147");
        provider.addAlias("Alg.Alias.Cipher.GOST-28147", "GOST28147");

        provider.addAlgorithmImplementation("Cipher", CryptoProObjectIdentifiers.gostR28147_gcfb, PREFIX + "$GCFB", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 64, GOST28147.GCFB)
                    .withGeneralOperators(generalParametersCreatorProvider, new GOST28147.OperatorFactory(), null)
                    .withParameters(availableSpecs).build();
            }
        }));

        provider.addAlgorithmImplementation("KeyGenerator.GOST28147", PREFIX + "$KeyGen", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseKeyGenerator(provider, "GOST28147", 256, true, new KeyGeneratorCreator()
                {
                    public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                    {
                        return new GOST28147.KeyGenerator(random);
                    }
                });
            }
        }));

        provider.addAlgorithmImplementation("AlgorithmParameters.GOST28147", PREFIX + "$AlgParams", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new AlgParams();
            }
        }));
        provider.addAlgorithmImplementation("AlgorithmParameterGenerator.GOST28147", PREFIX + "$AlgParamGen", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new AlgParamGen(provider);
            }
        }));

        provider.addAlgorithmImplementation("SecretKeyFactory.GOST28147", PREFIX + "$GOST28147KFACT", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSecretKeyFactory("GOST28147", GOST28147.ALGORITHM, new BaseSecretKeyFactory.Validator()
                {
                    public byte[] validated(byte[] keyBytes)
                        throws InvalidKeySpecException
                    {
                        int size = keyBytes.length * 8;
                        if (size != 256)
                        {
                            throw new InvalidKeySpecException("Provided key data wrong size for GOST28147");
                        }

                        return keyBytes;
                    }
                });
            }
        }));

        provider.addAlias("KeyGenerator", "GOST28147", CryptoProObjectIdentifiers.gostR28147_gcfb);

        provider.addAlgorithmImplementation("Mac.GOST28147MAC", PREFIX + "$Mac", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(GOST28147.MAC, new GOST28147.MACOperatorFactory(), new AuthParametersCreator(GOST28147.MAC));
            }
        }));
        provider.addAlias("Alg.Alias.Mac.GOST28147", "GOST28147MAC");
    }
}
