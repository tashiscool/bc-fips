package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.misc.IDEACBCPar;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.crypto.AuthenticationParametersWithIV;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.ParametersWithIV;
import org.bouncycastle.crypto.SymmetricKeyGenerator;
import org.bouncycastle.crypto.general.IDEA;
import org.bouncycastle.util.Arrays;

class ProvIDEA
    extends AlgorithmProvider
{
    ProvIDEA()
    {
    }

    private static class AlgParams
        extends BaseAlgorithmParameters
    {
        private byte[] iv;

        protected byte[] localGetEncoded()
            throws IOException
        {
            return new IDEACBCPar(Arrays.clone(iv)).getEncoded();
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
            if (!(paramSpec instanceof IvParameterSpec))
            {
                throw new InvalidParameterSpecException("IvParameterSpec required to initialise a IV parameters algorithm parameters object");
            }

            this.iv = ((IvParameterSpec)paramSpec).getIV();
        }

        protected void localInit(
            byte[] params)
            throws IOException
        {
            ASN1Primitive asn1Params = ASN1Primitive.fromByteArray(params);
            if (asn1Params instanceof ASN1Sequence)
            {
                IDEACBCPar oct = IDEACBCPar.getInstance(asn1Params);

                this.iv = Arrays.clone(oct.getIV());
            }
            else if (asn1Params instanceof ASN1OctetString)
            {
                this.iv = Arrays.clone(ASN1OctetString.getInstance(asn1Params).getOctets());
            }
            else
            {
                throw new IOException("Unable to recognize parameters");
            }
        }

        protected String engineToString()
        {
            return "IDEA Parameters";
        }
    }

    private static final String PREFIX = ProvIDEA.class.getName();

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
        provider.addAlgorithmImplementation("AlgorithmParameterGenerator", MiscObjectIdentifiers.as_sys_sec_alg_ideaCBC, PREFIX + "$AlgParamGen", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new IVAlgorithmParameterGenerator(provider, "IDEA", 8);
            }
        }));

        provider.addAlgorithmImplementation("AlgorithmParameters.IDEA", PREFIX + "$AlgParams", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new AlgParams();
            }
        }));

        provider.addAlias("AlgorithmParameters", "IDEA", MiscObjectIdentifiers.as_sys_sec_alg_ideaCBC);

        provider.addAlgorithmImplementation("Cipher.IDEA", PREFIX + "$ECB", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 64,
                    IDEA.ECBwithPKCS7, IDEA.ECB, IDEA.ECBwithISO10126_2, IDEA.ECBwithISO7816_4, IDEA.ECBwithTBC, IDEA.ECBwithX923,
                    IDEA.CBC, IDEA.CBCwithPKCS7, IDEA.CBCwithISO10126_2, IDEA.CBCwithISO7816_4, IDEA.CBCwithTBC, IDEA.CBCwithX923,
                    IDEA.CBCwithCS1, IDEA.CBCwithCS2, IDEA.CBCwithCS3,
                    IDEA.CFB64, IDEA.CFB8,
                    IDEA.OFB,
                    IDEA.CTR, IDEA.EAX, IDEA.OpenPGPCFB)
                    .withGeneralOperators(generalParametersCreatorProvider, new IDEA.OperatorFactory(), new IDEA.AEADOperatorFactory())
                    .withParameters(availableSpecs).build();
            }
        }));
        provider.addAlgorithmImplementation("Cipher", MiscObjectIdentifiers.as_sys_sec_alg_ideaCBC, PREFIX + "$CBC", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 64, IDEA.CBCwithPKCS7)
                    .withGeneralOperators(generalParametersCreatorProvider, new IDEA.OperatorFactory(), null)
                    .withParameters(availableSpecs).build();
            }
        }));
        provider.addAlgorithmImplementation("KeyGenerator.IDEA", PREFIX + "$KeyGen", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseKeyGenerator(provider, "IDEA", 128, false, new KeyGeneratorCreator()
                {
                    public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                    {
                        return new IDEA.KeyGenerator(keySize, random);
                    }
                });
            }
        }));
        provider.addAlias("KeyGenerator", "IDEA", MiscObjectIdentifiers.as_sys_sec_alg_ideaCBC);

        provider.addAlgorithmImplementation("Mac.IDEAMAC", PREFIX + "$Mac", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(IDEA.CBC_MAC, new IDEA.MACOperatorFactory(),new AuthParametersCreator(IDEA.CBC_MAC));
            }
        }));
        provider.addAlias("Alg.Alias.Mac.IDEA", "IDEAMAC");
        provider.addAlgorithmImplementation("Mac.IDEAMAC/CFB8", PREFIX + "$CFB8MAC", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(IDEA.CFB8_MAC, new IDEA.MACOperatorFactory(), new AuthParametersCreator(IDEA.CFB8_MAC));
            }
        }));
        provider.addAlias("Alg.Alias.Mac.IDEA/CFB8", "IDEAMAC/CFB8");

        provider.addAlgorithmImplementation("Mac.IDEACMAC", PREFIX + "$CMAC", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(IDEA.CMAC, new IDEA.MACOperatorFactory(), new AuthParametersCreator(IDEA.CMAC));
            }
        }));
        provider.addAlias("Mac", "IDEACMAC", "IDEA-CMAC");

        provider.addAlgorithmImplementation("SecretKeyFactory.IDEA", PREFIX + "$IDEAKFACT", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSecretKeyFactory("IDEA", IDEA.ALGORITHM, new BaseSecretKeyFactory.Validator()
                {
                    public byte[] validated(byte[] keyBytes)
                        throws InvalidKeySpecException
                    {
                        int size = keyBytes.length * 8;
                        if (size < 40 || size > 128)
                        {
                            throw new InvalidKeySpecException("IDEA key must be of length 40 to 128 bits");
                        }

                        return keyBytes;
                    }
                });
            }
        }));
    }
}
