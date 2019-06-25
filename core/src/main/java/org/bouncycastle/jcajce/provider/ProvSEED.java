package org.bouncycastle.jcajce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
import org.bouncycastle.crypto.AuthenticationParametersWithIV;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.ParametersWithIV;
import org.bouncycastle.crypto.SymmetricKeyGenerator;
import org.bouncycastle.crypto.general.SEED;
import org.bouncycastle.jcajce.spec.WrapParameterSpec;

class ProvSEED
    extends SymmetricAlgorithmProvider
{
    private SEED.OperatorFactory operatorFactory;
    private SEED.AEADOperatorFactory aeadOperatorFactory;
    private SEED.KeyWrapOperatorFactory keyWrapOperatorFactory;

    ProvSEED()
    {
        if (!CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            aeadOperatorFactory = new SEED.AEADOperatorFactory();
            keyWrapOperatorFactory = new SEED.KeyWrapOperatorFactory();
            operatorFactory = new SEED.OperatorFactory();
        }
    }

    public static class AlgParams
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "SEED IV";
        }
    }

    private static final String PREFIX = ProvSEED.class.getName();

    private ParametersCreatorProvider<Parameters> generalParametersCreatorProvider = new ParametersCreatorProvider<Parameters>()
    {
        public ParametersCreator get(final Parameters parameters)
        {
            if (Utils.isAuthMode(parameters.getAlgorithm()))
            {
                return new AuthParametersCreator((AuthenticationParametersWithIV)parameters);
            }
            else if (parameters.getAlgorithm().equals(SEED.KW.getAlgorithm()) || parameters.getAlgorithm().equals(SEED.KWP.getAlgorithm()))
            {
                return new ParametersCreator()
                {

                    public Parameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
                        throws InvalidAlgorithmParameterException
                    {
                        if (spec instanceof WrapParameterSpec)
                        {
                            return ((SEED.WrapParameters)parameters).withUsingInverseFunction(((WrapParameterSpec)spec).useInverseFunction());
                        }

                        return parameters;
                    }
                };
            }
            return new IvParametersCreator((ParametersWithIV)parameters);
        }
    };


    private SEED.OperatorFactory getGeneralOperatorFactory()
    {
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
        {
            return null;
        }

        return operatorFactory;
    }

    public void configure(final BouncyCastleFipsProvider provider)
    {
        final Class[] cipherSpecs = GcmSpecUtil.getCipherSpecClasses();
        final Class[] ivOnlySpec = new Class[]{IvParameterSpec.class};

        provider.addAlgorithmImplementation("AlgorithmParameters.SEED", PREFIX + "$AlgParams", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new AlgParams();
            }
        }));

        provider.addAlias("AlgorithmParameters", "SEED", KISAObjectIdentifiers.id_seedCBC);

        provider.addAlgorithmImplementation("AlgorithmParameterGenerator", KISAObjectIdentifiers.id_seedCBC, PREFIX + "$AlgParamGen", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new IVAlgorithmParameterGenerator(provider, "SEED", 16);
            }
        }));

        provider.addAlgorithmImplementation("Cipher.SEED", PREFIX + "$ECB", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128,
                    SEED.ECBwithPKCS7, SEED.ECB, SEED.ECBwithISO10126_2, SEED.ECBwithISO7816_4, SEED.ECBwithTBC, SEED.ECBwithX923,
                    SEED.CBC, SEED.CBCwithPKCS7, SEED.CBCwithISO10126_2, SEED.CBCwithISO7816_4, SEED.CBCwithTBC, SEED.CBCwithX923,
                    SEED.CBCwithCS1, SEED.CBCwithCS2, SEED.CBCwithCS3,
                    SEED.CFB128, SEED.CFB8,
                    SEED.OFB,
                    SEED.CTR, SEED.GCM, SEED.CCM, SEED.OCB, SEED.EAX)
                    .withGeneralOperators(generalParametersCreatorProvider, getGeneralOperatorFactory(), aeadOperatorFactory)
                    .withParameters(cipherSpecs).build();
            }
        }));

        provider.addAlgorithmImplementation("Cipher", KISAObjectIdentifiers.id_seedCBC, PREFIX + "$CBC", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 128, SEED.CBCwithPKCS7)
                    .withParameters(ivOnlySpec)
                    .withGeneralOperators(generalParametersCreatorProvider, getGeneralOperatorFactory(), null)
                    .build();
            }
        }));

        provider.addAlgorithmImplementation("Cipher.SEEDWRAP", PREFIX + "$Wrap", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseWrapCipher.Builder(provider, SEED.KW).withGeneralOperators(generalParametersCreatorProvider, keyWrapOperatorFactory).withParameters(ivOnlySpec).build();
            }
        }));

        provider.addAlias("Cipher", "SEEDWRAP", KISAObjectIdentifiers.id_npki_app_cmsSeed_wrap);
        provider.addAlias("Alg.Alias.Cipher.SEEDKW", "SEEDWRAP");
        provider.addAlgorithmImplementation("Cipher.SEEDKWP", PREFIX + "$WrapWithPad", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseWrapCipher.Builder(provider, SEED.KWP).withGeneralOperators(generalParametersCreatorProvider, keyWrapOperatorFactory).withParameters(ivOnlySpec).build();
            }
        }));
        provider.addAlias("Alg.Alias.Cipher.SEEDWRAPPAD", "SEEDKWP");

        provider.addAlgorithmImplementation("KeyGenerator.SEED", PREFIX + "$KeyGen", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseKeyGenerator(provider, "SEED", 128, true, new KeyGeneratorCreator()
                {
                    public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                    {
                        return new SEED.KeyGenerator(random);
                    }
                });
            }
        }));
        provider.addAlias("KeyGenerator", "SEED", KISAObjectIdentifiers.id_seedCBC, KISAObjectIdentifiers.id_npki_app_cmsSeed_wrap, KISAObjectIdentifiers.id_seedMAC);

        provider.addAlgorithmImplementation("Mac.SEEDGMAC", PREFIX + "$GMAC", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(SEED.GMAC, new SEED.MACOperatorFactory(), new AuthParametersCreator(SEED.GMAC));
            }
        }));
        provider.addAlias("Mac", "SEEDGMAC", "SEED-GMAC");

        provider.addAlgorithmImplementation("Mac.SEEDCMAC", PREFIX + "$CMAC", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(SEED.CMAC, new SEED.MACOperatorFactory(), new AuthParametersCreator(SEED.CMAC));
            }
        }));
        provider.addAlias("Mac", "SEEDCMAC", "SEED-CMAC");

        provider.addAlgorithmImplementation("Mac.SEEDCCMMAC", PREFIX + "$SEEDCCMMAC", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(SEED.CCM, new SEED.MACOperatorFactory(), new AuthParametersCreator(SEED.CCM.withMACSize(128)));
            }
        }));
        provider.addAlias("Mac", "SEEDCCMMAC", "SEED-CCMMAC");

        provider.addAlgorithmImplementation("SecretKeyFactory.SEED", PREFIX + "$SEEDKFACT", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSecretKeyFactory("SEED", SEED.ALGORITHM, new BaseSecretKeyFactory.Validator()
                {
                    public byte[] validated(byte[] keyBytes)
                        throws InvalidKeySpecException
                    {
                        int size = keyBytes.length * 8;
                        if (size != 128)
                        {
                            throw new InvalidKeySpecException("Provided key data wrong size for SEED");
                        }

                        return keyBytes;
                    }
                });
            }
        }));
    }
}
