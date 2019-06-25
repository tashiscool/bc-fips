package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RC2CBCParameter;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.PasswordBasedDeriver;
import org.bouncycastle.crypto.PasswordConverter;
import org.bouncycastle.crypto.SymmetricKeyGenerator;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.crypto.general.RC2;
import org.bouncycastle.crypto.general.SecureHash;

final class ProvRC2
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
            if (genParamSpec instanceof RC2ParameterSpec)
            {
                this.strength = ((RC2ParameterSpec)genParamSpec).getEffectiveKeyBits();
                this.random = random;
                return;
            }

            throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for RC2 parameter generation.");
        }

        protected AlgorithmParameters engineGenerateParameters()
        {
            AlgorithmParameters params;

            byte[] iv = new byte[8];

            if (random == null)
            {
                random = fipsProvider.getDefaultSecureRandom();
            }

            random.nextBytes(iv);

            try
            {
                params = AlgorithmParameters.getInstance("RC2", fipsProvider);
                params.init(new RC2ParameterSpec(strength, iv));
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
        private static final short[] table = {
            0xbd, 0x56, 0xea, 0xf2, 0xa2, 0xf1, 0xac, 0x2a, 0xb0, 0x93, 0xd1, 0x9c, 0x1b, 0x33, 0xfd, 0xd0,
            0x30, 0x04, 0xb6, 0xdc, 0x7d, 0xdf, 0x32, 0x4b, 0xf7, 0xcb, 0x45, 0x9b, 0x31, 0xbb, 0x21, 0x5a,
            0x41, 0x9f, 0xe1, 0xd9, 0x4a, 0x4d, 0x9e, 0xda, 0xa0, 0x68, 0x2c, 0xc3, 0x27, 0x5f, 0x80, 0x36,
            0x3e, 0xee, 0xfb, 0x95, 0x1a, 0xfe, 0xce, 0xa8, 0x34, 0xa9, 0x13, 0xf0, 0xa6, 0x3f, 0xd8, 0x0c,
            0x78, 0x24, 0xaf, 0x23, 0x52, 0xc1, 0x67, 0x17, 0xf5, 0x66, 0x90, 0xe7, 0xe8, 0x07, 0xb8, 0x60,
            0x48, 0xe6, 0x1e, 0x53, 0xf3, 0x92, 0xa4, 0x72, 0x8c, 0x08, 0x15, 0x6e, 0x86, 0x00, 0x84, 0xfa,
            0xf4, 0x7f, 0x8a, 0x42, 0x19, 0xf6, 0xdb, 0xcd, 0x14, 0x8d, 0x50, 0x12, 0xba, 0x3c, 0x06, 0x4e,
            0xec, 0xb3, 0x35, 0x11, 0xa1, 0x88, 0x8e, 0x2b, 0x94, 0x99, 0xb7, 0x71, 0x74, 0xd3, 0xe4, 0xbf,
            0x3a, 0xde, 0x96, 0x0e, 0xbc, 0x0a, 0xed, 0x77, 0xfc, 0x37, 0x6b, 0x03, 0x79, 0x89, 0x62, 0xc6,
            0xd7, 0xc0, 0xd2, 0x7c, 0x6a, 0x8b, 0x22, 0xa3, 0x5b, 0x05, 0x5d, 0x02, 0x75, 0xd5, 0x61, 0xe3,
            0x18, 0x8f, 0x55, 0x51, 0xad, 0x1f, 0x0b, 0x5e, 0x85, 0xe5, 0xc2, 0x57, 0x63, 0xca, 0x3d, 0x6c,
            0xb4, 0xc5, 0xcc, 0x70, 0xb2, 0x91, 0x59, 0x0d, 0x47, 0x20, 0xc8, 0x4f, 0x58, 0xe0, 0x01, 0xe2,
            0x16, 0x38, 0xc4, 0x6f, 0x3b, 0x0f, 0x65, 0x46, 0xbe, 0x7e, 0x2d, 0x7b, 0x82, 0xf9, 0x40, 0xb5,
            0x1d, 0x73, 0xf8, 0xeb, 0x26, 0xc7, 0x87, 0x97, 0x25, 0x54, 0xb1, 0x28, 0xaa, 0x98, 0x9d, 0xa5,
            0x64, 0x6d, 0x7a, 0xd4, 0x10, 0x81, 0x44, 0xef, 0x49, 0xd6, 0xae, 0x2e, 0xdd, 0x76, 0x5c, 0x2f,
            0xa7, 0x1c, 0xc9, 0x09, 0x69, 0x9a, 0x83, 0xcf, 0x29, 0x39, 0xb9, 0xe9, 0x4c, 0xff, 0x43, 0xab
        };

        private static final short[] ekb = {
            0x5d, 0xbe, 0x9b, 0x8b, 0x11, 0x99, 0x6e, 0x4d, 0x59, 0xf3, 0x85, 0xa6, 0x3f, 0xb7, 0x83, 0xc5,
            0xe4, 0x73, 0x6b, 0x3a, 0x68, 0x5a, 0xc0, 0x47, 0xa0, 0x64, 0x34, 0x0c, 0xf1, 0xd0, 0x52, 0xa5,
            0xb9, 0x1e, 0x96, 0x43, 0x41, 0xd8, 0xd4, 0x2c, 0xdb, 0xf8, 0x07, 0x77, 0x2a, 0xca, 0xeb, 0xef,
            0x10, 0x1c, 0x16, 0x0d, 0x38, 0x72, 0x2f, 0x89, 0xc1, 0xf9, 0x80, 0xc4, 0x6d, 0xae, 0x30, 0x3d,
            0xce, 0x20, 0x63, 0xfe, 0xe6, 0x1a, 0xc7, 0xb8, 0x50, 0xe8, 0x24, 0x17, 0xfc, 0x25, 0x6f, 0xbb,
            0x6a, 0xa3, 0x44, 0x53, 0xd9, 0xa2, 0x01, 0xab, 0xbc, 0xb6, 0x1f, 0x98, 0xee, 0x9a, 0xa7, 0x2d,
            0x4f, 0x9e, 0x8e, 0xac, 0xe0, 0xc6, 0x49, 0x46, 0x29, 0xf4, 0x94, 0x8a, 0xaf, 0xe1, 0x5b, 0xc3,
            0xb3, 0x7b, 0x57, 0xd1, 0x7c, 0x9c, 0xed, 0x87, 0x40, 0x8c, 0xe2, 0xcb, 0x93, 0x14, 0xc9, 0x61,
            0x2e, 0xe5, 0xcc, 0xf6, 0x5e, 0xa8, 0x5c, 0xd6, 0x75, 0x8d, 0x62, 0x95, 0x58, 0x69, 0x76, 0xa1,
            0x4a, 0xb5, 0x55, 0x09, 0x78, 0x33, 0x82, 0xd7, 0xdd, 0x79, 0xf5, 0x1b, 0x0b, 0xde, 0x26, 0x21,
            0x28, 0x74, 0x04, 0x97, 0x56, 0xdf, 0x3c, 0xf0, 0x37, 0x39, 0xdc, 0xff, 0x06, 0xa4, 0xea, 0x42,
            0x08, 0xda, 0xb4, 0x71, 0xb0, 0xcf, 0x12, 0x7a, 0x4e, 0xfa, 0x6c, 0x1d, 0x84, 0x00, 0xc8, 0x7f,
            0x91, 0x45, 0xaa, 0x2b, 0xc2, 0xb1, 0x8f, 0xd5, 0xba, 0xf2, 0xad, 0x19, 0xb2, 0x67, 0x36, 0xf7,
            0x0f, 0x0a, 0x92, 0x7d, 0xe3, 0x9d, 0xe9, 0x90, 0x3e, 0x23, 0x27, 0x66, 0x13, 0xec, 0x81, 0x15,
            0xbd, 0x22, 0xbf, 0x9f, 0x7e, 0xa9, 0x51, 0x4b, 0x4c, 0xfb, 0x02, 0xd3, 0x70, 0x86, 0x31, 0xe7,
            0x3b, 0x05, 0x03, 0x54, 0x60, 0x48, 0x65, 0x18, 0xd2, 0xcd, 0x5f, 0x32, 0x88, 0x0e, 0x35, 0xfd
        };

        private byte[] iv;
        private int parameterVersion = 58;

        protected byte[] localGetEncoded()
            throws IOException
        {
            if (parameterVersion == -1)
            {
                return new RC2CBCParameter(iv).getEncoded();
            }
            else
            {
                return new RC2CBCParameter(parameterVersion, iv).getEncoded();
            }
        }

        protected AlgorithmParameterSpec localEngineGetParameterSpec(
            Class paramSpec)
            throws InvalidParameterSpecException
        {
            if (paramSpec == RC2ParameterSpec.class || paramSpec == AlgorithmParameterSpec.class)
            {
                if (parameterVersion != -1)
                {
                    if (parameterVersion < 256)
                    {
                        return new RC2ParameterSpec(ekb[parameterVersion], iv);
                    }
                    else
                    {
                        return new RC2ParameterSpec(parameterVersion, iv);
                    }
                }
            }

            if (paramSpec == IvParameterSpec.class)
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
            else if (paramSpec instanceof RC2ParameterSpec)
            {
                int effKeyBits = ((RC2ParameterSpec)paramSpec).getEffectiveKeyBits();
                if (effKeyBits != -1)
                {
                    if (effKeyBits < 256)
                    {
                        parameterVersion = table[effKeyBits];
                    }
                    else
                    {
                        parameterVersion = effKeyBits;
                    }
                }

                this.iv = ((RC2ParameterSpec)paramSpec).getIV();
            }
            else
            {
                throw new InvalidParameterSpecException("IvParameterSpec or RC2ParameterSpec required to initialise a RC2 parameters algorithm parameters object");
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
                RC2CBCParameter rc2Param = RC2CBCParameter.getInstance(spec);
                this.iv = rc2Param.getIV();
                this.parameterVersion = rc2Param.getRC2ParameterVersion().intValue();
            }
            else
            {
                throw new IOException("Unable to recognize parameters");
            }
        }

        protected String engineToString()
        {
            return "RC2 Parameters";
        }
    }

    private static final String PREFIX = ProvRC2.class.getName();

    private Class[] availableSpecs =
        {
            RC2ParameterSpec.class,
            IvParameterSpec.class,
        };

    private ParametersCreatorProvider<Parameters> generalParametersCreatorProvider = new ParametersCreatorProvider<Parameters>()
    {
        public ParametersCreator get(final Parameters parameters)
        {
            return new ParametersCreator()
            {

                public Parameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
                {
                    if (spec instanceof IvParameterSpec)
                    {
                        if (Utils.isAuthMode(parameters.getAlgorithm()))
                        {
                            return ((RC2.AuthParameters)parameters).withIV(((IvParameterSpec)spec).getIV());
                        }
                        return ((RC2.Parameters)parameters).withIV(((IvParameterSpec)spec).getIV());
                    }

                    if (spec instanceof RC2ParameterSpec)
                    {
                        RC2ParameterSpec rc2Spec = (RC2ParameterSpec)spec;

                        if (Utils.isAuthMode(parameters.getAlgorithm()))
                        {
                            RC2.AuthParameters params = ((RC2.AuthParameters)parameters).withEffectiveKeySizeInBits(rc2Spec.getEffectiveKeyBits());
                            if (rc2Spec.getIV() != null)
                            {
                                return params.withIV(((RC2ParameterSpec)spec).getIV());
                            }
                            return params;
                        }
                        else
                        {
                            RC2.Parameters params = ((RC2.Parameters)parameters).withEffectiveKeySizeInBits(rc2Spec.getEffectiveKeyBits());

                            if (rc2Spec.getIV() != null)
                            {
                                return params.withIV(((RC2ParameterSpec)spec).getIV());
                            }
                            return params;
                        }
                    }

                    if (forEncryption && parameters.getAlgorithm().requiresAlgorithmParameters())
                    {
                        if (Utils.isAuthMode(parameters.getAlgorithm()))
                        {
                            return ((RC2.AuthParameters)parameters).withIV(random);
                        }
                        return ((RC2.Parameters)parameters).withIV(random);
                    }

                    return parameters;
                }
            };
        }
    };

    public void configure(final BouncyCastleFipsProvider provider)
    {

        provider.addAlgorithmImplementation("AlgorithmParameterGenerator.RC2", PREFIX + "$AlgParamGen", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new AlgParamGen(provider);
            }
        }));

        provider.addAlias("AlgorithmParameterGenerator", "RC2", PKCSObjectIdentifiers.RC2_CBC);

        provider.addAlgorithmImplementation("KeyGenerator.RC2", PREFIX + "$KeyGenerator", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseKeyGenerator(provider, "RC2", 128, false, new KeyGeneratorCreator()
                {
                    public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                    {
                        return new RC2.KeyGenerator(keySize, random);
                    }
                });
            }
        }));

        provider.addAlias("KeyGenerator", "RC2", PKCSObjectIdentifiers.RC2_CBC, PKCSObjectIdentifiers.id_alg_CMSRC2wrap);

        provider.addAlgorithmImplementation("AlgorithmParameters.RC2", PREFIX + "$AlgParams", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new AlgParams();
            }
        }));
        provider.addAlias("AlgorithmParameters", "RC2", PKCSObjectIdentifiers.RC2_CBC);

        provider.addAlgorithmImplementation("Cipher.RC2", PREFIX + "$ECB", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 64,
                    RC2.ECBwithPKCS7, RC2.ECB, RC2.ECBwithISO10126_2, RC2.ECBwithISO7816_4, RC2.ECBwithTBC, RC2.ECBwithX923,
                    RC2.CBC, RC2.CBCwithPKCS7, RC2.CBCwithISO10126_2, RC2.CBCwithISO7816_4, RC2.CBCwithTBC, RC2.CBCwithX923,
                    RC2.CBCwithCS1, RC2.CBCwithCS2, RC2.CBCwithCS3,
                    RC2.CFB64, RC2.CFB8,
                    RC2.OFB,
                    RC2.CTR, RC2.EAX)
                    .withGeneralOperators(generalParametersCreatorProvider, new RC2.OperatorFactory(), new RC2.AEADOperatorFactory())
                    .withParameters(availableSpecs).build();
            }
        }));

        provider.addAlgorithmImplementation("Cipher", PKCSObjectIdentifiers.RC2_CBC, PREFIX + "$CBC", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 64,
                    RC2.CBCwithPKCS7)
                    .withGeneralOperators(generalParametersCreatorProvider, new RC2.OperatorFactory(), null)
                    .withParameters(availableSpecs).build();
            }
        }));

        provider.addAlgorithmImplementation("Cipher.RC2WRAP", PREFIX + "$Wrap", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseWrapCipher.Builder(provider, RC2.RFC3217_WRAP)
                    .withGeneralOperators(generalParametersCreatorProvider, new RC2.KeyWrapOperatorFactory())
                    .withParameters(availableSpecs).build();
            }
        }));
        provider.addAlias("Cipher", "RC2WRAP", PKCSObjectIdentifiers.id_alg_CMSRC2wrap);

        provider.addAlgorithmImplementation("Mac.RC2MAC", PREFIX + "$CBCMAC", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(RC2.CBC_MAC, new RC2.MACOperatorFactory(), new AuthParametersCreator(RC2.CBC_MAC));
            }
        }));
        provider.addAlias("Alg.Alias.Mac.RC2", "RC2MAC");
        provider.addAlgorithmImplementation("Mac.RC2MAC/CFB8", PREFIX + "$CFB8MAC", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseMac(RC2.CFB8_MAC, new RC2.MACOperatorFactory(), new AuthParametersCreator(RC2.CFB8_MAC));
            }
        }));
        provider.addAlias("Alg.Alias.Mac.RC2/CFB8", "RC2MAC/CFB8");


        provider.addAlgorithmImplementation("Cipher.PBEWITHSHAAND128BITRC2-CBC", PREFIX + "$PBEWithSHAAnd128BitRC2", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {

                return new BaseCipher.Builder(provider, 64, RC2.CBCwithPKCS7)
                    .withFixedKeySize(128)
                    .withScheme(PBEScheme.PKCS12)
                    .withGeneralOperators(generalParametersCreatorProvider, new RC2.OperatorFactory(), null)
                    .withParameters(availableSpecs).build();
            }
        }));
        provider.addAlgorithmImplementation("Cipher.PBEWITHSHAAND40BITRC2-CBC", PREFIX + "$PBEWithSHAAnd40BitRC2", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 64, RC2.CBCwithPKCS7)
                    .withFixedKeySize(40)
                    .withScheme(PBEScheme.PKCS12)
                    .withGeneralOperators(generalParametersCreatorProvider, new RC2.OperatorFactory(), null)
                    .withParameters(availableSpecs).build();
            }
        }));
        provider.addAlgorithmImplementation("Cipher.PBEWITHMD5ANDRC2-CBC", PREFIX + "$PBEWithMD5", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 64, RC2.CBCwithPKCS7)
                    .withGeneralOperators(generalParametersCreatorProvider, new RC2.OperatorFactory(), null)
                    .withFixedKeySize(64)
                    .withScheme(PBEScheme.PBKDF1)
                    .withPrf(SecureHash.Algorithm.MD5)
                    .withParameters(availableSpecs).build();
            }
        }));
        provider.addAlgorithmImplementation("Cipher.PBEWITHSHA1ANDRC2-CBC", PREFIX + "$PBEWithSHA1", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 64, RC2.CBCwithPKCS7)
                    .withGeneralOperators(generalParametersCreatorProvider, new RC2.OperatorFactory(), null)
                    .withFixedKeySize(64)
                    .withScheme(PBEScheme.PBKDF1)
                    .withPrf(FipsSHS.Algorithm.SHA1)
                    .withParameters(availableSpecs).build();
            }
        }));

        provider.addAlias("Cipher", "PBEWITHMD5ANDRC2-CBC", PKCSObjectIdentifiers.pbeWithMD5AndRC2_CBC);
        provider.addAlias("Cipher", "PBEWITHMD5ANDRC2-CBC", "PBEWITHMD5ANDRC2");

        provider.addAlias("Cipher", "PBEWITHSHA1ANDRC2-CBC", PKCSObjectIdentifiers.pbeWithSHA1AndRC2_CBC);
        provider.addAlias("Cipher", "PBEWITHSHA1ANDRC2-CBC", "PBEWITHSHA1ANDRC2");

        provider.addAlias("Cipher", "PBEWITHSHAAND128BITRC2-CBC", PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC2_CBC);
        provider.addAlias("Cipher", "PBEWITHSHAAND40BITRC2-CBC", PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC);
        provider.addAlias("Cipher", "PBEWITHSHAAND128BITRC2-CBC", "PBEWITHSHA1AND128BITRC2-CBC");
        provider.addAlias("Cipher", "PBEWITHSHAAND40BITRC2-CBC", "PBEWITHSHA1AND40BITRC2-CBC");


        provider.addAlgorithmImplementation("SecretKeyFactory.RC2", PREFIX + "$RC2KFACT", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseSecretKeyFactory("RC2", RC2.ALGORITHM, new BaseSecretKeyFactory.Validator()
                {
                    public byte[] validated(byte[] keyBytes)
                        throws InvalidKeySpecException
                    {
                        int size = keyBytes.length * 8;
                        if (size < 8 || size > 1024)
                        {
                            throw new InvalidKeySpecException("Provided key data wrong size for RC2");
                        }

                        return keyBytes;
                    }
                });
            }
        }));

        provider.addAlgorithmImplementation("SecretKeyFactory.PBEWITHMD5ANDRC2", PREFIX + "PBEMD5RC2", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ProvPBEPBKDF1.FixedPBKDF1("RC2", PasswordConverter.ASCII, SecureHash.Algorithm.MD5, 64);
            }
        }));
        provider.addAlgorithmImplementation("SecretKeyFactory.PBEWITHSHAANDRC2", PREFIX + "PBESHARC2", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ProvPBEPBKDF1.FixedPBKDF1("RC2", PasswordConverter.ASCII, FipsSHS.Algorithm.SHA1, 64);
            }
        }));
        provider.addAlias("SecretKeyFactory", "PBEWITHSHAANDRC2", "PBEWITHSHA1ANDRC2", "PBEWITHSHA-1ANDRC2");

        provider.addAlgorithmImplementation("SecretKeyFactory.PBEWITHSHAAND128BITRC2", PREFIX + "PBE128RC2", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ProvPKCS12.KeyFactory("RC2", PasswordBasedDeriver.KeyType.CIPHER, 128);
            }
        }));
        provider.addAlias("SecretKeyFactory", "PBEWITHSHAAND128BITRC2", "PBEWITHSHA1AND128BITRC2", "PBEWITHSHA-1AND128BITRC2");

        provider.addAlgorithmImplementation("SecretKeyFactory.PBEWITHSHAAND40BITRC2", PREFIX + "PBE40RC2", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ProvPKCS12.KeyFactory("RC2", PasswordBasedDeriver.KeyType.CIPHER, 40);
            }
        }));
        provider.addAlias("SecretKeyFactory", "PBEWITHSHAAND40BITRC2", "PBEWITHSHA1AND40BITRC2", "PBEWITHSHA-1AND40BITRC2");

        provider.addAlias("AlgorithmParameters", "PBKDF-PKCS12", PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC, PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC2_CBC);
    }
}
