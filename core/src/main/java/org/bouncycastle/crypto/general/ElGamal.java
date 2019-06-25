package org.bouncycastle.crypto.general;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricKey;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DigestAlgorithm;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.InvalidWrappingException;
import org.bouncycastle.crypto.KeyUnwrapperUsingSecureRandom;
import org.bouncycastle.crypto.KeyWrapperUsingSecureRandom;
import org.bouncycastle.crypto.PlainInputProcessingException;
import org.bouncycastle.crypto.SingleBlockDecryptor;
import org.bouncycastle.crypto.asymmetric.AsymmetricDHKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricDHPrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricDHPublicKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricKeyPair;
import org.bouncycastle.crypto.asymmetric.DHDomainParameters;
import org.bouncycastle.crypto.fips.FipsDH;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.crypto.fips.FipsStatus;
import org.bouncycastle.crypto.fips.FipsUnapprovedOperationError;
import org.bouncycastle.crypto.internal.AsymmetricBlockCipher;
import org.bouncycastle.crypto.internal.CipherParameters;
import org.bouncycastle.crypto.internal.encodings.OAEPEncoding;
import org.bouncycastle.crypto.internal.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.internal.params.ParametersWithRandom;
import org.bouncycastle.util.Arrays;

/**
 * Source class for implementations of ElGamal based algorithms.
 */
public final class ElGamal
{
    private ElGamal()
    {

    }

    private enum Variations
    {
        RAW,
        PKCS1v1_5,
        OAEP
    }

    /**
     * Basic ElGamal key marker, can be used for creating general purpose ElGamal keys.
     */
    public static final GeneralAlgorithm ALGORITHM = new GeneralAlgorithm("ELGAMAL", Variations.RAW);

    private static final GeneralAlgorithm PKCS1v1_5 = new GeneralAlgorithm("ELGAMAL/PKCS1V1.5", Variations.PKCS1v1_5);
    private static final GeneralAlgorithm ALGORITHM_OAEP = new GeneralAlgorithm("ELGAMAL/OAEP", Variations.OAEP);

    /**
     * RAW ElGamal algorithm parameter source.
     */
    public static final RawParameters RAW = new RawParameters();

    /**
     * PKCS#1 v1.5 ElGamal algorithm parameter source.
     */
    public static final OAEPParameters WRAP_OAEP = new OAEPParameters();

    /**
     * OAEP ElGamal algorithm parameter source - default digest is SHA-1
     */
    public static final PKCS1v15Parameters WRAP_PKCS1v1_5 = new PKCS1v15Parameters();

    /**
     * Base class for ElGamal encryption/decryption and key wrap/unwrap parameters.
     */
    public static class Parameters
        extends GeneralParameters
    {
        Parameters(GeneralAlgorithm algorithm)
        {
            super(algorithm);
        }
    }

    /**
     * Parameters for use with unformatted encryption/decryption.
     */
    public static final class RawParameters
        extends Parameters
    {
        RawParameters()
        {
            super(ALGORITHM);
        }
    }

    /**
     * Marker interface for parameters that can also be used for key wrapping.
     */
    public interface WrapParameters extends org.bouncycastle.crypto.Parameters
    {

    }

    /**
     * Parameters for use with PKCS#1 v1.5 formatted key wrapping/unwrapping and encryption/decryption.
     */
    public static final class PKCS1v15Parameters
        extends Parameters implements WrapParameters
    {
        PKCS1v15Parameters()
        {
            super(PKCS1v1_5);
        }
    }

    /**
     * Parameters for use with OAEP formatted key wrapping/unwrapping and encryption/decryption.
     */
    public static final class OAEPParameters
        extends Parameters implements WrapParameters
    {
        private final DigestAlgorithm digestAlgorithm;
        private final DigestAlgorithm mgfDigestAlgorithm;
        private final byte[] encodingParams;

        OAEPParameters()
        {
            this(FipsSHS.Algorithm.SHA1, FipsSHS.Algorithm.SHA1, null);
        }

        private OAEPParameters(DigestAlgorithm digestAlgorithm, DigestAlgorithm mgfDigestAlgorithm, byte[] encodingParams)
        {
            super(ALGORITHM_OAEP);

            this.digestAlgorithm = digestAlgorithm;
            this.mgfDigestAlgorithm = mgfDigestAlgorithm;
            this.encodingParams = Arrays.clone(encodingParams);
        }

        /**
         * Specify the digest algorithm to use. This also sets the MGF digest.
         *
         * @param digestAlgorithm  a digest algorithm.
         * @return a new parameter set.
         */
        public OAEPParameters withDigest(DigestAlgorithm digestAlgorithm)
        {
            return new OAEPParameters(digestAlgorithm, digestAlgorithm, encodingParams);
        }

        /**
         * Specify the digest algorithm to use for the MGF.
         *
         * @param mgfDigestAlgorithm  a digest algorithm for the MGF.
         * @return a new parameter set.
         */
        public OAEPParameters withMGFDigest(DigestAlgorithm mgfDigestAlgorithm)
        {
            return new OAEPParameters(digestAlgorithm, mgfDigestAlgorithm, encodingParams);
        }

        /**
         * Set the encoding parameters.
         *
         * @param encodingParams encoding params to include.
         * @return a new parameter set.
         */
        public OAEPParameters withEncodingParams(byte[] encodingParams)
        {
            return new OAEPParameters(digestAlgorithm, mgfDigestAlgorithm, Arrays.clone(encodingParams));
        }

        public DigestAlgorithm getDigest()
        {
            return digestAlgorithm;
        }

        public DigestAlgorithm getMGFDigest()
        {
            return mgfDigestAlgorithm;
        }

        public byte[] getEncodingParams()
        {
            return Arrays.clone(encodingParams);
        }
    }

    /**
     * ElGamal key pair generation parameters.
     */
    public static final class KeyGenParameters
        extends GeneralParameters
    {
        private DHDomainParameters domainParameters;

        /**
         * Base constructor for specific domain parameters.
         *
         * @param domainParameters the DH domain parameters.
         */
        public KeyGenParameters(DHDomainParameters domainParameters)
        {
            super(ALGORITHM);
            this.domainParameters = domainParameters;
        }

        /**
         * Constructor for specifying the ElGamal algorithm explicitly.
         *
         * @param parameters the particular parameter set to generate keys for.
         * @param domainParameters DH domain parameters representing the curve any generated keys will be for.
         */
        public KeyGenParameters(Parameters parameters, DHDomainParameters domainParameters)
        {
            super(parameters.getAlgorithm());
            this.domainParameters = domainParameters;
        }

        public DHDomainParameters getDomainParameters()
        {
            return domainParameters;
        }
    }

    /**
     * ElGamal key pair generator class.
     */
    public static final class KeyPairGenerator
        extends GuardedAsymmetricKeyPairGenerator<KeyGenParameters, AsymmetricDHPublicKey, AsymmetricDHPrivateKey>
    {
        private final FipsDH.KeyPairGenerator kpGen;

        public KeyPairGenerator(KeyGenParameters keyGenParameters, SecureRandom random)
        {
            super(keyGenParameters);

            this.kpGen = new FipsDH.KeyPairGenerator(new FipsDH.KeyGenParameters(keyGenParameters.domainParameters), random);
        }

        @Override
        protected AsymmetricKeyPair<AsymmetricDHPublicKey, AsymmetricDHPrivateKey> doGenerateKeyPair()
        {
            AsymmetricKeyPair kp = kpGen.generateKeyPair();
            Algorithm algorithm = this.getParameters().getAlgorithm();

            AsymmetricDHPublicKey pubK = (AsymmetricDHPublicKey)kp.getPublicKey();
            AsymmetricDHPrivateKey priK = (AsymmetricDHPrivateKey)kp.getPrivateKey();

            return new AsymmetricKeyPair<AsymmetricDHPublicKey, AsymmetricDHPrivateKey>(new AsymmetricDHPublicKey(algorithm, pubK.getDomainParameters(), pubK.getY()), new AsymmetricDHPrivateKey(algorithm, priK.getDomainParameters(), priK.getX()));
        }
    }

    /**
     * Factory for creating ElGamal encryption/decryption operators.
     */
    public static final class OperatorFactory
        extends GuardedAsymmetricOperatorFactory<Parameters>
    {
        public SingleBlockDecryptor<Parameters> createBlockDecryptor(AsymmetricKey key, final Parameters parameters)
        {
            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                throw new FipsUnapprovedOperationError("Attempt to create unapproved algorithm in approved only mode", parameters.getAlgorithm());
            }

            final AsymmetricBlockCipher engine = createCipher(false, key, parameters, null);

            return new SingleBlockDecryptor<Parameters>()
            {
                public byte[] decryptBlock(byte[] bytes, int offSet, int length)
                    throws InvalidCipherTextException
                {
                    try
                    {
                        Utils.approveModeCheck(parameters.getAlgorithm());

                        return engine.processBlock(bytes, offSet, length);
                    }
                    catch (org.bouncycastle.crypto.internal.InvalidCipherTextException e)
                    {
                        throw new InvalidCipherTextException(e.getMessage(), e);
                    }
                }

                public Parameters getParameters()
                {
                    Utils.approveModeCheck(parameters.getAlgorithm());

                    return parameters;
                }

                public int getInputSize()
                {
                    Utils.approveModeCheck(parameters.getAlgorithm());

                    // we allow one extra byte for raw engines
                    if (isRawEngine(engine))
                    {
                        return engine.getInputBlockSize() + 1;
                    }
                    else
                    {
                        return engine.getInputBlockSize();
                    }
                }

                public int getOutputSize()
                {
                    Utils.approveModeCheck(parameters.getAlgorithm());

                    return engine.getOutputBlockSize();
                }
            };
        }

        @Override
        protected AsymmetricBlockCipher createCipher(boolean forEncryption, AsymmetricKey key, Parameters parameters, SecureRandom random)
        {
            return ElGamal.createCipher(forEncryption, key, parameters, random);
        }
    }

    /**
     * Factory for creating ElGamal key wrap/unwrap operators.
     */
    public static final class KeyWrapOperatorFactory
        implements org.bouncycastle.crypto.KeyWrapOperatorFactory<WrapParameters, AsymmetricDHKey>
    {
        public KeyWrapOperatorFactory()
        {
            FipsStatus.isReady();
            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                throw new FipsUnapprovedOperationError("Attempt to create unapproved factory in approved only mode");
            }
        }

        public KeyWrapperUsingSecureRandom<WrapParameters> createKeyWrapper(AsymmetricDHKey key, WrapParameters parameters)
        {
            return new KeyWrapper(key, parameters, null);
        }

        public KeyUnwrapperUsingSecureRandom<WrapParameters> createKeyUnwrapper(AsymmetricDHKey key, WrapParameters parameters)
        {
            return new KeyUnwrapper(key, parameters, null);
        }

        private class KeyWrapper
            implements KeyWrapperUsingSecureRandom<WrapParameters>
        {
            private final AsymmetricBlockCipher keyWrapper;
            private final AsymmetricDHKey key;
            private final WrapParameters parameters;

            public KeyWrapper(AsymmetricDHKey key, WrapParameters parameters, SecureRandom random)
            {
                if (!(parameters instanceof Parameters))
                {
                    throw new IllegalArgumentException("Unknown parameters object: " + parameters.getClass().getName());
                }
                this.key = key;
                this.parameters = parameters;

                if (random != null)
                {
                    keyWrapper = createCipher(true, key, (Parameters)parameters, random);
                }
                else
                {
                    keyWrapper = null;
                }
            }

            public WrapParameters getParameters()
            {
                return parameters;
            }

            public byte[] wrap(byte[] in, int inOff, int inLen)
                throws PlainInputProcessingException
            {
                if (keyWrapper == null)
                {
                    throw new IllegalStateException("KeyWrapper requires a SecureRandom");
                }

                Utils.approveModeCheck(parameters.getAlgorithm());

                try
                {
                    return keyWrapper.processBlock(in, inOff, inLen);
                }
                catch (Exception e)
                {
                    throw new PlainInputProcessingException("Unable to wrap key: " + e.getMessage(), e);
                }
            }

            public KeyWrapperUsingSecureRandom<WrapParameters> withSecureRandom(SecureRandom random)
            {
                return new KeyWrapper(this.key, this.parameters, random);
            }
        }

        private class KeyUnwrapper
            implements KeyUnwrapperUsingSecureRandom<WrapParameters>
        {
            private final AsymmetricBlockCipher keyWrapper;
            private final AsymmetricDHKey key;
            private final WrapParameters parameters;

            public KeyUnwrapper(AsymmetricDHKey key, WrapParameters parameters, SecureRandom random)
            {
                if (!(parameters instanceof Parameters))
                {
                    throw new IllegalArgumentException("Unknown parameters object: " + parameters.getClass().getName());
                }
                this.key = key;
                this.parameters = parameters;

                if (random != null)
                {
                    keyWrapper = createCipher(false, key, (Parameters)parameters, random);
                }
                else
                {
                    keyWrapper = null;
                }
            }

            public WrapParameters getParameters()
            {
                return parameters;
            }

            public byte[] unwrap(byte[] in, int inOff, int inLen)
                throws InvalidWrappingException
            {
                if (keyWrapper == null)
                {
                    throw new IllegalStateException("KeyUnwrapper requires a SecureRandom");
                }

                Utils.approveModeCheck(parameters.getAlgorithm());

                try
                {
                    return keyWrapper.processBlock(in, inOff, inLen);
                }
                catch (Exception e)
                {
                    throw new InvalidWrappingException("Unable to unwrap key: " + e.getMessage(), e);
                }
            }

            public KeyUnwrapperUsingSecureRandom<WrapParameters> withSecureRandom(SecureRandom random)
            {
                return new KeyUnwrapper(this.key, this.parameters, random);
            }
        }
    }

    private static AsymmetricBlockCipher createCipher(boolean forEncryption, AsymmetricKey key, Parameters parameters, SecureRandom random)
    {
        AsymmetricBlockCipher engine = new ElGamalEngine();

        CipherParameters params;

        if (key instanceof AsymmetricDHPublicKey)
        {
            AsymmetricDHPublicKey k = (AsymmetricDHPublicKey)key;

            params = new ElGamalPublicKeyParameters(k.getY(), new ElGamalParameters(k.getDomainParameters().getP(), k.getDomainParameters().getG(), k.getDomainParameters().getL()));
        }
        else
        {
            AsymmetricDHPrivateKey k = (AsymmetricDHPrivateKey)key;

            params = new ElGamalPrivateKeyParameters(k.getX(), new ElGamalParameters(k.getDomainParameters().getP(), k.getDomainParameters().getG(), k.getDomainParameters().getL()));
        }

        if (parameters.getAlgorithm().equals(PKCS1v1_5))
        {
            engine = new PKCS1Encoding(engine);
        }
        else if (parameters.getAlgorithm().equals(ALGORITHM_OAEP))
        {
            OAEPParameters oeapParams = (OAEPParameters)parameters;

            engine = new OAEPEncoding(engine, Register.createDigest(oeapParams.digestAlgorithm), Register.createDigest(oeapParams.mgfDigestAlgorithm), oeapParams.encodingParams);
        }

        if (random != null)
        {
            params = new ParametersWithRandom(params, random);
        }

        engine.init(forEncryption, params);

        return engine;
    }
}
