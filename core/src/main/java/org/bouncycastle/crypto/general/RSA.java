package org.bouncycastle.crypto.general;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.SecureRandom;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricKey;
import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.AsymmetricPublicKey;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DigestAlgorithm;
import org.bouncycastle.crypto.IllegalKeyException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.InvalidSignatureException;
import org.bouncycastle.crypto.InvalidWrappingException;
import org.bouncycastle.crypto.KeyUnwrapperUsingSecureRandom;
import org.bouncycastle.crypto.KeyWrapperUsingSecureRandom;
import org.bouncycastle.crypto.OperatorUsingSecureRandom;
import org.bouncycastle.crypto.OutputSignerUsingSecureRandom;
import org.bouncycastle.crypto.OutputSignerWithMessageRecovery;
import org.bouncycastle.crypto.OutputVerifier;
import org.bouncycastle.crypto.OutputVerifierWithMessageRecovery;
import org.bouncycastle.crypto.PlainInputProcessingException;
import org.bouncycastle.crypto.RecoveredMessage;
import org.bouncycastle.crypto.SingleBlockDecryptor;
import org.bouncycastle.crypto.SingleBlockDecryptorUsingSecureRandom;
import org.bouncycastle.crypto.UpdateOutputStream;
import org.bouncycastle.crypto.asymmetric.AsymmetricKeyPair;
import org.bouncycastle.crypto.asymmetric.AsymmetricRSAKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricRSAPrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricRSAPublicKey;
import org.bouncycastle.crypto.fips.FipsRSA;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.crypto.fips.FipsStatus;
import org.bouncycastle.crypto.fips.FipsUnapprovedOperationError;
import org.bouncycastle.crypto.internal.AsymmetricBlockCipher;
import org.bouncycastle.crypto.internal.CipherParameters;
import org.bouncycastle.crypto.internal.CryptoException;
import org.bouncycastle.crypto.internal.DataLengthException;
import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.PrimeCertaintyCalculator;
import org.bouncycastle.crypto.internal.Signer;
import org.bouncycastle.crypto.internal.SignerWithRecovery;
import org.bouncycastle.crypto.internal.encodings.OAEPEncoding;
import org.bouncycastle.crypto.internal.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.internal.io.SignerOutputStream;
import org.bouncycastle.crypto.internal.params.ParametersWithRandom;
import org.bouncycastle.crypto.internal.params.RsaKeyParameters;
import org.bouncycastle.crypto.internal.params.RsaPrivateCrtKeyParameters;
import org.bouncycastle.crypto.internal.signers.BaseRsaDigestSigner;
import org.bouncycastle.util.Arrays;

/**
 * Source class for non-FIPS implementations of RSA based algorithms.
 */
public final class RSA
{
    private RSA()
    {

    }

    private enum Variations
    {
        RAW,
        PKCS1v1_5,
        PSS,
        X931,
        ISO9796d2,
        ISO9796d2PSS,
        OAEP
    }

    /**
     * The generic algorithm for RSA.
     */
    public static final GeneralAlgorithm ALGORITHM = new GeneralAlgorithm("RSA", Variations.RAW);

    private static final GeneralAlgorithm ALGORITHM_OAEP = new GeneralAlgorithm("RSA/OAEP", Variations.OAEP);
    private static final GeneralAlgorithm ALGORITHM_PKCS1v1_5 = new GeneralAlgorithm("RSA/PKCS1V1.5", Variations.PKCS1v1_5);
    private static final GeneralAlgorithm ALGORITHM_X931 = new GeneralAlgorithm("RSA/X9.31", Variations.X931);
    private static final GeneralAlgorithm ALGORITHM_PSS = new GeneralAlgorithm("RSA/PSS", Variations.PSS);
    private static final GeneralAlgorithm ALGORITHM_ISO9796d2 = new GeneralAlgorithm("RSA/ISO9796-2", Variations.ISO9796d2);
    private static final GeneralAlgorithm ALGORITHM_ISO9796d2PSS = new GeneralAlgorithm("RSA/ISO9796-2PSS", Variations.ISO9796d2PSS);

    /**
     * Algorithm parameter source for raw unpadded RSA.
     */
    public static final RawParameters RAW = new RawParameters();

    /**
     * Algorithm parameter source for ISO9796-2.
     */
    public static final ISO9796d2SignatureParameters ISO9796d2 = new ISO9796d2SignatureParameters();

    /**
     * Algorithm parameter source for ISO9796-2PSS.
     */
    public static final ISO9796d2PSSSignatureParameters ISO9796d2PSS = new ISO9796d2PSSSignatureParameters();

    /**
     * RSA OAEP algorithm parameter source - default digest is SHA-1
     */
    public static final OAEPParameters WRAP_OAEP = new OAEPParameters();

    /**
     * RSA PKCS#1 v1.5 Signature parameter source - default digest is SHA-1.
     */
    public static final PKCS1v15SignatureParameters PKCS1v1_5 = new PKCS1v15SignatureParameters();

    /**
     * RSA PKCS#1 v1.5 key wrap algorithm parameter source - default is SHA-1
     */
    public static final PKCS1v15Parameters WRAP_PKCS1v1_5 = new PKCS1v15Parameters();

    /**
     * RSA X9.31 signature algorithm parameter source - default is SHA-1
     */
    public static final X931SignatureParameters X931 = new X931SignatureParameters();

    /**
     * Base class for RSA encryption/decryption and key wrap/unwrap parameters.
     */
    public static class Parameters
        extends GeneralParameters<GeneralAlgorithm>
    {
        Parameters(GeneralAlgorithm algorithm)
        {
            super(algorithm);
        }
    }

    /**
     * Parameters for use with unformatted RSA encryption/decryption.
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
     * Base class for parameters that can also be used for key wrapping.
     */
    public static class WrapParameters
        extends Parameters
    {
        WrapParameters(GeneralAlgorithm algorithm)
        {
            super(algorithm);
        }
    }

    /**
     * Parameters for use with non-FIPS RSA PKCS#1 v1.5 formatted key wrapping/unwrapping and encryption/decryption.
     */
    public static final class PKCS1v15Parameters
        extends WrapParameters
    {
        PKCS1v15Parameters()
        {
            super(ALGORITHM_PKCS1v1_5);
        }
    }

    /**
     * Parameters for use with non-FIPS RSA OAEP formatted key wrapping/unwrapping and encryption/decryption.
     */
    public static final class OAEPParameters
        extends WrapParameters
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
         * @param digestAlgorithm a digest algorithm.
         * @return a new parameter set.
         */
        public OAEPParameters withDigest(DigestAlgorithm digestAlgorithm)
        {
            return new OAEPParameters(digestAlgorithm, digestAlgorithm, encodingParams);
        }

        /**
         * Specify the digest algorithm to use for the MGF.
         *
         * @param mgfDigestAlgorithm a digest algorithm for the MGF.
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
     * RSA key pair generation parameters for non-FIPS usages.
     */
    public static final class KeyGenParameters
        extends GeneralParameters<GeneralAlgorithm>
    {
        private BigInteger publicExponent;
        private int keySize;
        private int certainty;

        /**
         * Base constructor.
         *
         * @param publicExponent the public exponent to use.
         * @param keySize the key size (in bits).
         */
        public KeyGenParameters(BigInteger publicExponent, int keySize)
        {
            this(ALGORITHM, publicExponent, keySize, PrimeCertaintyCalculator.getDefaultCertainty(keySize));
        }

        /**
          * Base constructor with certainty.
          *
          * @param publicExponent the public exponent to use.
          * @param keySize the key size (in bits).
          * @param certainty certainty to use for prime number calculation.
          */
         public KeyGenParameters(BigInteger publicExponent, int keySize, int certainty)
         {
             this(ALGORITHM, publicExponent, keySize, certainty);
         }

        /**
         * Constructor for a key targeted to a specific signature algorithm.
         *
         * @param parameters the signature parameter set containing the algorithm.
         * @param publicExponent the public exponent to use.
         * @param keySize the key size (in bits).
         */
        public KeyGenParameters(SignatureParameters parameters, BigInteger publicExponent, int keySize)
        {
            this(parameters.getAlgorithm(), publicExponent, keySize, PrimeCertaintyCalculator.getDefaultCertainty(keySize));
        }

        /**
         * Constructor for a key targeted to a specific wrap algorithm.
         *
         * @param parameters the wrap parameter set containing the algorithm.
         * @param publicExponent the public exponent to use.
         * @param keySize the key size (in bits).
         */
        public KeyGenParameters(WrapParameters parameters, BigInteger publicExponent, int keySize)
        {
            this(parameters.getAlgorithm(), publicExponent, keySize, PrimeCertaintyCalculator.getDefaultCertainty(keySize));
        }

        private KeyGenParameters(Algorithm algorithm, BigInteger publicExponent, int keySize, int certainty)
        {
            super((GeneralAlgorithm)algorithm);

            this.publicExponent = publicExponent;
            this.keySize = keySize;
            this.certainty = certainty;
        }

        public BigInteger getPublicExponent()
        {
            return publicExponent;
        }

        public int getKeySize()
        {
            return keySize;
        }

        public int getCertainty()
        {
            return certainty;
        }
    }

    /**
     * RSA key pair generator class for non-FIPS usages.
     */
    public static final class KeyPairGenerator
        extends GuardedAsymmetricKeyPairGenerator<KeyGenParameters, AsymmetricRSAPublicKey, AsymmetricRSAPrivateKey>
    {
        private final FipsRSA.KeyPairGenerator kpGen;

        public KeyPairGenerator(KeyGenParameters keyGenParameters, SecureRandom random)
        {
            super(keyGenParameters);

            this.kpGen = new FipsRSA.KeyPairGenerator(
                new FipsRSA.KeyGenParameters(keyGenParameters.publicExponent, keyGenParameters.keySize, keyGenParameters.certainty), random);
        }

        @Override
        public AsymmetricKeyPair<AsymmetricRSAPublicKey, AsymmetricRSAPrivateKey> doGenerateKeyPair()
        {
            AsymmetricKeyPair kp = kpGen.generateKeyPair();

            final AsymmetricRSAPublicKey pubKey = (AsymmetricRSAPublicKey)kp.getPublicKey();
            final AsymmetricRSAPrivateKey prvKey = (AsymmetricRSAPrivateKey)kp.getPrivateKey();

            final Algorithm algorithm = this.getParameters().getAlgorithm();

            return AccessController.doPrivileged(new PrivilegedAction<AsymmetricKeyPair<AsymmetricRSAPublicKey, AsymmetricRSAPrivateKey>>()
            {
                public AsymmetricKeyPair<AsymmetricRSAPublicKey, AsymmetricRSAPrivateKey> run()
                {
                    return new AsymmetricKeyPair<AsymmetricRSAPublicKey, AsymmetricRSAPrivateKey>(new AsymmetricRSAPublicKey(algorithm, pubKey.getModulus(), pubKey.getPublicExponent()),
                        new AsymmetricRSAPrivateKey(algorithm, prvKey.getModulus(), prvKey.getPublicExponent(), prvKey.getPrivateExponent(),
                            prvKey.getP(), prvKey.getQ(), prvKey.getDP(), prvKey.getDQ(), prvKey.getQInv()));
                }
            });

        }
    }

    /**
     * Base class for non-FIPS RSA digest based signature algorithm parameters.
     */
    public static class SignatureParameters<T extends SignatureParameters>
        extends GeneralParameters
    {
        private final DigestAlgorithm digestAlgorithm;

        SignatureParameters(GeneralAlgorithm algorithm, DigestAlgorithm digestAlgorithm)
        {
            super(algorithm);
            this.digestAlgorithm = digestAlgorithm;
        }

        public DigestAlgorithm getDigestAlgorithm()
        {
            return digestAlgorithm;
        }
    }

    /**
     * Parameters for PKCS#1 v1.5 signature algorithms.
     */
    public static final class PKCS1v15SignatureParameters
        extends SignatureParameters<PKCS1v15SignatureParameters>
    {
        PKCS1v15SignatureParameters()
        {
            super(ALGORITHM_PKCS1v1_5, FipsSHS.Algorithm.SHA1);
        }

        private PKCS1v15SignatureParameters(DigestAlgorithm digestAlgorithm)
        {
            super(ALGORITHM_PKCS1v1_5, digestAlgorithm);
        }

        /**
         * Return a new parameter set with for the passed in digest algorithm.
         *
         * @param digestAlgorithm the digest to use for signature generation.
         * @return a new parameter for signature generation.
         */
        public PKCS1v15SignatureParameters withDigestAlgorithm(DigestAlgorithm digestAlgorithm)
        {
            return new PKCS1v15SignatureParameters(digestAlgorithm);
        }
    }

    /**
     * Parameters for PKCS#1 v1.5 signature algorithms.
     */
    public static final class X931SignatureParameters
        extends SignatureParameters<X931SignatureParameters>
    {
        public X931SignatureParameters()
        {
            super(ALGORITHM_X931, FipsSHS.Algorithm.SHA1);
        }

        public X931SignatureParameters(DigestAlgorithm digestAlgorithm)
        {
            super(ALGORITHM_X931, digestAlgorithm);
        }

        /**
         * Return a new parameter set with for the passed in digest algorithm.
         *
         * @param digestAlgorithm the digest to use for signature generation.
         * @return a new parameter for signature generation.
         */
        public X931SignatureParameters withDigestAlgorithm(DigestAlgorithm digestAlgorithm)
        {
            return new X931SignatureParameters(digestAlgorithm);
        }
    }

    /**
     * Parameters for ISO 9796-2 signature algorithms.
     */
    public static final class ISO9796d2SignatureParameters
        extends SignatureParameters<ISO9796d2SignatureParameters>
    {
        ISO9796d2SignatureParameters()
        {
            super(ALGORITHM_ISO9796d2, FipsSHS.Algorithm.SHA1);
        }

        private ISO9796d2SignatureParameters(DigestAlgorithm digestAlgorithm)
        {
            super(ALGORITHM_ISO9796d2, digestAlgorithm);
        }

        /**
         * Return a new parameter set with for the passed in digest algorithm.
         *
         * @param digestAlgorithm the digest to use for signature generation.
         * @return a new parameter for signature generation.
         */
        public ISO9796d2SignatureParameters withDigestAlgorithm(DigestAlgorithm digestAlgorithm)
        {
            return new ISO9796d2SignatureParameters(digestAlgorithm);
        }
    }

    /**
     * Parameters for ISO 9796-2 PSS signature algorithms.
     */
    public static final class ISO9796d2PSSSignatureParameters
        extends SignatureParameters<ISO9796d2PSSSignatureParameters>
    {
        private final int saltLength;
        private final byte[] salt;

        ISO9796d2PSSSignatureParameters()
        {
            this(FipsSHS.Algorithm.SHA1, 20, null);
        }

        private ISO9796d2PSSSignatureParameters(DigestAlgorithm digestAlgorithm)
        {
            this(digestAlgorithm, Register.createDigest(digestAlgorithm).getDigestSize(), null);
        }

        private ISO9796d2PSSSignatureParameters(DigestAlgorithm digestAlgorithm, int saltLength, byte[] salt)
        {
            super(ALGORITHM_ISO9796d2PSS, digestAlgorithm);

            this.saltLength = saltLength;
            this.salt = salt;
        }

        /**
         * Return a new parameter set with for the passed in digest algorithm.
         *
         * @param digestAlgorithm the digest to use for signature generation.
         * @return a new parameter for signature generation.
         */
        public ISO9796d2PSSSignatureParameters withDigestAlgorithm(DigestAlgorithm digestAlgorithm)
        {
            return new ISO9796d2PSSSignatureParameters(digestAlgorithm);
        }

        /**
         * Specify the saltLength for the signature.
         *
         * @param saltLength the salt length.
         * @return a new parameter set.
         */
        public ISO9796d2PSSSignatureParameters withSaltLength(int saltLength)
        {
            return new ISO9796d2PSSSignatureParameters(this.getDigestAlgorithm(), saltLength, null);
        }

        /**
         * Specify a fixed salt for the signature.
         *
         * @param salt the salt to use.
         * @return a new parameter set.
         */
        public ISO9796d2PSSSignatureParameters withSalt(byte[] salt)
        {
            return new ISO9796d2PSSSignatureParameters(this.getDigestAlgorithm(), salt.length, Arrays.clone(salt));
        }

        public byte[] getSalt()
        {
            return Arrays.clone(salt);
        }

        public int getSaltLength()
        {
            return saltLength;
        }
    }

    /**
     * Operator factory for creating non-FIPS RSA based signing and verification operators.
     *
     * @param <T> the parameters type for the algorithm the factory is for.
     */
    public static final class SignatureOperatorFactory<T extends SignatureParameters>
        extends GuardedSignatureOperatorFactory<T>
    {
        @Override
        protected OutputSignerUsingSecureRandom<T> doCreateSigner(AsymmetricPrivateKey key, final T parameters)
        {
            AsymmetricRSAPrivateKey k = (AsymmetricRSAPrivateKey)key;

            // FSM_STATE:5.13,"RSA KEY USAGE CHECK", "The module verifies recent usage of an RSA key is consistent with requested usage"
            // FSM_TRANS:5.RSAK.0,"CONDITIONAL TEST", "RSA KEY USAGE CHECK", "Invoke RSA key usage check"
            if (!k.canBeUsed(AsymmetricRSAKey.Usage.SIGN_OR_VERIFY))
            {
                // FSM_TRANS:5.RSAK.2,"RSA KEY USAGE CHECK", "USER COMMAND REJECTED", "RSA key usage check failed"
                throw new IllegalKeyException("Attempt to sign/verify with RSA modulus already used for encrypt/decrypt.");
            }
            // FSM_TRANS:5.RSAK.1,"RSA KEY USAGE CHECK", "CONDITIONAL TEST", "RSA key usage check successful"

            return new RSASigner<T>(parameters, getPrivateKeyParameters(k), null);
        }

        private class RSASigner<P extends SignatureParameters>
            implements OutputSignerUsingSecureRandom<P>
        {
            private final Signer signer;
            private final CipherParameters keyParameters;
            private final P parameters;

            private SecureRandom random;

            RSASigner(P parameters, CipherParameters keyParameters, SecureRandom random)
            {
                this.parameters = parameters;
                this.keyParameters = keyParameters;
                this.random = random;
                this.signer = getSigner(parameters);

                if (random != null)
                {
                    signer.init(true, new ParametersWithRandom(keyParameters, random));
                }
            }

            public P getParameters()
            {
                return parameters;
            }

            public UpdateOutputStream getSigningStream()
            {
                checkInit();

                return new SignerOutputStream(parameters.getAlgorithm().getName(), signer);
            }

            public byte[] getSignature()
                throws PlainInputProcessingException
            {
                try
                {
                    return signer.generateSignature();
                }
                catch (Exception e)
                {
                    throw new PlainInputProcessingException("Unable to create signature: " + e.getMessage(), e);
                }
            }

            public OutputSignerUsingSecureRandom<P> withSecureRandom(SecureRandom random)
            {
                return new RSASigner<P>(parameters, keyParameters, random);
            }

            public int getSignature(byte[] output, int off)
                throws PlainInputProcessingException
            {
                byte[] signature = getSignature();

                System.arraycopy(signature, 0, output, off, signature.length);

                return signature.length;
            }

            private void checkInit()
            {
                if (random == null)
                {
                    random = CryptoServicesRegistrar.getSecureRandom();
                    signer.init(true, new ParametersWithRandom(keyParameters, random));
                }
            }
        }

        private Signer getSigner(SignatureParameters parameters)
        {
            if (parameters.getAlgorithm() == ALGORITHM_PKCS1v1_5)
            {
                if (parameters.getDigestAlgorithm() == null)
                {
                    return new NullSigner();
                }
                return new RsaDigestSigner(Register.createDigest(parameters.digestAlgorithm));
            }
            else if (parameters.getAlgorithm() == ALGORITHM_X931)
            {
                return new X931Signer(Register.createDigest(parameters.digestAlgorithm));
            }
            else
            {
                throw new IllegalArgumentException("Algorithm " + parameters.getAlgorithm().getName() + " not recognized");
            }
        }

        @Override
        public OutputVerifier<T> doCreateVerifier(AsymmetricPublicKey key, final SignatureParameters parameters)
        {
            AsymmetricRSAPublicKey k = (AsymmetricRSAPublicKey)key;

            // FSM_STATE:5.13,"RSA KEY USAGE CHECK", "The module verifies recent usage of an RSA key is consistent with requested usage"
            // FSM_TRANS:5.RSAK.0,"CONDITIONAL TEST", "RSA KEY USAGE CHECK", "Invoke RSA key usage check"
            if (!k.canBeUsed(AsymmetricRSAKey.Usage.SIGN_OR_VERIFY))
            {
                // FSM_TRANS:5.RSAK.2,"RSA KEY USAGE CHECK", "USER COMMAND REJECTED", "RSA key usage check failed"
                throw new IllegalKeyException("Attempt to sign/verify with RSA modulus already used for encrypt/decrypt.");
            }
            // FSM_TRANS:5.RSAK.1,"RSA KEY USAGE CHECK", "CONDITIONAL TEST", "RSA key usage check successful"

            RsaKeyParameters publicKeyParameters = new RsaKeyParameters(false, k.getModulus(), k.getPublicExponent());

            final Signer rsaSigner = getSigner(parameters);

            rsaSigner.init(false, publicKeyParameters);

            return new OutputVerifier<T>()
            {
                public T getParameters()
                {
                    return (T)parameters;
                }

                public UpdateOutputStream getVerifyingStream()
                {
                    return new SignerOutputStream(parameters.getAlgorithm().getName(), rsaSigner);
                }

                public boolean isVerified(byte[] signature)
                    throws InvalidSignatureException
                {
                    return rsaSigner.verifySignature(signature);
                }
            };
        }
    }

    /**
     * Operator factory for creating RSA based signing and verification operators which also offer message recovery.
     *
     * @param <T> the parameters type for the algorithm the factory is for.
     */
    public static final class SignatureWithMessageRecoveryOperatorFactory<T extends SignatureParameters>
        extends GuardedSignatureWithMessageRecoveryOperatorFactory<T>
    {
        @Override
        protected OutputSignerWithMessageRecovery<T> doCreateSigner(AsymmetricPrivateKey key, final T parameters)
        {
            AsymmetricRSAPrivateKey k = (AsymmetricRSAPrivateKey)key;

            // FSM_STATE:5.13,"RSA KEY USAGE CHECK", "The module verifies recent usage of an RSA key is consistent with requested usage"
            // FSM_TRANS:5.RSAK.0,"CONDITIONAL TEST", "RSA KEY USAGE CHECK", "Invoke RSA key usage check"
            if (!k.canBeUsed(AsymmetricRSAKey.Usage.SIGN_OR_VERIFY))
            {
                // FSM_TRANS:5.RSAK.2,"RSA KEY USAGE CHECK", "USER COMMAND REJECTED", "RSA key usage check failed"
                throw new IllegalKeyException("Attempt to sign/verify with RSA modulus already used for encrypt/decrypt.");
            }
            // FSM_TRANS:5.RSAK.1,"RSA KEY USAGE CHECK", "CONDITIONAL TEST", "RSA key usage check successful"

            RsaKeyParameters privateKeyParameters = getPrivateKeyParameters(k);

            return new RSASigner<T>(parameters, privateKeyParameters, null);
        }

        @Override
        protected OutputVerifierWithMessageRecovery<T> doCreateVerifier(AsymmetricPublicKey key, final SignatureParameters parameters)
        {
            AsymmetricRSAPublicKey k = (AsymmetricRSAPublicKey)key;

            // FSM_STATE:5.13,"RSA KEY USAGE CHECK", "The module verifies recent usage of an RSA key is consistent with requested usage"
            // FSM_TRANS:5.RSAK.0,"CONDITIONAL TEST", "RSA KEY USAGE CHECK", "Invoke RSA key usage check"
            if (!k.canBeUsed(AsymmetricRSAKey.Usage.SIGN_OR_VERIFY))
            {
                // FSM_TRANS:5.RSAK.2,"RSA KEY USAGE CHECK", "USER COMMAND REJECTED", "RSA key usage check failed"
                throw new IllegalKeyException("Attempt to sign/verify with RSA modulus already used for encrypt/decrypt.");
            }
            // FSM_TRANS:5.RSAK.1,"RSA KEY USAGE CHECK", "CONDITIONAL TEST", "RSA key usage check successful"

            CipherParameters publicKeyParameters = new RsaKeyParameters(false, k.getModulus(), k.getPublicExponent());

            final SignerWithRecovery rsaSigner = getSigner(parameters);

            rsaSigner.init(false, publicKeyParameters);

            return new OutputVerifierWithMessageRecovery<T>()
            {
                public T getParameters()
                {
                    return (T)parameters;
                }

                public UpdateOutputStream getVerifyingStream()
                {
                    return new SignerOutputStream(parameters.getAlgorithm().getName(), rsaSigner);
                }

                public boolean isVerified(byte[] signature)
                    throws InvalidSignatureException
                {
                    return rsaSigner.verifySignature(signature);
                }

                public RecoveredMessage getRecoveredMessage()
                {
                    return new RecoveredMessageImpl(rsaSigner.hasFullMessage(), rsaSigner.getRecoveredMessage());
                }

                public void updateWithRecoveredMessage(byte[] signature)
                    throws InvalidSignatureException
                {
                    try
                    {
                        rsaSigner.updateWithRecoveredMessage(signature);
                    }
                    catch (Exception e)
                    {
                        throw new InvalidSignatureException("Unable to recover message: " + e.getMessage(), e);
                    }
                }

            };
        }

        private SignerWithRecovery getSigner(SignatureParameters parameters)
        {
            if (parameters.getAlgorithm() == ALGORITHM_ISO9796d2)
            {
                return new ISO9796d2Signer(Register.createDigest(parameters.digestAlgorithm));
            }
            else if (parameters.getAlgorithm() == ALGORITHM_ISO9796d2PSS)
            {
                ISO9796d2PSSSignatureParameters params = (ISO9796d2PSSSignatureParameters)parameters;

                Digest digest = Register.createDigest(parameters.digestAlgorithm);

                byte[] fixedSalt = params.getSalt();
                if (fixedSalt != null)
                {
                    return new ISO9796d2PSSSigner(digest, fixedSalt);
                }
                else
                {
                    return new ISO9796d2PSSSigner(digest, params.getSaltLength());
                }
            }
            else
            {
                throw new IllegalArgumentException("Algorithm " + parameters.getAlgorithm().getName() + " not recognized");
            }
        }

        private class RSASigner<T extends SignatureParameters>
            implements OutputSignerWithMessageRecovery<T>, OperatorUsingSecureRandom<RSASigner<T>>
        {
            private final SignerWithRecovery signer;
            private final CipherParameters keyParameters;
            private final T parameters;

            private SecureRandom random;

            RSASigner(T parameters, CipherParameters keyParameters, SecureRandom random)
            {
                this.parameters = parameters;
                this.keyParameters = keyParameters;
                this.random = random;
                this.signer = getSigner(parameters);

                if (random != null)
                {
                    signer.init(true, new ParametersWithRandom(keyParameters, random));
                }
            }

            public T getParameters()
            {
                return (T)parameters;
            }

            public UpdateOutputStream getSigningStream()
            {
                checkInit();

                return new SignerOutputStream(parameters.getAlgorithm().getName(), signer);
            }

            public byte[] getSignature()
                throws PlainInputProcessingException
            {
                try
                {
                    return signer.generateSignature();
                }
                catch (Exception e)
                {
                    throw new PlainInputProcessingException("Unable to create signature: " + e.getMessage(), e);
                }
            }

            public int getSignature(byte[] output, int off)
                throws PlainInputProcessingException
            {
                byte[] sig = getSignature();

                System.arraycopy(sig, 0, output, off, sig.length);

                return sig.length;
            }

            public RecoveredMessage getRecoveredMessage()
            {
                return new RecoveredMessageImpl(signer.hasFullMessage(), signer.getRecoveredMessage());
            }

            public RSASigner<T> withSecureRandom(SecureRandom random)
            {
                return new RSASigner<T>(parameters, keyParameters, random);
            }

            private void checkInit()
            {
                if (random == null)
                {
                    random = CryptoServicesRegistrar.getSecureRandom();
                    signer.init(true, new ParametersWithRandom(keyParameters, random));
                }
            }
        }
    }

    /**
     * Factory for creating non-FIPS encryption/decryption operators.
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

            return new BlockDecryptor(key, parameters, null);
        }

        @Override
        protected AsymmetricBlockCipher createCipher(boolean forEncryption, AsymmetricKey key, Parameters parameters, SecureRandom random)
        {
            return RSA.createCipher(forEncryption, (AsymmetricRSAKey)key, parameters, random);
        }

        private class BlockDecryptor
            implements SingleBlockDecryptorUsingSecureRandom<Parameters>
        {
            private final AsymmetricKey key;
            private final Parameters parameters;

            private AsymmetricBlockCipher engine;

            BlockDecryptor(AsymmetricKey key, Parameters parameters, SecureRandom random)
            {
                this.key = key;
                this.parameters = parameters;
                if (random != null)
                {
                    engine = createCipher(false, key, parameters, random);
                }
            }

            public byte[] decryptBlock(byte[] bytes, int offSet, int length)
                throws InvalidCipherTextException
            {
                if (engine == null)
                {
                    throw new IllegalStateException("RSA BlockDecryptor requires a SecureRandom");
                }

                Utils.approveModeCheck(parameters.getAlgorithm());

                try
                {
                    Utils.approveModeCheck(parameters.getAlgorithm());

                    return engine.processBlock(bytes, offSet, length);
                }
                catch (Exception e)
                {
                    throw new InvalidCipherTextException("Unable to decrypt block: " + e.getMessage(), e);
                }
            }

            public Parameters getParameters()
            {
                return parameters;
            }

            public int getInputSize()
            {
                Utils.approveModeCheck(parameters.getAlgorithm());

                if (engine == null)
                {
                    throw new IllegalStateException("RSA BlockDecryptor requires a SecureRandom");
                }

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

                if (engine == null)
                {
                    throw new IllegalStateException("RSA BlockDecryptor requires a SecureRandom");
                }

                return engine.getOutputBlockSize();
            }

            public SingleBlockDecryptorUsingSecureRandom<Parameters> withSecureRandom(SecureRandom random)
            {
                Utils.approveModeCheck(parameters.getAlgorithm());

                return new BlockDecryptor(key, parameters, random);
            }
        }
    }

    /**
     * Factory for creating non-FIPS RSA key wrap/unwrap operators.
     */
    public static final class KeyWrapOperatorFactory
        implements org.bouncycastle.crypto.KeyWrapOperatorFactory<WrapParameters, AsymmetricRSAKey>
    {
        public KeyWrapOperatorFactory()
        {
            FipsStatus.isReady();
            if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            {
                throw new FipsUnapprovedOperationError("Attempt to create unapproved factory in approved only mode");
            }
        }

        public KeyWrapperUsingSecureRandom<WrapParameters> createKeyWrapper(AsymmetricRSAKey key, WrapParameters parameters)
        {
            return new KeyWrapper(key, parameters, null);
        }

        public KeyUnwrapperUsingSecureRandom<WrapParameters> createKeyUnwrapper(AsymmetricRSAKey key, WrapParameters parameters)
        {
            return new KeyUnwrapper(key, parameters, null);
        }

        private class KeyWrapper
            implements KeyWrapperUsingSecureRandom<WrapParameters>
        {
            private final AsymmetricBlockCipher keyWrapper;
            private final AsymmetricRSAKey key;
            private final WrapParameters parameters;

            public KeyWrapper(AsymmetricRSAKey key, WrapParameters parameters, SecureRandom random)
            {
                // FSM_STATE:5.13,"RSA KEY USAGE CHECK", "The module verifies recent usage of an RSA key is consistent with requested usage"
                // FSM_TRANS:5.RSAK.0,"CONDITIONAL TEST", "RSA KEY USAGE CHECK", "Invoke RSA key usage check"
                if (!key.canBeUsed(AsymmetricRSAKey.Usage.ENCRYPT_OR_DECRYPT))
                {
                    // FSM_TRANS:5.RSAK.2,"RSA KEY USAGE CHECK", "USER COMMAND REJECTED", "RSA key usage check failed"
                    throw new IllegalKeyException("Attempt to encrypt/decrypt with RSA modulus already used for sign/verify.");
                }
                // FSM_TRANS:5.RSAK.1,"RSA KEY USAGE CHECK", "CONDITIONAL TEST", "RSA key usage check successful"

                if (parameters == null)
                {
                    throw new NullPointerException("Null parameters object");
                }

                this.key = key;
                this.parameters = parameters;

                if (random != null)
                {
                    keyWrapper = createCipher(true, key, parameters, random);
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
            private final AsymmetricRSAKey key;
            private final WrapParameters parameters;

            public KeyUnwrapper(AsymmetricRSAKey key, WrapParameters parameters, SecureRandom random)
            {
                // FSM_STATE:5.13,"RSA KEY USAGE CHECK", "The module verifies recent usage of an RSA key is consistent with requested usage"
                // FSM_TRANS:5.RSAK.0,"CONDITIONAL TEST", "RSA KEY USAGE CHECK", "Invoke RSA key usage check"
                if (!key.canBeUsed(AsymmetricRSAKey.Usage.ENCRYPT_OR_DECRYPT))
                {
                    // FSM_TRANS:5.RSAK.2,"RSA KEY USAGE CHECK", "USER COMMAND REJECTED", "RSA key usage check failed"
                    throw new IllegalKeyException("Attempt to encrypt/decrypt with RSA modulus already used for sign/verify.");
                }
                // FSM_TRANS:5.RSAK.1,"RSA KEY USAGE CHECK", "CONDITIONAL TEST", "RSA key usage check successful"

                if (!(parameters instanceof Parameters))
                {
                    throw new IllegalArgumentException("Unknown parameters object: " + parameters.getClass().getName());
                }

                this.key = key;
                this.parameters = parameters;

                if (random != null)
                {
                    keyWrapper = createCipher(false, key, parameters, random);
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

    private static AsymmetricBlockCipher createCipher(boolean forEncryption, AsymmetricRSAKey key, Parameters parameters, SecureRandom random)
    {
        AsymmetricBlockCipher engine = (AsymmetricBlockCipher)FipsRegister.getProvider(FipsRSA.ALGORITHM).createEngine();

        CipherParameters params;

        // FSM_STATE:5.13,"RSA KEY USAGE CHECK", "The module verifies recent usage of an RSA key is consistent with requested usage"
        // FSM_TRANS:5.RSAK.0,"CONDITIONAL TEST", "RSA KEY USAGE CHECK", "Invoke RSA key usage check"
        if (!key.canBeUsed(AsymmetricRSAKey.Usage.ENCRYPT_OR_DECRYPT))
        {
            // FSM_TRANS:5.RSAK.2,"RSA KEY USAGE CHECK", "USER COMMAND REJECTED", "RSA key usage check failed"
            throw new IllegalKeyException("Attempt to encrypt/decrypt with RSA modulus already used for sign/verify.");
        }
        // FSM_TRANS:5.RSAK.1,"RSA KEY USAGE CHECK", "CONDITIONAL TEST", "RSA key usage check successful"

        if (key instanceof AsymmetricRSAPublicKey)
        {
            AsymmetricRSAPublicKey k = (AsymmetricRSAPublicKey)key;

            params = new RsaKeyParameters(false, k.getModulus(), k.getPublicExponent());
        }
        else
        {
            AsymmetricRSAPrivateKey k = (AsymmetricRSAPrivateKey)key;

            params = getPrivateKeyParameters(k);
        }

        if (parameters.getAlgorithm().equals(ALGORITHM_OAEP))
        {
            OAEPParameters oaep = (OAEPParameters)parameters;

            engine = new OAEPEncoding(engine, Register.createDigest(oaep.digestAlgorithm), Register.createDigest(oaep.mgfDigestAlgorithm), oaep.encodingParams);
        }
        else if (parameters.getAlgorithm().equals(ALGORITHM_PKCS1v1_5))
        {
            engine = new PKCS1Encoding(engine);
        }

        if (random != null)
        {
            params = new ParametersWithRandom(params, random);
        }

        engine.init(forEncryption, params);

        return engine;
    }

    private static RsaKeyParameters getPrivateKeyParameters(final AsymmetricRSAPrivateKey k)
    {
        return AccessController.doPrivileged(new PrivilegedAction<RsaKeyParameters>()
        {
            public RsaKeyParameters run()
            {
                if (k.getPublicExponent().equals(BigInteger.ZERO))
                {
                    return new RsaKeyParameters(true, k.getModulus(), k.getPrivateExponent());
                }
                else
                {
                    return new RsaPrivateCrtKeyParameters(k.getModulus(), k.getPublicExponent(), k.getPrivateExponent(), k.getP(), k.getQ(), k.getDP(), k.getDQ(), k.getQInv());
                }
            }
        });
    }

    private static class RecoveredMessageImpl
        implements RecoveredMessage
    {
        private final boolean isFullMessage;
        private final byte[] content;

        public RecoveredMessageImpl(boolean isFullMessage, byte[] content)
        {
            this.isFullMessage = isFullMessage;
            this.content = content;
        }

        public byte[] getContent()
        {
            return Arrays.clone(content);
        }

        public boolean isFullMessage()
        {
            return isFullMessage;
        }
    }

    private static class NullSigner
        implements Signer
    {
        AsymmetricBlockCipher engine = new PKCS1Encoding((AsymmetricBlockCipher)FipsRegister.getProvider(FipsRSA.ALGORITHM).createEngine());
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        public void init(boolean forSigning, CipherParameters param)
        {
            engine.init(forSigning, param);
        }

        public void update(byte b)
        {
            bOut.write(b);
        }

        public void update(byte[] in, int off, int len)
        {
            bOut.write(in, off, len);
        }

        public byte[] generateSignature()
            throws CryptoException, DataLengthException
        {
            byte[] data = bOut.toByteArray();

            bOut.reset();

            return engine.processBlock(data, 0, data.length);
        }

        public boolean verifySignature(byte[] signature)
            throws InvalidSignatureException
        {
            byte[] input = bOut.toByteArray();

            bOut.reset();

            try
            {
                byte[] sig = engine.processBlock(signature, 0, signature.length);

                return BaseRsaDigestSigner.checkPKCS1Sig(input, sig);
            }
            catch (org.bouncycastle.crypto.internal.InvalidCipherTextException e)
            {
                throw new InvalidSignatureException("Unable to process signature: " + e.getMessage(), e);
            }
        }

        public void reset()
        {
            bOut = new ByteArrayOutputStream();
        }
    }
}
