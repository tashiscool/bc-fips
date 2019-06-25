package org.bouncycastle.jcajce.provider;

import java.io.ByteArrayOutputStream;
import java.security.AccessController;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.interfaces.DHKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricKey;
import org.bouncycastle.crypto.AsymmetricOperatorFactory;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.InvalidWrappingException;
import org.bouncycastle.crypto.KeyUnwrapper;
import org.bouncycastle.crypto.KeyWrapOperatorFactory;
import org.bouncycastle.crypto.KeyWrapper;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.PlainInputProcessingException;
import org.bouncycastle.crypto.SingleBlockCipher;
import org.bouncycastle.crypto.SingleBlockDecryptor;
import org.bouncycastle.crypto.SingleBlockEncryptor;
import org.bouncycastle.crypto.fips.FipsAlgorithm;
import org.bouncycastle.crypto.fips.FipsKeyWrapOperatorFactory;
import org.bouncycastle.util.Strings;

class BaseSingleBlockCipher
    extends CipherSpi
{
    private static final Class TlsRsaPremasterSecretParameterSpec = AccessController.doPrivileged(new PrivilegedAction<Class>()
    {
        public Class run()
        {
            return lookup("sun.security.internal.spec.TlsRsaPremasterSecretParameterSpec");
        }
    });

    static class Builder
    {
        private final BouncyCastleFipsProvider fipsProvider;
        private final Map<Algorithm, Parameters> baseParametersMap;
        private final Algorithm[] algorithms;

        private boolean publicKeyOnly;
        private boolean privateKeyOnly;
        private boolean wrapModeOnly;
        private AsymmetricOperatorFactory generalFactory;
        private PublicKeyConverter publicKeyConverter;
        private PrivateKeyConverter privateKeyConverter;
        private ParametersCreatorProvider parametersCreatorProvider;
        private FipsKeyWrapOperatorFactory fipsKeyWrapOperatorFactory;
        private KeyWrapOperatorFactory generalKeyWrapOperatorFactory;
        private Class[] availableSpecs = new Class[0];

        Builder(BouncyCastleFipsProvider fipsProvider, Algorithm... algorithms)
        {
            this.fipsProvider = fipsProvider;
            this.baseParametersMap = new HashMap<Algorithm, Parameters>();
            this.algorithms = algorithms;
        }

        Builder(BouncyCastleFipsProvider fipsProvider, Parameters... parameters)
        {
            this.fipsProvider = fipsProvider;
            this.baseParametersMap = new HashMap<Algorithm, Parameters>(parameters.length);
            this.algorithms = new Algorithm[parameters.length];
            for (int i = 0; i != parameters.length; i++)
            {
                this.baseParametersMap.put(parameters[i].getAlgorithm(), parameters[i]);
                this.algorithms[i] = parameters[i].getAlgorithm();
            }
        }

        Builder setPublicKeyOnly(boolean publicKeyOnly)
        {
            this.publicKeyOnly = publicKeyOnly;

            return this;
        }

        Builder setPrivateKeyOnly(boolean privateKeyOnly)
        {
            this.privateKeyOnly = privateKeyOnly;

            return this;
        }

        Builder setWrapModeOnly(boolean wrapModeOnly)
        {
            this.wrapModeOnly = wrapModeOnly;

            return this;
        }

        Builder withFipsOperators(AsymmetricOperatorFactory generalFactory, FipsKeyWrapOperatorFactory fipsKeyWrapOperatorFactory)
        {
            this.generalFactory = generalFactory;
            this.fipsKeyWrapOperatorFactory = fipsKeyWrapOperatorFactory;

            return this;
        }

        Builder withGeneralOperators(AsymmetricOperatorFactory generalFactory, KeyWrapOperatorFactory generalKeyWrapOperatorFactory)
        {
            this.generalFactory = generalFactory;
            this.generalKeyWrapOperatorFactory = generalKeyWrapOperatorFactory;

            return this;
        }

        Builder withPublicKeyConverter(PublicKeyConverter publicKeyConverter)
        {
            this.publicKeyConverter = publicKeyConverter;

            return this;
        }

        Builder withPrivateKeyConverter(PrivateKeyConverter privateKeyConverter)
        {
            this.privateKeyConverter = privateKeyConverter;

            return this;
        }

        Builder withParameters(Class[] availableSpecs)
        {
            this.availableSpecs = availableSpecs;

            return this;
        }

        Builder withParametersCreatorProvider(ParametersCreatorProvider parametersCreatorProvider)
        {
            this.parametersCreatorProvider = parametersCreatorProvider;

            return this;
        }

        BaseSingleBlockCipher build()
        {
            return new BaseSingleBlockCipher(fipsProvider, publicKeyOnly, privateKeyOnly, wrapModeOnly, availableSpecs, generalFactory, fipsKeyWrapOperatorFactory, generalKeyWrapOperatorFactory, publicKeyConverter, privateKeyConverter, parametersCreatorProvider, baseParametersMap, algorithms);
        }
    }

    private final BouncyCastleFipsProvider fipsProvider;
    private final boolean wrapModeOnly;
    private final FipsKeyWrapOperatorFactory fipsKeyWrapOperatorFactory;
    private final KeyWrapOperatorFactory generalKeyWrapOperatorFactory;
    private final AsymmetricOperatorFactory generalFactory;
    private final Map<Algorithm, Parameters> baseParametersMap;
    private final Algorithm[] algorithms;
    private final PublicKeyConverter publicKeyConverter;
    private final PrivateKeyConverter privateKeyConverter;
    private final ParametersCreatorProvider parametersCreatorProvider;
    private final Class[] availableSpecs;

    private Set<Algorithm> activeAlgorithmSet = new HashSet<Algorithm>();

    private SingleBlockCipher cipher;

    private AlgorithmParameterSpec paramSpec;
    private AlgorithmParameters engineParams;
    private boolean                 publicKeyOnly = false;
    private boolean                 privateKeyOnly = false;
    private ByteArrayOutputStream bOut = new ByteArrayOutputStream();

    private Parameters algParameters;
    private KeyWrapper keyWrapper;
    private KeyUnwrapper keyUnwrapper;

    public BaseSingleBlockCipher(
        BouncyCastleFipsProvider fipsProvider,
        boolean publicKeyOnly,
        boolean privateKeyOnly,
        boolean wrapModeOnly,
        Class[] availableSpecs,
        AsymmetricOperatorFactory generalFactory,
        FipsKeyWrapOperatorFactory fipsKeyWrapOperatorFactory,
        KeyWrapOperatorFactory generalKeyWrapOperatorFactory,
        PublicKeyConverter publicKeyConverter, PrivateKeyConverter privateKeyConverter,
        ParametersCreatorProvider parametersCreatorProvider,
        Map<Algorithm, Parameters> baseParametersMap, Algorithm... algorithms)
    {
        this.fipsProvider = fipsProvider;
        this.publicKeyOnly = publicKeyOnly;
        this.privateKeyOnly = privateKeyOnly;
        this.wrapModeOnly = wrapModeOnly;
        this.availableSpecs = availableSpecs;
        this.generalFactory = generalFactory;
        this.fipsKeyWrapOperatorFactory = fipsKeyWrapOperatorFactory;
        this.generalKeyWrapOperatorFactory = generalKeyWrapOperatorFactory;
        this.publicKeyConverter = publicKeyConverter;
        this.privateKeyConverter = privateKeyConverter;
        this.parametersCreatorProvider = parametersCreatorProvider;
        this.baseParametersMap = baseParametersMap;
        this.algorithms = algorithms;
        activeAlgorithmSet.addAll(Arrays.asList((Algorithm[])algorithms));
    }
    
    protected int engineGetBlockSize() 
    {
        return 0;            // these are not block ciphers!!!!
    }

    protected int engineGetKeySize(
        Key key)
    {
        if (key instanceof RSAKey)
        {
            RSAKey k = (RSAKey)key;

            return k.getModulus().bitLength();
        }
        else if (key instanceof DHKey)
        {
            DHKey k = (DHKey)key;

            return k.getParams().getP().bitLength();
        }

        throw new IllegalArgumentException("not an valid key!");
    }

    protected int engineGetOutputSize(
        int     inputLen) 
    {
        try
        {
            return cipher.getOutputSize();
        }
        catch (NullPointerException e)
        {
            throw new IllegalStateException("Single block Cipher not initialised");
        }
    }

    @Override
    protected byte[] engineGetIV()
    {
        return null;
    }

    protected AlgorithmParameters engineGetParameters()
    {
        if (engineParams == null)
        {
            if (algParameters != null)
            {
                try
                {
                    engineParams = AlgorithmParameters.getInstance("OAEP", fipsProvider);
                    engineParams.init(paramSpec);
                }
                catch (Exception e)
                {
                    throw new IllegalStateException(e.toString(), e);
                }
            }
        }

        return engineParams;
    }

    protected void engineSetMode(
        String mode)
        throws NoSuchAlgorithmException
    {
        String md = Strings.toUpperCase(mode);

        if (md.equals("NONE") || md.equals("ECB"))
        {
            return;
        }

        throw new NoSuchAlgorithmException("can't support mode " + mode);
    }

    private void initFromSpec(
        Set<Algorithm> currentAlgs, OAEPParameterSpec pSpec)
        throws NoSuchPaddingException
    {
        for (Algorithm alg : currentAlgs)
        {
            if (alg.getName().endsWith("OAEP"))
            {
                 activeAlgorithmSet.add(alg);
            }
        }

        MGF1ParameterSpec mgfParams = (MGF1ParameterSpec)pSpec.getMGFParameters();
        Algorithm digest = Utils.digestNameToAlgMap.get(mgfParams.getDigestAlgorithm());

        if (digest == null)
        {
            throw new NoSuchPaddingException("no match on OAEP constructor for digest algorithm: "+ mgfParams.getDigestAlgorithm());
        }

        paramSpec = pSpec;
    }

    protected void engineSetPadding(
        String  padding)
    throws NoSuchPaddingException
    {
        String  paddingName = Strings.toUpperCase(padding);

        Set<Algorithm> currentAlgs = new HashSet<Algorithm>(activeAlgorithmSet);

        activeAlgorithmSet.clear();

        if (paddingName.equals("NOPADDING"))
        {
            for (Algorithm alg : currentAlgs)
            {
                // one or none
                if (alg.getName().indexOf('/') < 0)
                {
                     activeAlgorithmSet.add(alg);
                }
            }
        }
        else
        {
            if (paddingName.equals("PKCS1PADDING"))
            {
                for (Algorithm alg : currentAlgs)
                {
                    if (alg.getName().endsWith("PKCS1V1.5"))
                    {
                         activeAlgorithmSet.add(alg);
                    }
                }
            }
            else if (paddingName.equals("OAEPPADDING"))
            {
                initFromSpec(currentAlgs, OAEPParameterSpec.DEFAULT);
            }
            else if (paddingName.equals("OAEPWITHSHA1ANDMGF1PADDING") || paddingName.equals("OAEPWITHSHA-1ANDMGF1PADDING"))
            {
                initFromSpec(currentAlgs, OAEPParameterSpec.DEFAULT);
            }
            else if (paddingName.equals("OAEPWITHSHA224ANDMGF1PADDING") || paddingName.equals("OAEPWITHSHA-224ANDMGF1PADDING"))
            {
                initFromSpec(currentAlgs, new OAEPParameterSpec("SHA-224", "MGF1", new MGF1ParameterSpec("SHA-224"), PSource.PSpecified.DEFAULT));
            }
            else if (paddingName.equals("OAEPWITHSHA256ANDMGF1PADDING") || paddingName.equals("OAEPWITHSHA-256ANDMGF1PADDING"))
            {
                initFromSpec(currentAlgs, new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
            }
            else if (paddingName.equals("OAEPWITHSHA384ANDMGF1PADDING") || paddingName.equals("OAEPWITHSHA-384ANDMGF1PADDING"))
            {
                initFromSpec(currentAlgs, new OAEPParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, PSource.PSpecified.DEFAULT));
            }
            else if (paddingName.equals("OAEPWITHSHA512ANDMGF1PADDING") || paddingName.equals("OAEPWITHSHA-512ANDMGF1PADDING"))
            {
                initFromSpec(currentAlgs, new OAEPParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, PSource.PSpecified.DEFAULT));
            }
            else
            {
                throw new NoSuchPaddingException("Padding " + padding + " unknown.");
            }
        }

        if (activeAlgorithmSet.isEmpty())
        {
            throw new NoSuchPaddingException(paddingName + " not found");
        }
    }

    protected void engineInit(
        int                     opmode,
        Key key,
        final AlgorithmParameterSpec params,
        SecureRandom random)
    throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        final Algorithm alg;
        if (activeAlgorithmSet.size() == 1)
        {
            alg = activeAlgorithmSet.iterator().next();
        }
        else
        {
            alg = algorithms[0];
        }

        AsymmetricOperatorFactory operatorFactory = generalFactory;
        final AsymmetricKey param;

        if (params == null || params instanceof OAEPParameterSpec
            || (TlsRsaPremasterSecretParameterSpec != null && TlsRsaPremasterSecretParameterSpec.isAssignableFrom(params.getClass())))
        {
            if (key instanceof RSAPublicKey || key instanceof DHPublicKey)
            {
                if (privateKeyOnly && opmode == Cipher.ENCRYPT_MODE)
                {
                    throw new InvalidKeyException(
                                "Mode 1 requires PrivateKey for encryption");
                }

                param = publicKeyConverter.convertKey(alg, (PublicKey)key);
            }
            else if (key instanceof RSAPrivateKey || key instanceof DHPrivateKey)
            {
                if (publicKeyOnly && opmode == Cipher.ENCRYPT_MODE)
                {
                    throw new InvalidKeyException(
                                "Mode 2 requires PublicKey for encryption");
                }

                param = privateKeyConverter.convertKey(alg, (PrivateKey)key);
            }
            else
            {
                if (key != null)
                {
                    throw new InvalidKeyException("Unknown key type passed to single block cipher: " + key.getClass().getName());
                }
                else
                {
                    throw new InvalidKeyException("Null key type passed to single block cipher");
                }
            }

            if (params instanceof OAEPParameterSpec)
            {
                OAEPParameterSpec spec = (OAEPParameterSpec)params;

                paramSpec = params;

                if (!spec.getMGFAlgorithm().equalsIgnoreCase("MGF1") && !spec.getMGFAlgorithm().equals(PKCSObjectIdentifiers.id_mgf1.getId()))
                {
                    throw new InvalidAlgorithmParameterException("Unknown mask generation function specified");
                }

                if (!(spec.getMGFParameters() instanceof MGF1ParameterSpec))
                {
                    throw new InvalidAlgorithmParameterException("Unkown MGF parameters");
                }
    
                Algorithm digest = Utils.digestNameToAlgMap.get(spec.getDigestAlgorithm());

                if (digest == null)
                {
                    throw new InvalidAlgorithmParameterException("No match on digest algorithm: "+ spec.getDigestAlgorithm());
                }

                MGF1ParameterSpec mgfParams = (MGF1ParameterSpec)spec.getMGFParameters();
                Algorithm mgfDigest = Utils.digestNameToAlgMap.get(mgfParams.getDigestAlgorithm());

                if (mgfDigest == null)
                {
                    throw new InvalidAlgorithmParameterException("no match on MGF digest algorithm: "+ mgfParams.getDigestAlgorithm());
                }
            }
            else
            {
                if (params != null)
                {
                    AccessController.doPrivileged(new PrivilegedAction<Object>()
                    {
                        public Object run()
                        {
                            if (TlsRsaPremasterSecretParameterSpec != null && TlsRsaPremasterSecretParameterSpec.isAssignableFrom(params.getClass()))
                            {
                                // in this case it just gets passed in, as to why, who knows...
                            }
                            return null;
                        }
                    });
                }
            }
        }
        else
        {
            throw new InvalidAlgorithmParameterException("Unknown parameter type: " + params.getClass().getName());
        }

        if (random == null)
        {
            random = fipsProvider.getDefaultSecureRandom();
        }

        algParameters = parametersCreatorProvider.get(new Parameters()
        {
            public Algorithm getAlgorithm()
            {
                return alg;
            }
        }).createParameters(true, paramSpec, random);

        bOut.reset();

        switch (opmode)
        {
        case Cipher.WRAP_MODE:
            if (alg instanceof FipsAlgorithm)
            {
                keyWrapper = fipsKeyWrapOperatorFactory.createKeyWrapper(param, algParameters);
            }
            else
            {
                try
                {
                    keyWrapper = generalKeyWrapOperatorFactory.createKeyWrapper(param, algParameters);
                }
                catch (ClassCastException e)
                {
                    throw new InvalidParameterException("Cipher does not support WRAP_MODE");
                }
            }
            keyWrapper = Utils.addRandomIfNeeded(keyWrapper, random);
            break;
        case Cipher.UNWRAP_MODE:
            if (alg instanceof FipsAlgorithm)
            {
                keyUnwrapper = fipsKeyWrapOperatorFactory.createKeyUnwrapper(param, algParameters);
            }
            else
            {
                try
                {
                    keyUnwrapper = generalKeyWrapOperatorFactory.createKeyUnwrapper(param, algParameters);
                }
                catch (ClassCastException e)
                {
                    throw new InvalidParameterException("Cipher does not support WRAP_MODE");
                }
            }
            keyUnwrapper = Utils.addRandomIfNeeded(keyUnwrapper, random);
            break;
        case Cipher.ENCRYPT_MODE:
            if (wrapModeOnly)
            {
                throw new InvalidParameterException("Cipher available for WRAP_MODE and UNWRAP_MODE only");
            }
            cipher = Utils.addRandomIfNeeded(operatorFactory.createBlockEncryptor(param, algParameters), random);
            break;
        case Cipher.DECRYPT_MODE:
            // a number of APIs, including the JSSE, use DECRYPT rather than unwrap as HSM will store the key internally,
            // we handle this by allowing decrypt for wrap mode only ciphers.
            if (wrapModeOnly)
            {
                if (alg instanceof FipsAlgorithm)
                {
                    keyUnwrapper = fipsKeyWrapOperatorFactory.createKeyUnwrapper(param, algParameters);
                }
                else
                {
                    try
                    {
                        keyUnwrapper = generalKeyWrapOperatorFactory.createKeyUnwrapper(param, algParameters);
                    }
                    catch (ClassCastException e)
                    {
                        throw new InvalidParameterException("Cipher does not support WRAP_MODE");
                    }
                }
                keyUnwrapper = Utils.addRandomIfNeeded(keyUnwrapper, random);
            }
            else
            {
                cipher = Utils.addRandomIfNeeded(operatorFactory.createBlockDecryptor(param, algParameters), random);
            }
            break;
        default:
            throw new InvalidParameterException("Unknown opmode " + opmode + " passed to single block cipher");
        }
    }

    protected void engineInit(
        int                 opmode,
        Key key,
        AlgorithmParameters params,
        SecureRandom random)
    throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        AlgorithmParameterSpec paramSpec = null;

        if (params != null)
        {
            try
            {
                paramSpec = params.getParameterSpec(OAEPParameterSpec.class);
            }
            catch (InvalidParameterSpecException e)
            {
                throw new InvalidAlgorithmParameterException("Cannot recognize parameters: " + e.toString(), e);
            }
        }

        engineParams = params;
        engineInit(opmode, key, paramSpec, random);
    }

    protected void engineInit(
        int                 opmode,
        Key key,
        SecureRandom random)
    throws InvalidKeyException
    {
        try
        {
            engineInit(opmode, key, (AlgorithmParameterSpec)null, random);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            // this shouldn't happen
            throw new InvalidKeyException("Eeeek! " + e.toString(), e);
        }
    }

    protected byte[] engineUpdate(
        byte[]  input,
        int     inputOffset,
        int     inputLen) 
    {
        bOut.write(input, inputOffset, inputLen);

        checkBufferSize();

        return null;
    }

    protected int engineUpdate(
        byte[]  input,
        int     inputOffset,
        int     inputLen,
        byte[]  output,
        int     outputOffset) 
    {
        bOut.write(input, inputOffset, inputLen);

        checkBufferSize();

        return 0;
    }

    protected byte[] engineDoFinal(
        byte[]  input,
        int     inputOffset,
        int     inputLen) 
        throws IllegalBlockSizeException, BadPaddingException
    {
        if (input != null)
        {
            bOut.write(input, inputOffset, inputLen);
        }

        checkBufferSize();

        return getOutput();
    }

    protected int engineDoFinal(
        byte[]  input,
        int     inputOffset,
        int     inputLen,
        byte[]  output,
        int     outputOffset)
        throws IllegalBlockSizeException, BadPaddingException, ShortBufferException
    {
        if (outputOffset + engineGetOutputSize(inputLen) > output.length)
        {
            throw new ShortBufferException("Not enough space for output");
        }

        if (input != null)
        {
            bOut.write(input, inputOffset, inputLen);
        }

        checkBufferSize();

        byte[]  out = getOutput();

        for (int i = 0; i != out.length; i++)
        {
            output[outputOffset + i] = out[i];
        }

        Arrays.fill(out, (byte)0);

        return out.length;
    }

    private void checkBufferSize()
    {
        if (cipher != null)
        {
            if (bOut.size() > cipher.getInputSize())
            {
                throw new ArrayIndexOutOfBoundsException("Too much data for block: maximum " + cipher.getInputSize() + " bytes");
            }
        }
    }

    private byte[] getOutput()
        throws BadPaddingException, IllegalBlockSizeException
    {
        byte[]  bytes = null;
        try
        {
            bytes = bOut.toByteArray();

            if (cipher instanceof SingleBlockEncryptor)
            {
                try
                {
                    return ((SingleBlockEncryptor)cipher).encryptBlock(bytes, 0, bytes.length);
                }
                catch (PlainInputProcessingException e)
                {
                    throw new IllegalBlockSizeException("unable to encrypt block: " + e.getMessage());
                }
            }
            else
            {
                if (cipher != null)
                {
                    try
                    {
                        return ((SingleBlockDecryptor)cipher).decryptBlock(bytes, 0, bytes.length);
                    }
                    catch (final InvalidCipherTextException e)
                    {
                        throw new BadBlockException("unable to decrypt block", e);
                    }
                    catch (final ArrayIndexOutOfBoundsException e)
                    {
                        throw new BadBlockException("unable to decrypt block", e);
                    }
                }
                else
                {
                    try
                    {
                        return keyUnwrapper.unwrap(bytes, 0, bytes.length);
                    }
                    catch (final InvalidWrappingException e)
                    {
                        throw new BadBlockException("unable to decrypt block", e);
                    }
                    catch (final ArrayIndexOutOfBoundsException e)
                    {
                        throw new BadBlockException("unable to decrypt block", e);
                    }
                }
            }
        }
        finally
        {
            if (bytes != null)
            {
                Arrays.fill(bytes, (byte)0);
                Utils.clearAndResetByteArrayOutputStream(bOut);
            }
        }
    }

    protected byte[] engineWrap(
        Key     key)
    throws IllegalBlockSizeException, InvalidKeyException
    {
        if (key == null)
        {
            throw new NullPointerException("Key parameter is null");
        }

        byte[] encoded = key.getEncoded();
        if (encoded == null)
        {
            throw new InvalidKeyException("Cannot wrap key, null encoding");
        }

        try
        {
            return keyWrapper.wrap(encoded, 0, encoded.length);
        }
        catch (PlainInputProcessingException e)
        {
            throw new IllegalBlockSizeException(e.getMessage());
        }
    }

    protected Key engineUnwrap(
        byte[]  wrappedKey,
        String  wrappedKeyAlgorithm,
        int     wrappedKeyType)
    throws InvalidKeyException, NoSuchAlgorithmException
    {
        byte[] encoded;
        try
        {
            encoded = keyUnwrapper.unwrap(wrappedKey, 0, wrappedKey.length);
        }
        catch (NullPointerException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new InvalidKeyException("unwrapping failed", e);
        }

        return BaseWrapCipher.rebuildKey(wrappedKeyAlgorithm, wrappedKeyType, encoded, fipsProvider);
    }

    private static Class lookup(String className)
    {
        try
        {
            Class def = BaseSingleBlockCipher.class.getClassLoader().loadClass(className);

            return def;
        }
        catch (Exception e)
        {
            return null;
        }
    }

    private static class BadBlockException
        extends BadPaddingException
    {
        private Throwable cause;

        public BadBlockException(String msg, Throwable cause)
        {
            super(msg);

            this.cause = cause;
        }

        public Throwable getCause()
        {
            return cause;
        }
    }
}
