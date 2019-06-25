package org.bouncycastle.crypto.general;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AuthenticationParameters;
import org.bouncycastle.crypto.AuthenticationParametersWithIV;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.ParametersWithIV;
import org.bouncycastle.crypto.fips.FipsDRBG;
import org.bouncycastle.crypto.internal.BlockCipher;
import org.bouncycastle.crypto.internal.BufferedBlockCipher;
import org.bouncycastle.crypto.internal.CipherParameters;
import org.bouncycastle.crypto.internal.EngineProvider;
import org.bouncycastle.crypto.internal.Mac;
import org.bouncycastle.crypto.internal.ValidatedSymmetricKey;
import org.bouncycastle.crypto.internal.Wrapper;
import org.bouncycastle.crypto.internal.macs.AEADCipherMac;
import org.bouncycastle.crypto.internal.macs.CBCBlockCipherMac;
import org.bouncycastle.crypto.internal.macs.CFBBlockCipherMac;
import org.bouncycastle.crypto.internal.macs.CMac;
import org.bouncycastle.crypto.internal.macs.GMac;
import org.bouncycastle.crypto.internal.modes.AEADBlockCipher;
import org.bouncycastle.crypto.internal.modes.CBCBlockCipher;
import org.bouncycastle.crypto.internal.modes.CCMBlockCipher;
import org.bouncycastle.crypto.internal.modes.CFBBlockCipher;
import org.bouncycastle.crypto.internal.modes.EAXBlockCipher;
import org.bouncycastle.crypto.internal.modes.GCFBBlockCipher;
import org.bouncycastle.crypto.internal.modes.GCMBlockCipher;
import org.bouncycastle.crypto.internal.modes.GOFBBlockCipher;
import org.bouncycastle.crypto.internal.modes.NISTCTSBlockCipher;
import org.bouncycastle.crypto.internal.modes.OCBBlockCipher;
import org.bouncycastle.crypto.internal.modes.OFBBlockCipher;
import org.bouncycastle.crypto.internal.modes.OpenPGPCFBBlockCipher;
import org.bouncycastle.crypto.internal.modes.SICBlockCipher;
import org.bouncycastle.crypto.internal.paddings.ISO10126d2Padding;
import org.bouncycastle.crypto.internal.paddings.ISO7816d4Padding;
import org.bouncycastle.crypto.internal.paddings.PKCS7Padding;
import org.bouncycastle.crypto.internal.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.internal.paddings.TBCPadding;
import org.bouncycastle.crypto.internal.paddings.X923Padding;
import org.bouncycastle.crypto.internal.params.KeyParameter;
import org.bouncycastle.crypto.internal.params.KeyParameterImpl;
import org.bouncycastle.crypto.internal.params.ParametersWithRandom;
import org.bouncycastle.crypto.internal.wrappers.SP80038FWrapEngine;
import org.bouncycastle.crypto.internal.wrappers.SP80038FWrapWithPaddingEngine;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Strings;

class CipherUtils
{
    private static SecureRandom defaultRandomPadder;

    static BufferedBlockCipher createBlockCipher(EngineProvider<BlockCipher> provider, Parameters parameter)
    {
        GeneralAlgorithm algorithm = (GeneralAlgorithm)parameter.getAlgorithm();
        BlockCipher cipher = provider.createEngine();
        Padding padding = (Padding)algorithm.additionalVariation();

        switch (((Mode)algorithm.basicVariation()))
        {
        case ECB:
            break;
        case CBC:
            if (padding != Padding.CS1 && padding != Padding.CS2 && padding != Padding.CS3)
            {
                cipher = new CBCBlockCipher(cipher);
            }
            break;
        case CFB8:
            cipher = new CFBBlockCipher(cipher, 8);
            break;
        case CFB64:
            cipher = new CFBBlockCipher(cipher, 64);
            break;
        case CFB128:
            cipher = new CFBBlockCipher(cipher, 128);
            break;
        case CFB256:
            cipher = new CFBBlockCipher(cipher, 256);
            break;
        case OFB64:
            cipher = new OFBBlockCipher(cipher, 64);
            break;
        case OFB128:
            cipher = new OFBBlockCipher(cipher, 128);
            break;
        case OFB256:
            cipher = new OFBBlockCipher(cipher, 256);
            break;
        case CTR:
            cipher = new SICBlockCipher(cipher);
            break;
        case OpenPGPCFB:
            cipher = new OpenPGPCFBBlockCipher(cipher);
            break;
        case GCFB:
            cipher = new GCFBBlockCipher(cipher);
            break;
        case GOFB:
            cipher = new GOFBBlockCipher(cipher);
            break;
        default:
            throw new IllegalArgumentException("Unknown algorithm passed to createBlockCipher: " + algorithm.getName());
        }

        if (padding != null)
        {
            switch (padding)
            {
            case PKCS7:
                return new PaddedBufferedBlockCipher(cipher, new PKCS7Padding());
            case ISO7816_4:
                return new PaddedBufferedBlockCipher(cipher, new ISO7816d4Padding());
            case ISO10126_2:
                return new PaddedBufferedBlockCipher(cipher, new ISO10126d2Padding());
            case TBC:
                return new PaddedBufferedBlockCipher(cipher, new TBCPadding());
            case X923:
                return new PaddedBufferedBlockCipher(cipher, new X923Padding());
            case CS1:
                return new NISTCTSBlockCipher(NISTCTSBlockCipher.CS1, cipher);
            case CS2:
                return new NISTCTSBlockCipher(NISTCTSBlockCipher.CS2, cipher);
            case CS3:
                return new NISTCTSBlockCipher(NISTCTSBlockCipher.CS3, cipher);
            default:
                throw new IllegalArgumentException("Unknown padding passed to createBlockCipher: " + parameter.getAlgorithm());
            }
        }

        return new BufferedBlockCipher(cipher);
    }

    static BufferedBlockCipher createStandardCipher(boolean forEncryption, ValidatedSymmetricKey key, EngineProvider<BlockCipher> engineProvider, ParametersWithIV parameters, SecureRandom random)
    {
        KeyParameter keyParameter = new KeyParameterImpl(key.getKeyBytes());

        return createStandardCipher(forEncryption, keyParameter, engineProvider, parameters, random);
    }

    static BufferedBlockCipher createStandardCipher(boolean forEncryption, KeyParameter keyParameter, EngineProvider<BlockCipher> engineProvider, ParametersWithIV parameters, SecureRandom random)
    {
        BufferedBlockCipher cipher = CipherUtils.createBlockCipher(engineProvider, parameters);

        CipherParameters cipherParameters = keyParameter;

        if (parameters.getIV() != null)
        {
            cipherParameters = new org.bouncycastle.crypto.internal.params.ParametersWithIV(cipherParameters, parameters.getIV());
        }

        if (((GeneralAlgorithm)parameters.getAlgorithm()).additionalVariation() instanceof Padding)
        {
            Padding padding = (Padding)((GeneralAlgorithm)parameters.getAlgorithm()).additionalVariation();

            if (padding.getBasePadding().requiresRandom() && forEncryption)
            {
                if (random != null)
                {
                    cipherParameters = new ParametersWithRandom(cipherParameters, random);
                }
                else
                {
                    try
                    {
                        cipherParameters = new ParametersWithRandom(cipherParameters, CryptoServicesRegistrar.getSecureRandom());
                    }
                    catch (IllegalStateException e)
                    {
                        cipherParameters = new ParametersWithRandom(cipherParameters, getDefaultRandomPadder());
                    }
                }
            }
        }

        cipher.init(forEncryption, cipherParameters);

        return cipher;
    }

    static AEADBlockCipher createAEADCipher(GeneralAlgorithm algorithm, EngineProvider<BlockCipher> provider)
    {
        AEADBlockCipher cipher;

        switch (((Mode)algorithm.basicVariation()))
        {
        case CCM:
            cipher = new CCMBlockCipher(provider.createEngine());
            break;
        case EAX:
            cipher = new EAXBlockCipher(provider.createEngine());
            break;
        case GCM:
            cipher = new GCMBlockCipher(provider.createEngine());
            break;
        case OCB:
            cipher = new OCBBlockCipher(provider.createEngine(), provider.createEngine());
            break;
        default:
            throw new IllegalArgumentException("Unknown algorithm passed to createAEADCipher: " + algorithm.getName());
        }

        return cipher;
    }

    static AEADBlockCipher createStandardAEADCipher(boolean forEncryption, ValidatedSymmetricKey key, EngineProvider<BlockCipher> engineProvider,
                                                    final AuthenticationParametersWithIV parameters)
    {
        KeyParameter keyParameter = new KeyParameterImpl(key.getKeyBytes());

        return createStandardAEADCipher(forEncryption, keyParameter, engineProvider, parameters);
    }

    static AEADBlockCipher createStandardAEADCipher(boolean forEncryption, KeyParameter keyParameter, EngineProvider<BlockCipher> engineProvider,
                                                    final AuthenticationParametersWithIV parameters)
    {
        final AEADBlockCipher cipher = CipherUtils.createAEADCipher((GeneralAlgorithm)parameters.getAlgorithm(), engineProvider);

        if (parameters.getIV() != null)
        {
            cipher.init(forEncryption, new org.bouncycastle.crypto.internal.params.AEADParameters(keyParameter, parameters.getMACSizeInBits(), parameters.getIV()));
        }
        else
        {
            cipher.init(forEncryption, keyParameter);
        }

        return cipher;
    }

    static Mac createStandardMac(ValidatedSymmetricKey key, EngineProvider<BlockCipher> provider, GeneralAuthParameters parameters)
    {
        KeyParameter keyParameter = new KeyParameterImpl(key.getKeyBytes());

        return createStandardMac(keyParameter, provider, parameters);
    }

    static Mac createStandardMac(KeyParameter keyParameter, EngineProvider<BlockCipher> provider, GeneralAuthParameters parameters)
    {
        final Mac mac = getMac(parameters, provider);

        if (parameters.getIV() != null)
        {
            mac.init(new org.bouncycastle.crypto.internal.params.ParametersWithIV(keyParameter, parameters.getIV()));
        }
        else
        {
            mac.init(keyParameter);
        }

        return mac;
    }

    private static Mac getMac(AuthenticationParameters parameters, EngineProvider<BlockCipher> provider)
    {
        Mac mac;
        Padding pad = (Padding)((GeneralAlgorithm)parameters.getAlgorithm()).additionalVariation();

        switch (((Mode)((GeneralAlgorithm)parameters.getAlgorithm()).basicVariation()))
        {
        case CBCMAC:
            if (pad != null)
            {
                if (pad == Padding.ISO7816_4)
                {
                    mac = new CBCBlockCipherMac(provider.createEngine(), parameters.getMACSizeInBits(), new ISO7816d4Padding());
                }
                else
                {
                    throw new IllegalArgumentException("Unknown padding passed to MAC operator factory: " + parameters.getAlgorithm().getName());
                }
            }
            else
            {
                mac = new CBCBlockCipherMac(provider.createEngine(), parameters.getMACSizeInBits());
            }
            break;
        case CCM:
            mac = new AEADCipherMac(new CCMBlockCipher(provider.createEngine()), parameters.getMACSizeInBits());
            break;
        case CMAC:
            mac = new CMac(provider.createEngine(), parameters.getMACSizeInBits());
            break;
        case GMAC:
            mac = new GMac(new GCMBlockCipher(provider.createEngine()), parameters.getMACSizeInBits());
            break;
        case CFB8MAC:
            mac = new CFBBlockCipherMac(provider.createEngine());
            break;
        case GOSTMAC:
            mac = new GOST28147Mac();
            break;
        case ISO9797alg3:
            if (pad != null)
            {
                if (pad == Padding.ISO7816_4)
                {
                    mac = new ISO9797Alg3Mac(provider.createEngine(), parameters.getMACSizeInBits(), new ISO7816d4Padding());
                }
                else
                {
                    throw new IllegalArgumentException("Unknown padding passed to MAC operator factory: " + parameters.getAlgorithm().getName());
                }
            }
            else
            {
                mac = new ISO9797Alg3Mac(provider.createEngine());
            }
            break;
        default:
            throw new IllegalArgumentException("Unknown algorithm passed to MAC operator factory: " + parameters.getAlgorithm().getName());
        }
        return mac;
    }

    static Wrapper createStandardWrapper(boolean forWrapping, ValidatedSymmetricKey key, EngineProvider<BlockCipher> provider, ParametersWithIV parameters, SecureRandom random)
    {
        return createStandardWrapper(forWrapping, new KeyParameterImpl(key.getKeyBytes()), provider, parameters, false, random);
    }

    static Wrapper createStandardWrapper(boolean forWrapping, ValidatedSymmetricKey key, EngineProvider<BlockCipher> provider, ParametersWithIV parameters, boolean useInverse, SecureRandom random)
    {
        return createStandardWrapper(forWrapping, new KeyParameterImpl(key.getKeyBytes()), provider, parameters, useInverse, random);
    }

    static Wrapper createStandardWrapper(boolean forWrapping, KeyParameter keyParameter, EngineProvider<BlockCipher> provider, ParametersWithIV parameters, boolean useInverse, SecureRandom random)
    {
        GeneralAlgorithm algorithm = (GeneralAlgorithm)parameters.getAlgorithm();
        boolean randomRequired = false;
        Wrapper wrapper;

        switch (((Mode)algorithm.basicVariation()))
        {
        case WRAP:
            wrapper = new SP80038FWrapEngine(provider.createEngine(), useInverse);
            break;
        case WRAPPAD:
            wrapper = new SP80038FWrapWithPaddingEngine(provider.createEngine(), useInverse);
            break;
        case RFC3211_WRAP:
            randomRequired = true;
            wrapper = new RFC3211WrapEngine(provider.createEngine());
            break;
        case RFC3217_WRAP:
            randomRequired = true;
            if (algorithm.equals(TripleDES.RFC3217_WRAP.getAlgorithm()))
            {
                wrapper = new DesEdeWrapEngine();
            }
            else if (algorithm.equals(RC2.RFC3217_WRAP.getAlgorithm()))
            {
                wrapper = new RC2WrapEngine();
            }
            else
            {
                throw new IllegalArgumentException("Unknown RFC3217 algorithm passed to Key Wrap operator factory: " + algorithm.getName());
            }
            break;
        default:
            throw new IllegalArgumentException("Unknown algorithm passed to Key Wrap operator factory: " + algorithm.getName());
        }

        CipherParameters params = keyParameter;

        if (parameters.getIV() != null)
        {
            params = new org.bouncycastle.crypto.internal.params.ParametersWithIV(keyParameter, parameters.getIV());
        }

        if (forWrapping && randomRequired)
        {
            if (random != null)
            {
                params = new ParametersWithRandom(params, random);
            }
            else
            {
                throw new IllegalArgumentException("No SecureRandom provided when one required");
            }
        }

        wrapper.init(forWrapping, params);

        return wrapper;
    }


    static synchronized SecureRandom getDefaultRandomPadder()
    {
        if (defaultRandomPadder == null)
        {
            defaultRandomPadder = FipsDRBG.SHA512.fromDefaultEntropy().
                setPersonalizationString(Strings.toByteArray("Bouncy Castle General Default Padder"))
                .build(Pack.longToBigEndian(System.currentTimeMillis()), false);
        }

        return defaultRandomPadder;
    }
}
