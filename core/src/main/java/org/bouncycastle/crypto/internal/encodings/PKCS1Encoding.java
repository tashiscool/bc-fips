package org.bouncycastle.crypto.internal.encodings;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.internal.AsymmetricBlockCipher;
import org.bouncycastle.crypto.internal.CipherParameters;
import org.bouncycastle.crypto.internal.InvalidCipherTextException;
import org.bouncycastle.crypto.internal.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.internal.params.ParametersWithRandom;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;

/**
 * this does your basic PKCS 1 v1.5 padding - whether or not you should be using this
 * depends on your application - see PKCS1 Version 2 for details.
 */
public class PKCS1Encoding
    implements AsymmetricBlockCipher
{
    /**
     * some providers fail to include the leading zero in PKCS1 encoded blocks. If you need to
     * work with one of these set the system property org.bouncycastle.pkcs1.strict to false.
     * <p>
     * The system property is checked during construction of the encoding object, it is set to 
     * true by default.
     * </p>
     */
    public static final String NOT_STRICT_LENGTH_ENABLED_PROPERTY = "org.bouncycastle.pkcs1.not_strict";
    
    private static final int HEADER_LENGTH = 10;

    private SecureRandom            random;
    private AsymmetricBlockCipher   engine;
    private boolean                 forEncryption;
    private boolean                 forPrivateKey;
    private boolean                 useStrictLength;
    private byte[]                  dudBlock;

    /**
     * Basic constructor.
     * @param cipher
     */
    public PKCS1Encoding(
        AsymmetricBlockCipher   cipher)
    {
        this.engine = cipher;
        this.useStrictLength = useStrict();
    }   

    //
    // for J2ME compatibility
    //
    private boolean useStrict()
    {
        return CryptoServicesRegistrar.isInApprovedOnlyMode() || !Properties.isOverrideSet(NOT_STRICT_LENGTH_ENABLED_PROPERTY);
    }

    public AsymmetricBlockCipher getUnderlyingCipher()
    {
        return engine;
    }

    public void init(
        boolean             forEncryption,
        CipherParameters    param)
    {
        AsymmetricKeyParameter  kParam;

        if (param instanceof ParametersWithRandom)
        {
            ParametersWithRandom    rParam = (ParametersWithRandom)param;

            this.random = rParam.getRandom();
            kParam = (AsymmetricKeyParameter)rParam.getParameters();
        }
        else
        {
            kParam = (AsymmetricKeyParameter)param;
            if (!kParam.isPrivate() && forEncryption)
            {
                throw new IllegalArgumentException("No SecureRandom specified.");
            }
        }

        engine.init(forEncryption, param);

        this.forPrivateKey = kParam.isPrivate();
        this.forEncryption = forEncryption;
        this.dudBlock = new byte[engine.getOutputBlockSize()];
    }

    public int getInputBlockSize()
    {
        int     baseBlockSize = engine.getInputBlockSize();

        if (forEncryption)
        {
            return baseBlockSize - HEADER_LENGTH;
        }
        else
        {
            return baseBlockSize;
        }
    }

    public int getOutputBlockSize()
    {
        int     baseBlockSize = engine.getOutputBlockSize();

        if (forEncryption)
        {
            return baseBlockSize;
        }
        else
        {
            return baseBlockSize - HEADER_LENGTH;
        }
    }

    public byte[] processBlock(
        byte[]  in,
        int     inOff,
        int     inLen)
        throws InvalidCipherTextException
    {
        if (forEncryption)
        {
            return encodeBlock(in, inOff, inLen);
        }
        else
        {
            return decodeBlock(in, inOff, inLen);
        }
    }

    private byte[] encodeBlock(
        byte[]  in,
        int     inOff,
        int     inLen)
        throws InvalidCipherTextException
    {
        if (inLen > getInputBlockSize())
        {
            throw new IllegalArgumentException("input data too large");
        }
        
        byte[]  block = new byte[engine.getInputBlockSize()];

        if (forPrivateKey)
        {
            block[0] = 0x01;                        // type code 1

            for (int i = 1; i != block.length - inLen - 1; i++)
            {
                block[i] = (byte)0xFF;
            }
        }
        else
        {
            random.nextBytes(block);                // random fill

            block[0] = 0x02;                        // type code 2

            //
            // a zero byte marks the end of the padding, so all
            // the pad bytes must be non-zero.
            //
            for (int i = 1; i != block.length - inLen - 1; i++)
            {
                while (block[i] == 0)
                {
                    block[i] = (byte)random.nextInt();
                }
            }
        }

        block[block.length - inLen - 1] = 0x00;       // mark the end of the padding
        System.arraycopy(in, inOff, block, block.length - inLen, inLen);

        return engine.processBlock(block, 0, block.length);
    }

    /**
     * @exception InvalidCipherTextException if the decrypted block is not in PKCS1 format.
     */
    private byte[] decodeBlock(
        byte[]  in,
        int     inOff,
        int     inLen)
        throws InvalidCipherTextException
    {
        byte[]  block = engine.processBlock(in, inOff, inLen);

        if (block.length < getOutputBlockSize())
        {
            block = dudBlock;
        }

        byte type = block[0];

        boolean badType;
        if (forPrivateKey)
        {
            badType = (type != 2);
        }
        else
        {
            badType = (type != 1);
        }

        boolean incorrectLength = (useStrictLength & (block.length != engine.getOutputBlockSize()));
        
        //
        // find and extract the message block.
        //
        int start = findStart(type, block);

        start++;           // data should start at the next byte

        if (badType | start < HEADER_LENGTH)
        {
            Arrays.fill(block, (byte)0);
            throw new InvalidCipherTextException("block incorrect");
        }

        // if we get this far, it's likely to be a genuine encoding error
        if (incorrectLength)
        {
            Arrays.fill(block, (byte)0);
            throw new InvalidCipherTextException("block incorrect size");
        }

        byte[]  result = new byte[block.length - start];

        System.arraycopy(block, start, result, 0, result.length);

        return result;
    }

    private int findStart(byte type, byte[] block)
        throws InvalidCipherTextException
    {
        int start = -1;
        boolean padErr = false;

        for (int i = 1; i != block.length; i++)
        {
            byte pad = block[i];

            if (pad == 0 & start < 0)
            {
                start = i;
            }
            padErr |= (type == 1 & start < 0 & pad != (byte)0xff);
        }

        if (padErr)
        {
            return -1;
        }

        return start;
    }
}
