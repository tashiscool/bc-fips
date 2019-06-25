package org.bouncycastle.crypto.internal.signers;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.crypto.InvalidSignatureException;
import org.bouncycastle.crypto.internal.AsymmetricBlockCipher;
import org.bouncycastle.crypto.internal.CipherParameters;
import org.bouncycastle.crypto.internal.CryptoException;
import org.bouncycastle.crypto.internal.DataLengthException;
import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.Signer;
import org.bouncycastle.crypto.internal.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.internal.params.ParametersWithRandom;
import org.bouncycastle.util.Arrays;

public class BaseRsaDigestSigner
    implements Signer
{
    private final AsymmetricBlockCipher rsaEngine;
    private final AlgorithmIdentifier algId;
    private final Digest digest;
    private boolean forSigning;

    public BaseRsaDigestSigner(
        AsymmetricBlockCipher rsaEngine,
        Digest digest,
        ASN1ObjectIdentifier digestOid)
    {
        this.rsaEngine = rsaEngine;
        this.digest = digest;
        this.algId = new AlgorithmIdentifier(digestOid, DERNull.INSTANCE);
    }

    /**
     * initialise the signer for signing or verification.
     *
     * @param forSigning
     *            true if for signing, false otherwise
     * @param parameters
     *            necessary parameters.
     */
    public void init(
        boolean          forSigning,
        CipherParameters parameters)
    {
        this.forSigning = forSigning;
        AsymmetricKeyParameter k;

        if (parameters instanceof ParametersWithRandom)
        {
            k = (AsymmetricKeyParameter)((ParametersWithRandom)parameters).getParameters();
        }
        else
        {
            k = (AsymmetricKeyParameter)parameters;
        }

        if (forSigning && !k.isPrivate())
        {
            throw new IllegalArgumentException("signing requires private key");
        }

        if (!forSigning && k.isPrivate())
        {
            throw new IllegalArgumentException("verification requires public key");
        }

        reset();

        rsaEngine.init(forSigning, parameters);
    }

    /**
     * update the internal digest with the byte b
     */
    public void update(
        byte input)
    {
        digest.update(input);
    }

    /**
     * update the internal digest with the byte array in
     */
    public void update(
        byte[]  input,
        int     inOff,
        int     length)
    {
        digest.update(input, inOff, length);
    }

    /**
     * Generate a signature for the message we've been loaded with using the key
     * we were initialised with.
     */
    public byte[] generateSignature()
        throws CryptoException, DataLengthException
    {
        if (!forSigning)
        {
            throw new IllegalStateException("RsaDigestSigner not initialised for signature generation.");
        }

        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        try
        {
            byte[] data = derEncode(hash);
            return rsaEngine.processBlock(data, 0, data.length);
        }
        catch (IOException e)
        {
            throw new CryptoException("unable to encode signature: " + e.getMessage(), e);
        }
    }

    /**
     * return true if the internal state represents the signature described in
     * the passed in array.
     */
    public boolean verifySignature(
        byte[] signature)
        throws InvalidSignatureException
    {
        if (forSigning)
        {
            throw new IllegalStateException("RsaDigestSigner not initialised for verification");
        }

        byte[] hash = new byte[digest.getDigestSize()];

        digest.doFinal(hash, 0);

        byte[] sig;
        byte[] expected;

        try
        {
            sig = rsaEngine.processBlock(signature, 0, signature.length);
            expected = derEncode(hash);
        }
        catch (Exception e)
        {
            throw new InvalidSignatureException("Unable to process signature: " + e.getMessage(), e);
        }

        return checkPKCS1Sig(expected, sig);
    }

    public void reset()
    {
        digest.reset();
    }

    private byte[] derEncode(
        byte[] hash)
        throws IOException
    {
        DigestInfo dInfo = new DigestInfo(algId, hash);

        return dInfo.getEncoded(ASN1Encoding.DER);
    }


    public static boolean checkPKCS1Sig(byte[] expected, byte[] sig)
    {
        if (sig.length == expected.length)
        {
            return Arrays.constantTimeAreEqual(expected, sig);
        }
        if (sig.length == expected.length - 2)  // NULL left out
        {
            expected[1] -= 2;      // adjust lengths
            expected[3] -= 2;

            int sigOffset = 4 + expected[3];
            int expectedOffset = sigOffset + 2;
            int nonEqual = 0;

            for (int i = 0; i < expected.length - expectedOffset; i++)
            {
                nonEqual |= (sig[sigOffset + i] ^ expected[expectedOffset + i]);
            }

            for (int i = 0; i < sigOffset; i++)
            {
                nonEqual |= (sig[i] ^ expected[i]);  // check header less NULL
            }

            return nonEqual == 0;
        }

        Arrays.constantTimeAreEqual(expected, expected);  // maintain delay

        return false;
    }
}
