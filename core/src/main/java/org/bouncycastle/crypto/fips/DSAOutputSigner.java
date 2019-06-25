package org.bouncycastle.crypto.fips;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.OperatorNotReadyException;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.PlainInputProcessingException;
import org.bouncycastle.crypto.UpdateOutputStream;
import org.bouncycastle.crypto.internal.DSA;
import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.io.DigestOutputStream;

class DSAOutputSigner<T extends Parameters>
    extends FipsOutputSignerUsingSecureRandom<T>
{
    private final DSA dsa;
    private final Digest digest;
    private final T parameter;
    private final Initializer initializer;
    private final boolean ready;

    DSAOutputSigner(DSA dsa, Digest digest, T parameter, Initializer initializer)
    {
        this(false, dsa, digest, parameter, initializer);
    }

    DSAOutputSigner(boolean ready, DSA dsa, Digest digest, T parameter, Initializer initializer)
    {
        this.ready = ready;
        this.dsa = dsa;
        this.digest = digest;
        this.parameter = parameter;
        this.initializer = initializer;
    }

    @Override
    public T getParameters()
    {
        return parameter;
    }

    @Override
    public UpdateOutputStream getSigningStream()
    {
        if (!ready)
        {
            throw new OperatorNotReadyException("Signer requires a SecureRandom to be attached before use");
        }

        return new DigestOutputStream(digest);
    }

    @Override
    public byte[] getSignature()
        throws PlainInputProcessingException
    {
        byte[] m = new byte[digest.getDigestSize()];

        digest.doFinal(m, 0);

        try
        {
            return encode(dsa.generateSignature(m));
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

    private byte[] encode(
        BigInteger[] rs)
        throws IOException
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(rs[0]));
        v.add(new ASN1Integer(rs[1]));

        return new DERSequence(v).getEncoded(ASN1Encoding.DER);
    }

    public DSAOutputSigner<T> withSecureRandom(SecureRandom random)
    {
        initializer.initialize(dsa, random);

        return new DSAOutputSigner<T>(true, dsa, digest, parameter, initializer);
    }

    static interface Initializer
    {
        void initialize(DSA signer, SecureRandom random);
    }
}
