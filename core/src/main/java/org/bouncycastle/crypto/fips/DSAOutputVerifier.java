package org.bouncycastle.crypto.fips;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.crypto.InvalidSignatureException;
import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.internal.DSA;
import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.io.DigestOutputStream;
import org.bouncycastle.util.Arrays;

class DSAOutputVerifier<T extends Parameters>
    extends FipsOutputVerifier<T>
{
    private final DSA dsa;
    private final Digest digest;
    private final T parameter;

    DSAOutputVerifier(DSA dsa, Digest digest, T parameter)
    {
        this.dsa = dsa;
        this.digest = digest;
        this.parameter = parameter;
    }

    @Override
    public T getParameters()
    {
        return parameter;
    }

    @Override
    public org.bouncycastle.crypto.UpdateOutputStream getVerifyingStream()
    {
        return new DigestOutputStream(digest);
    }

    @Override
    public boolean isVerified(byte[] signature)
        throws InvalidSignatureException
    {
        try
        {
            BigInteger[] rs = decode(signature);

            byte[] m = new byte[digest.getDigestSize()];

            digest.doFinal(m, 0);

            return dsa.verifySignature(m, rs[0], rs[1]);
        }
        catch (Exception e)
        {
            throw new InvalidSignatureException("Unable to process signature: " + e.getMessage(), e);
        }
    }

    public BigInteger[] decode(
        byte[] encoding)
        throws IOException
    {
        ASN1Sequence s = (ASN1Sequence)ASN1Primitive.fromByteArray(encoding);
        if (s.size() != 2)
        {
            throw new IOException("malformed signature");
        }
        if (!Arrays.areEqual(encoding, s.getEncoded(ASN1Encoding.DER)))
        {
            throw new IOException("malformed signature");
        }

        BigInteger[] sig = new BigInteger[2];

        sig[0] = ASN1Integer.getInstance(s.getObjectAt(0)).getValue();
        sig[1] = ASN1Integer.getInstance(s.getObjectAt(1)).getValue();

        return sig;
    }

}
