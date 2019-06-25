package org.bouncycastle.crypto.fips;

import java.math.BigInteger;

import org.bouncycastle.crypto.IllegalKeyException;
import org.bouncycastle.crypto.internal.BasicAgreement;
import org.bouncycastle.crypto.internal.CipherParameters;
import org.bouncycastle.crypto.internal.params.DhParameters;
import org.bouncycastle.crypto.internal.params.DhPrivateKeyParameters;
import org.bouncycastle.crypto.internal.params.DhPublicKeyParameters;

/**
 * a Diffie-Hellman key agreement class.
 * <p>
 * note: This is only the basic algorithm, it doesn't take advantage of
 * long term public keys if they are available. See the DHAgreement class
 * for a "better" implementation.
 */
class DhBasicAgreement
    implements BasicAgreement
{
    private DhPrivateKeyParameters  key;
    private DhParameters            dhParams;

    public void init(
        CipherParameters    param)
    {
        DhPrivateKeyParameters  kParam = (DhPrivateKeyParameters)param;

        this.key = kParam;
        this.dhParams = key.getParameters();
    }

    public int getFieldSize()
    {
        return (key.getParameters().getP().bitLength() + 7) / 8;
    }

    /**
     * given a short term public key from a given party calculate the next
     * message in the agreement sequence. 
     */
    public BigInteger calculateAgreement(
        CipherParameters   pubKey)
    {
        DhPublicKeyParameters   pub = (DhPublicKeyParameters)pubKey;
        DhParameters pubParams = pub.getParameters();

        if (!pubParams.getG().equals(dhParams.getG()) || !pubParams.getP().equals(dhParams.getP()))
        {
            throw new IllegalKeyException("DH public key has wrong domain parameters");
        }

        return pub.getY().modPow(key.getX(), dhParams.getP());
    }
}
