package org.bouncycastle.crypto.fips;

import java.math.BigInteger;

import org.bouncycastle.crypto.AsymmetricPublicKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricECPublicKey;
import org.bouncycastle.crypto.asymmetric.ECDomainParameters;
import org.bouncycastle.crypto.asymmetric.NamedECDomainParameters;
import org.bouncycastle.crypto.internal.BasicAgreement;
import org.bouncycastle.crypto.internal.params.EcDomainParameters;
import org.bouncycastle.crypto.internal.params.EcMqvPublicParameters;
import org.bouncycastle.crypto.internal.params.EcNamedDomainParameters;
import org.bouncycastle.crypto.internal.params.EcPublicKeyParameters;
import org.bouncycastle.util.BigIntegers;

class EcDHAgreement<T extends FipsAgreementParameters>
    extends FipsAgreement<T>
{
    private final BasicAgreement dh;
    private final T parameter;

    EcDHAgreement(BasicAgreement dh, T parameter)
    {
        this.dh = dh;
        this.parameter = parameter;
    }

    @Override
    public T getParameters()
    {
        return parameter;
    }

    @Override
    public byte[] calculate(AsymmetricPublicKey key)
    {
        AsymmetricECPublicKey ecKey = (AsymmetricECPublicKey)key;
        EcPublicKeyParameters lwECKey = new EcPublicKeyParameters(ecKey.getW(), getDomainParams(ecKey.getDomainParameters()));

        int length = dh.getFieldSize();

        BigInteger z;
        if (dh instanceof EcMqvBasicAgreement)
        {
            AsymmetricECPublicKey ephPublicKey = ((FipsEC.MQVAgreementParameters)parameter).getOtherPartyEphemeralKey();
            z = dh.calculateAgreement(new EcMqvPublicParameters(lwECKey, new EcPublicKeyParameters(ephPublicKey.getW(), getDomainParams(ephPublicKey.getDomainParameters()))));
        }
        else
        {
            z = dh.calculateAgreement(lwECKey);
        }

        byte[] zBytes = BigIntegers.asUnsignedByteArray(length, z);

        return FipsKDF.processZBytes(zBytes, parameter);
    }

    private static EcDomainParameters getDomainParams(ECDomainParameters curveParams)
    {
        if (curveParams instanceof NamedECDomainParameters)
        {
            return new EcNamedDomainParameters(((NamedECDomainParameters)curveParams).getID(), curveParams.getCurve(), curveParams.getG(), curveParams.getN(), curveParams.getH(), curveParams.getSeed());
        }
        return new EcDomainParameters(curveParams.getCurve(), curveParams.getG(), curveParams.getN(), curveParams.getH(), curveParams.getSeed());
    }
}
