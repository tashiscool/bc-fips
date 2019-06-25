package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.jcajce.spec.AEADParameterSpec;

class ASN1AlgorithmParameters
    extends BaseAlgorithmParameters
{
    private final String algorithm;

    private ASN1Primitive spec;

    ASN1AlgorithmParameters(String algName)
    {
        this.algorithm = algName;
    }

    protected byte[] localGetEncoded()
        throws IOException
    {
        return spec.getEncoded();
    }

    protected AlgorithmParameterSpec localEngineGetParameterSpec(
        Class paramSpec)
        throws InvalidParameterSpecException
    {
        if (paramSpec == IvParameterSpec.class)
        {
            if (spec instanceof ASN1OctetString)
            {
                return new IvParameterSpec(ASN1OctetString.getInstance(spec).getOctets());
            }
            if (spec instanceof ASN1Sequence)
            {
                return new IvParameterSpec(GCMParameters.getInstance(spec).getNonce());
            }
            throw new InvalidParameterSpecException("Cannot convert AlgorithmParameters to IvParameterSpec");
        }
        if (paramSpec == AlgorithmParameterSpec.class)
        {
            if (spec instanceof ASN1OctetString)
            {
                return new IvParameterSpec(ASN1OctetString.getInstance(spec).getOctets());
            }
            if (spec instanceof ASN1Sequence)
            {
                if (GcmSpecUtil.gcmSpecExists())
                {
                    return GcmSpecUtil.extractGcmSpec(spec);
                }
                else
                {
                    GCMParameters gcmParams = GCMParameters.getInstance(spec);

                    return new AEADParameterSpec(gcmParams.getNonce(), gcmParams.getIcvLen() * 8);
                }
            }
            throw new InvalidParameterSpecException("Cannot convert AlgorithmParameters to IvParameterSpec");
        }

        if (GcmSpecUtil.isGcmSpec(paramSpec))
        {
             return GcmSpecUtil.extractGcmSpec(spec);
        }

        if (paramSpec == AEADParameterSpec.class && spec instanceof ASN1Sequence)
        {
            try
            {
                GCMParameters gcmParams = GCMParameters.getInstance(spec);

                return new AEADParameterSpec(gcmParams.getNonce(), gcmParams.getIcvLen() * 8);
            }
            catch (Exception e)
            {
                throw new InvalidParameterSpecException("ASN.1 encoding not recognized: " + e.getMessage());   // should never happen
            }
        }

        throw new InvalidParameterSpecException("AlgorithmParameterSpec not recognized: " + paramSpec.getName());
    }

    protected void engineInit(
        AlgorithmParameterSpec paramSpec)
        throws InvalidParameterSpecException
    {
        if (paramSpec instanceof IvParameterSpec)
        {
            if (paramSpec instanceof AEADParameterSpec)
            {
                spec = new GCMParameters(((AEADParameterSpec)paramSpec).getNonce(), (((AEADParameterSpec)paramSpec).getMacSizeInBits() + 7) / 8).toASN1Primitive();
            }
            else
            {
                spec = new DEROctetString(((IvParameterSpec)paramSpec).getIV());
            }
        }
        else if (GcmSpecUtil.isGcmSpec(paramSpec))
        {
            spec = GcmSpecUtil.extractGcmParameters(paramSpec).toASN1Primitive();
        }
        else
        {
            throw new InvalidParameterSpecException("AlgorithmParameterSpec class not recognized: " + paramSpec.getClass().getName());
        }
    }

    protected void localInit(
        byte[] params)
        throws IOException
    {
        spec = ASN1Primitive.fromByteArray(params);
    }

    protected String engineToString()
    {
        return "ASN.1 Parameters";
    }
}
