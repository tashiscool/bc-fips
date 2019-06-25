package org.bouncycastle.jcajce.provider;

import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

abstract class AsymmetricAlgorithmProvider
    extends AlgorithmProvider
{       
    protected void addKeyAgreementAlgorithm(
        BouncyCastleFipsProvider provider,
        String algorithm,
        String className,
        Map<String, String> attributes,
        EngineCreator engineCreator)
    {
        provider.addAlgorithmImplementation("KeyAgreement." + algorithm, className, engineCreator);
        provider.addAttributes("KeyAgreement." + algorithm, attributes);
    }

    protected void addSignatureAlgorithm(
        BouncyCastleFipsProvider provider,
        String digest,
        String algorithm,
        String className,
        ASN1ObjectIdentifier oid,
        Map<String, String> attributes,
        EngineCreator engineCreator)
    {
        String mainName = digest + "WITH" + algorithm;
        String alias = digest + "/" + algorithm;

        provider.addAlgorithmImplementation("Signature." + mainName, className, engineCreator);
        provider.addAlias("Signature", mainName, alias);

        if (oid != null)
        {
            provider.addAlias("Signature", mainName, oid);
        }
        provider.addAttributes("Signature." + mainName, attributes);
    }

    protected void addSignatureAlgorithm(
        BouncyCastleFipsProvider provider,
        String digest,
        String algorithm,
        String className,
        ASN1ObjectIdentifier oid,
        EngineCreator engineCreator)
    {
        String mainName = digest + "WITH" + algorithm;
        String alias = digest + "/" + algorithm;

        provider.addAlgorithmImplementation("Signature." + mainName, className, engineCreator);
        provider.addAlias("Signature", mainName, alias);

        if (oid != null)
        {
            provider.addAlias("Signature", mainName, oid);
        }
    }

    protected void registerOid(BouncyCastleFipsProvider provider, ASN1ObjectIdentifier oid, String name, AsymmetricKeyInfoConverter keyFactory)
    {
        provider.addAlias("KeyFactory", name, oid);
        provider.addAlias("KeyPairGenerator", name, oid);

        provider.addKeyInfoConverter(oid, keyFactory);
    }

    protected void registerOidAlgorithmParameters(BouncyCastleFipsProvider provider, ASN1ObjectIdentifier oid, String name)
    {
        provider.addAlias("AlgorithmParameterGenerator", name, oid);
        provider.addAlias("AlgorithmParameters", name, oid);
    }
}
