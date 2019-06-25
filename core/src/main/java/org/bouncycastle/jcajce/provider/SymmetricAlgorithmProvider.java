package org.bouncycastle.jcajce.provider;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

abstract class SymmetricAlgorithmProvider
    extends AlgorithmProvider
{
    protected void addKeyGeneratorForOIDs(
        BouncyCastleFipsProvider provider,
        String prefix,
        EngineCreator keyGeneratorCreator,
        ASN1ObjectIdentifier... oids)
    {
        for (ASN1ObjectIdentifier oid : oids)
        {
            provider.addAlgorithmImplementation("KeyGenerator", oid, prefix + "$" + oid, keyGeneratorCreator);
        }
    }
}
