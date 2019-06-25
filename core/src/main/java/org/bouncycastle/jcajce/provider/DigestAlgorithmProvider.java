package org.bouncycastle.jcajce.provider;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

abstract class DigestAlgorithmProvider
    extends AlgorithmProvider
{
    void addHMACAlgorithm(
        BouncyCastleFipsProvider provider,
        String algorithm,
        String algorithmClassName,
        EngineCreator algorithmCreator,
        String keyGeneratorClassName,
        EngineCreator keyGeneratorCreator,
        String keyFactoryClassName,
        EngineCreator keyFactoryCreator)
    {
        String mainName = "HMAC" + algorithm;

        provider.addAlgorithmImplementation("Mac." + mainName, algorithmClassName, algorithmCreator);
        provider.addAlias("Mac", mainName, "HMAC-" + algorithm, "HMAC/" + algorithm);

        provider.addAlgorithmImplementation("KeyGenerator." + mainName, keyGeneratorClassName, keyGeneratorCreator);
        provider.addAlias("KeyGenerator", mainName, "HMAC-" + algorithm, "HMAC/" + algorithm);

        provider.addAlgorithmImplementation("SecretKeyFactory." + mainName, keyFactoryClassName, keyFactoryCreator);
        provider.addAlias("SecretKeyFactory", mainName, "HMAC-" + algorithm, "HMAC/" + algorithm);
    }

    void addHMACAlias(
        BouncyCastleFipsProvider provider,
        String algorithm,
        String... aliases)
    {
        String mainName = "HMAC" + algorithm;

        provider.addAlias("Mac", mainName, aliases);
        provider.addAlias("KeyGenerator", mainName, aliases);
        provider.addAlias("SecretKeyFactory", mainName, aliases);
    }

    void addHMACAlias(
        BouncyCastleFipsProvider provider,
        String algorithm,
        ASN1ObjectIdentifier... oids)
    {
        String mainName = "HMAC" + algorithm;

        provider.addAlias("Mac", mainName, oids);
        provider.addAlias("KeyGenerator", mainName, oids);
        provider.addAlias("SecretKeyFactory", mainName, oids);
    }
}
