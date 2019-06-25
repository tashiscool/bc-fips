package org.bouncycastle.jcajce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertPathValidatorSpi;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PKIXNameConstraintValidator;
import org.bouncycastle.jcajce.PKIXExtendedBuilderParameters;
import org.bouncycastle.jcajce.PKIXExtendedParameters;

/**
 * CertPathValidatorSpi implementation for X.509 Certificate validation � la RFC
 * 3280.
 */
class PKIXCertPathValidatorSpi
        extends CertPathValidatorSpi
{
    private final Provider fipsProvider;

    PKIXCertPathValidatorSpi(Provider fipsProvider)
    {
        this.fipsProvider = fipsProvider;
    }

    public CertPathValidatorResult engineValidate(
            CertPath certPath,
            CertPathParameters params)
            throws CertPathValidatorException,
            InvalidAlgorithmParameterException
    {
        PKIXExtendedParameters paramsPKIX;
        if (params instanceof PKIXExtendedParameters)
        {
            paramsPKIX = (PKIXExtendedParameters)params;
        }
        else if (params instanceof PKIXExtendedBuilderParameters)
        {
            paramsPKIX = ((PKIXExtendedBuilderParameters)params).getBaseParameters();
        }
        else if (params instanceof PKIXParameters)
        {
            paramsPKIX = new PKIXExtendedParameters.Builder((PKIXParameters)params).build();
        }
        else
        {
            throw new InvalidAlgorithmParameterException("Parameters must be " + PKIXParameters.class.getName()
                    + " or " + PKIXExtendedParameters.class.getName() + " instance.");
        }

        if (paramsPKIX.getTrustAnchors() == null)
        {
            throw new InvalidAlgorithmParameterException(
                    "trustAnchors is null, this is not allowed for certification path validation.");
        }

        //
        // 6.1.1 - inputs
        //

        //
        // (a)
        //
        List certs = certPath.getCertificates();
        int n = certs.size();

        if (certs.isEmpty())
        {
            throw new CertPathValidatorException("Certification path is empty.", null, certPath, -1);
        }

        //
        // (b)
        //
        // Date validDate = CertPathValidatorUtilities.getValidDate(paramsPKIX);

        //
        // (c)
        //
        Set userInitialPolicySet = paramsPKIX.getInitialPolicies();

        //
        // (d)
        // 
        TrustAnchor trust;
        try
        {
            trust = CertPathValidatorUtilities.findTrustAnchor((X509Certificate) certs.get(certs.size() - 1),
                    paramsPKIX.getTrustAnchors(), paramsPKIX.getSigProvider());
        }
        catch (AnnotatedException e)
        {
            throw new CertPathValidatorException(e.getMessage(), e, certPath, certs.size() - 1);
        }

        if (trust == null)
        {
            throw new CertPathValidatorException("Trust anchor for certification path not found.", null, certPath, -1);
        }

        // RFC 5280 - CRLs must originate from the same trust anchor as the target certificate.
        paramsPKIX = new PKIXExtendedParameters.Builder(paramsPKIX).setTrustAnchor(trust).build();

        //
        // (e), (f), (g) are part of the paramsPKIX object.
        //
        Iterator certIter;
        int index = 0;
        int i;
        // Certificate for each iteration of the validation loop
        // Signature information for each iteration of the validation loop
        //
        // 6.1.2 - setup
        //

        //
        // (a)
        //
        List[] policyNodes = new ArrayList[n + 1];
        for (int j = 0; j < policyNodes.length; j++)
        {
            policyNodes[j] = new ArrayList();
        }

        Set policySet = new HashSet();

        policySet.add(RFC3280CertPathUtilities.ANY_POLICY);

        PKIXPolicyNode validPolicyTree = new PKIXPolicyNode(new ArrayList(), 0, policySet, null, new HashSet(),
                RFC3280CertPathUtilities.ANY_POLICY, false);

        policyNodes[0].add(validPolicyTree);

        //
        // (b) and (c)
        //
        PKIXNameConstraintValidator nameConstraintValidator = new PKIXNameConstraintValidator();

        // (d)
        //
        int explicitPolicy;
        Set acceptablePolicies = new HashSet();

        if (paramsPKIX.isExplicitPolicyRequired())
        {
            explicitPolicy = 0;
        }
        else
        {
            explicitPolicy = n + 1;
        }

        //
        // (e)
        //
        int inhibitAnyPolicy;

        if (paramsPKIX.isAnyPolicyInhibited())
        {
            inhibitAnyPolicy = 0;
        }
        else
        {
            inhibitAnyPolicy = n + 1;
        }

        //
        // (f)
        //
        int policyMapping;

        if (paramsPKIX.isPolicyMappingInhibited())
        {
            policyMapping = 0;
        }
        else
        {
            policyMapping = n + 1;
        }

        //
        // (g), (h), (i), (j)
        //
        PublicKey workingPublicKey;
        X500Principal workingIssuerName;

        X509Certificate sign = trust.getTrustedCert();
        try
        {
            if (sign != null)
            {
                workingIssuerName = CertPathValidatorUtilities.getSubjectPrincipal(sign);
                workingPublicKey = sign.getPublicKey();
            }
            else
            {
                workingIssuerName = new X500Principal(trust.getCAName());
                workingPublicKey = trust.getCAPublicKey();
            }
        }
        catch (IllegalArgumentException ex)
        {
            throw new CertPathValidatorException("Subject of trust anchor could not be (re)encoded.", ex, certPath, -1);
        }

        AlgorithmIdentifier workingAlgId = null;
        try
        {
            workingAlgId = CertPathValidatorUtilities.getAlgorithmIdentifier(workingPublicKey);
        }
        catch (CertPathValidatorException e)
        {
            throw new CertPathValidatorException("Algorithm identifier of public key of trust anchor could not be read.", e, certPath, -1);
        }
        ASN1ObjectIdentifier workingPublicKeyAlgorithm = workingAlgId.getAlgorithm();
        ASN1Encodable workingPublicKeyParameters = workingAlgId.getParameters();

        //
        // (k)
        //
        int maxPathLength = n;

        //
        // 6.1.3
        //

        if (paramsPKIX.getTargetConstraints() != null
                && !paramsPKIX.getTargetConstraints().match((X509Certificate) certs.get(0)))
        {
            throw new CertPathValidatorException("Target certificate in certification path does not match targetConstraints.", null, certPath, 0);
        }

        // 
        // initialize CertPathChecker's
        //
        List pathCheckers = paramsPKIX.getCertPathCheckers();
        certIter = pathCheckers.iterator();
        while (certIter.hasNext())
        {
            ((PKIXCertPathChecker) certIter.next()).init(false);
        }

        X509Certificate cert = null;

        for (index = certs.size() - 1; index >= 0; index--)
        {
            // try
            // {
            //
            // i as defined in the algorithm description
            //
            i = n - index;

            //
            // set certificate to be checked in this round
            // sign and workingPublicKey and workingIssuerName are set
            // at the end of the for loop and initialized the
            // first time from the TrustAnchor
            //
            cert = (X509Certificate) certs.get(index);
            boolean verificationAlreadyPerformed = (index == certs.size() - 1);
            if (cert == null)
            {
                throw new CertPathValidatorException("NULL certificate found", null, certPath, index);
            }

            //
            // 6.1.3
            //

            RFC3280CertPathUtilities.processCertA(certPath, paramsPKIX, index, workingPublicKey,
                verificationAlreadyPerformed, workingIssuerName, sign, fipsProvider);

            RFC3280CertPathUtilities.processCertBC(certPath, index, nameConstraintValidator);

            validPolicyTree = RFC3280CertPathUtilities.processCertD(certPath, index, acceptablePolicies,
                    validPolicyTree, policyNodes, inhibitAnyPolicy);

            validPolicyTree = RFC3280CertPathUtilities.processCertE(certPath, index, validPolicyTree);

            RFC3280CertPathUtilities.processCertF(certPath, index, validPolicyTree, explicitPolicy);

            //
            // 6.1.4
            //

            if (i != n)
            {
                if (cert.getVersion() == 1)
                {
                    throw new CertPathValidatorException("Version 1 certificates can't be used as CA ones.", null,
                            certPath, index);
                }

                RFC3280CertPathUtilities.prepareNextCertA(certPath, index);

                validPolicyTree = RFC3280CertPathUtilities.prepareCertB(certPath, index, policyNodes, validPolicyTree,
                        policyMapping);

                RFC3280CertPathUtilities.prepareNextCertG(certPath, index, nameConstraintValidator);

                // (h)
                explicitPolicy = RFC3280CertPathUtilities.prepareNextCertH1(certPath, index, explicitPolicy);
                policyMapping = RFC3280CertPathUtilities.prepareNextCertH2(certPath, index, policyMapping);
                inhibitAnyPolicy = RFC3280CertPathUtilities.prepareNextCertH3(certPath, index, inhibitAnyPolicy);

                //
                // (i)
                //
                explicitPolicy = RFC3280CertPathUtilities.prepareNextCertI1(certPath, index, explicitPolicy);
                policyMapping = RFC3280CertPathUtilities.prepareNextCertI2(certPath, index, policyMapping);

                // (j)
                inhibitAnyPolicy = RFC3280CertPathUtilities.prepareNextCertJ(certPath, index, inhibitAnyPolicy);

                // (k)
                RFC3280CertPathUtilities.prepareNextCertK(certPath, index);

                // (l)
                maxPathLength = RFC3280CertPathUtilities.prepareNextCertL(certPath, index, maxPathLength);

                // (m)
                maxPathLength = RFC3280CertPathUtilities.prepareNextCertM(certPath, index, maxPathLength);

                // (n)
                RFC3280CertPathUtilities.prepareNextCertN(certPath, index);

                Set criticalExtensions = cert.getCriticalExtensionOIDs();
                if (criticalExtensions != null)
                {
                    criticalExtensions = new HashSet(criticalExtensions);

                    criticalExtensions.removeAll(RFC3280CertPathUtilities.CERT_SUPPORTED_CRITICAL_EXTENSIONS);
                }
                else
                {
                    criticalExtensions = new HashSet();
                }

                // (o)
                RFC3280CertPathUtilities.prepareNextCertO(certPath, index, criticalExtensions, pathCheckers);
                
                // set signing certificate for next round
                sign = cert;

                // (c)
                workingIssuerName = CertPathValidatorUtilities.getSubjectPrincipal(sign);

                // (d)
                try
                {
                    workingPublicKey = CertPathValidatorUtilities.getNextWorkingKey(certPath.getCertificates(), index, fipsProvider);
                }
                catch (CertPathValidatorException e)
                {
                    throw new CertPathValidatorException("Next working key could not be retrieved.", e, certPath, index);
                }

                workingAlgId = CertPathValidatorUtilities.getAlgorithmIdentifier(workingPublicKey);
                // (f)
                workingPublicKeyAlgorithm = workingAlgId.getAlgorithm();
                // (e)
                workingPublicKeyParameters = workingAlgId.getParameters();
            }
        }

        //
        // 6.1.5 Wrap-up procedure
        //

        explicitPolicy = RFC3280CertPathUtilities.wrapupCertA(explicitPolicy, cert);

        explicitPolicy = RFC3280CertPathUtilities.wrapupCertB(certPath, index + 1, explicitPolicy);

        //
        // (c) (d) and (e) are already done
        //

        //
        // (f)
        //
        Set criticalExtensions = cert.getCriticalExtensionOIDs();

        if (criticalExtensions != null)
        {
            criticalExtensions = new HashSet(criticalExtensions);

            // these extensions are handled by the algorithm
            criticalExtensions.removeAll(RFC3280CertPathUtilities.CERT_SUPPORTED_CRITICAL_EXTENSIONS);

            // not associated with CertPath processingin an end-entity
            criticalExtensions.remove(Extension.extendedKeyUsage.getId());
        }
        else
        {
            criticalExtensions = new HashSet();
        }

        RFC3280CertPathUtilities.wrapupCertF(certPath, index + 1, pathCheckers, criticalExtensions);

        PKIXPolicyNode intersection = RFC3280CertPathUtilities.wrapupCertG(certPath, paramsPKIX, userInitialPolicySet,
                index + 1, policyNodes, validPolicyTree, acceptablePolicies);

        if ((explicitPolicy > 0) || (intersection != null))
        {
            return new PKIXCertPathValidatorResult(trust, intersection, cert.getPublicKey());
        }

        throw new CertPathValidatorException("Path processing failed on policy.", null, certPath, index);
    }

}
