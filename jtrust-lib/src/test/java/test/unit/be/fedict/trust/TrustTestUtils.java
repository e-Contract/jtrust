/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see 
 * http://www.gnu.org/licenses/.
 */

package test.unit.be.fedict.trust;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.*;
import org.bouncycastle.x509.X509V2CRLGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.joda.time.DateTime;
import sun.security.x509.IssuerAlternativeNameExtension;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

public class TrustTestUtils {

	public static X509Certificate generateCertificate(
			PublicKey subjectPublicKey, String subjectDn, DateTime notBefore,
			DateTime notAfter, X509Certificate issuerCertificate,
			PrivateKey issuerPrivateKey) throws IOException,
            InvalidKeyException, IllegalStateException,
            NoSuchAlgorithmException, SignatureException, CertificateException, OperatorCreationException {
		return generateCertificate(subjectPublicKey, subjectDn, notBefore,
				notAfter, issuerCertificate, issuerPrivateKey, true);
	}

	public static X509Certificate generateCertificate(
			PublicKey subjectPublicKey, String subjectDn, DateTime notBefore,
			DateTime notAfter, X509Certificate issuerCertificate,
			PrivateKey issuerPrivateKey, boolean caFlag) throws IOException,
            InvalidKeyException, IllegalStateException,
            NoSuchAlgorithmException, SignatureException, CertificateException, OperatorCreationException {
		return generateCertificate(subjectPublicKey, subjectDn, notBefore,
				notAfter, issuerCertificate, issuerPrivateKey, caFlag, -1);
	}

	public static X509Certificate generateCertificate(
			PublicKey subjectPublicKey, String subjectDn, DateTime notBefore,
			DateTime notAfter, X509Certificate issuerCertificate,
			PrivateKey issuerPrivateKey, boolean caFlag, int pathLength)
            throws IOException, InvalidKeyException, IllegalStateException,
            NoSuchAlgorithmException, SignatureException, CertificateException, OperatorCreationException {
		return generateCertificate(subjectPublicKey, subjectDn, notBefore,
				notAfter, issuerCertificate, issuerPrivateKey, caFlag,
				pathLength, null);
	}

	public static X509Certificate generateCertificate(
			PublicKey subjectPublicKey, String subjectDn, DateTime notBefore,
			DateTime notAfter, X509Certificate issuerCertificate,
			PrivateKey issuerPrivateKey, boolean caFlag, int pathLength,
			String crlUri) throws IOException, InvalidKeyException,
            IllegalStateException, NoSuchAlgorithmException,
            SignatureException, CertificateException, OperatorCreationException {
		return generateCertificate(subjectPublicKey, subjectDn, notBefore,
				notAfter, issuerCertificate, issuerPrivateKey, caFlag,
				pathLength, crlUri, null);
	}

	public static X509Certificate generateCertificate(
			PublicKey subjectPublicKey, String subjectDn, DateTime notBefore,
			DateTime notAfter, X509Certificate issuerCertificate,
			PrivateKey issuerPrivateKey, boolean caFlag, int pathLength,
			String crlUri, String ocspUri) throws IOException,
            InvalidKeyException, IllegalStateException,
            NoSuchAlgorithmException, SignatureException, CertificateException, OperatorCreationException {
		X509Certificate certificate = generateCertificate(subjectPublicKey,
				subjectDn, notBefore, notAfter, issuerCertificate,
				issuerPrivateKey, caFlag, pathLength, crlUri, ocspUri, null,
				"SHA1withRSA");
		return certificate;
	}

	public static X509Certificate generateCertificate(
			PublicKey subjectPublicKey, String subjectDn, DateTime notBefore,
			DateTime notAfter, X509Certificate issuerCertificate,
			PrivateKey issuerPrivateKey, boolean caFlag, int pathLength,
			String crlUri, String ocspUri, KeyUsage keyUsage,
			String signatureAlgorithm) throws IOException, InvalidKeyException,
            IllegalStateException, NoSuchAlgorithmException,
            SignatureException, CertificateException, OperatorCreationException {

		return generateCertificate(subjectPublicKey, subjectDn, notBefore,
				notAfter, issuerCertificate, issuerPrivateKey, caFlag,
				pathLength, crlUri, ocspUri, keyUsage, signatureAlgorithm,
				false);
	}

	public static X509Certificate generateCertificate(
			PublicKey subjectPublicKey, String subjectDn, DateTime notBefore,
			DateTime notAfter, X509Certificate issuerCertificate,
			PrivateKey issuerPrivateKey, boolean caFlag, int pathLength,
			String crlUri, String ocspUri, KeyUsage keyUsage,
			String signatureAlgorithm, boolean tsa) throws IOException,
            InvalidKeyException, IllegalStateException,
            NoSuchAlgorithmException, SignatureException, CertificateException, OperatorCreationException {

		return generateCertificate(subjectPublicKey, subjectDn, notBefore,
				notAfter, issuerCertificate, issuerPrivateKey, caFlag,
				pathLength, crlUri, ocspUri, keyUsage, signatureAlgorithm, tsa,
				true, true);
	}

	public static X509Certificate generateCertificate(
			PublicKey subjectPublicKey, String subjectDn, DateTime notBefore,
			DateTime notAfter, X509Certificate issuerCertificate,
			PrivateKey issuerPrivateKey, boolean caFlag, int pathLength,
			String crlUri, String ocspUri, KeyUsage keyUsage,
			String signatureAlgorithm, boolean tsa, boolean includeSKID,
			boolean includeAKID) throws IOException, InvalidKeyException,
            IllegalStateException, NoSuchAlgorithmException,
            SignatureException, CertificateException, OperatorCreationException {

		return generateCertificate(subjectPublicKey, subjectDn, notBefore,
				notAfter, issuerCertificate, issuerPrivateKey, caFlag,
				pathLength, crlUri, ocspUri, keyUsage, signatureAlgorithm, tsa,
				includeSKID, includeAKID, null);
	}

	public static X509Certificate generateCertificate(
			PublicKey subjectPublicKey, String subjectDn, DateTime notBefore,
			DateTime notAfter, X509Certificate issuerCertificate,
			PrivateKey issuerPrivateKey, boolean caFlag, int pathLength,
			String crlUri, String ocspUri, KeyUsage keyUsage,
			String signatureAlgorithm, boolean tsa, boolean includeSKID,
			boolean includeAKID, PublicKey akidPublicKey) throws IOException,
            InvalidKeyException, IllegalStateException,
            NoSuchAlgorithmException, SignatureException, CertificateException, OperatorCreationException {

		return generateCertificate(subjectPublicKey, subjectDn, notBefore,
				notAfter, issuerCertificate, issuerPrivateKey, caFlag,
				pathLength, crlUri, ocspUri, keyUsage, signatureAlgorithm, tsa,
				includeSKID, includeAKID, akidPublicKey, null);
	}

	public static X509Certificate generateCertificate(
			PublicKey subjectPublicKey, String subjectDn, DateTime notBefore,
			DateTime notAfter, X509Certificate issuerCertificate,
			PrivateKey issuerPrivateKey, boolean caFlag, int pathLength,
			String crlUri, String ocspUri, KeyUsage keyUsage,
			String signatureAlgorithm, boolean tsa, boolean includeSKID,
			boolean includeAKID, PublicKey akidPublicKey,
			String certificatePolicy) throws IOException, InvalidKeyException,
            IllegalStateException, NoSuchAlgorithmException,
            SignatureException, CertificateException, OperatorCreationException {

		return generateCertificate(subjectPublicKey, subjectDn, notBefore,
				notAfter, issuerCertificate, issuerPrivateKey, caFlag,
				pathLength, crlUri, ocspUri, keyUsage, signatureAlgorithm, tsa,
				includeSKID, includeAKID, akidPublicKey, certificatePolicy,
				null);
	}

	public static X509Certificate generateCertificate(
			PublicKey subjectPublicKey, String subjectDn, DateTime notBefore,
			DateTime notAfter, X509Certificate issuerCertificate,
			PrivateKey issuerPrivateKey, boolean caFlag, int pathLength,
			String crlUri, String ocspUri, KeyUsage keyUsage,
			String signatureAlgorithm, boolean tsa, boolean includeSKID,
			boolean includeAKID, PublicKey akidPublicKey,
			String certificatePolicy, Boolean qcCompliance) throws IOException,
            InvalidKeyException, IllegalStateException,
            NoSuchAlgorithmException, SignatureException, CertificateException, OperatorCreationException {

		return generateCertificate(subjectPublicKey, subjectDn, notBefore,
				notAfter, issuerCertificate, issuerPrivateKey, caFlag,
				pathLength, crlUri, ocspUri, keyUsage, signatureAlgorithm, tsa,
				includeSKID, includeAKID, akidPublicKey, certificatePolicy,
				qcCompliance, false);
	}

	public static X509Certificate generateCertificate(
			PublicKey subjectPublicKey, String subjectDn, DateTime notBefore,
			DateTime notAfter, X509Certificate issuerCertificate,
			PrivateKey issuerPrivateKey, boolean caFlag, int pathLength,
			String crlUri, String ocspUri, KeyUsage keyUsage,
			String signatureAlgorithm, boolean tsa, boolean includeSKID,
			boolean includeAKID, PublicKey akidPublicKey,
			String certificatePolicy, Boolean qcCompliance,
			boolean ocspResponder) throws IOException, InvalidKeyException,
            IllegalStateException, NoSuchAlgorithmException,
            SignatureException, CertificateException, OperatorCreationException {

        X500Name issuerName;
        if (null != issuerCertificate) {
            issuerName = new X500Name(issuerCertificate.getSubjectX500Principal().toString());
        } else {
            issuerName = new X500Name(subjectDn);
        }
        X500Name subjectName = new X500Name(subjectDn);
        BigInteger serial = new BigInteger(128, new SecureRandom());
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo
                .getInstance(subjectPublicKey.getEncoded());
        X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(issuerName, serial, notBefore.toDate(), notAfter.toDate(),
                subjectName, publicKeyInfo);

        JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
		if (includeSKID) {
            x509v3CertificateBuilder.addExtension(
                    X509Extension.subjectKeyIdentifier, false, extensionUtils
                    .createSubjectKeyIdentifier(subjectPublicKey));
		}

		if (includeAKID) {

			PublicKey authorityPublicKey;
			if (null != akidPublicKey) {
                authorityPublicKey = akidPublicKey;
			} else if (null != issuerCertificate) {
                authorityPublicKey = issuerCertificate.getPublicKey();
			} else {
                authorityPublicKey = subjectPublicKey;
			}
            x509v3CertificateBuilder.addExtension(
                    X509Extension.authorityKeyIdentifier, false, extensionUtils
                    .createAuthorityKeyIdentifier(authorityPublicKey));
		}

		if (caFlag) {
			if (-1 == pathLength) {
                x509v3CertificateBuilder.addExtension(
                        X509Extension.basicConstraints, true, new BasicConstraints(
                        2147483647));
			} else {
                x509v3CertificateBuilder.addExtension(
                        X509Extension.basicConstraints, true, new BasicConstraints(
                        pathLength));
			}
		}

		if (null != crlUri) {
            GeneralName generalName = new GeneralName(
                    GeneralName.uniformResourceIdentifier, new DERIA5String(
                    crlUri));
            GeneralNames generalNames = new GeneralNames(generalName);
            DistributionPointName distPointName = new DistributionPointName(
                    generalNames);
            DistributionPoint distPoint = new DistributionPoint(distPointName,
                    null, null);
            DistributionPoint[] crlDistPoints = new DistributionPoint[] { distPoint };
            CRLDistPoint crlDistPoint = new CRLDistPoint(crlDistPoints);
            x509v3CertificateBuilder.addExtension(
                    X509Extension.cRLDistributionPoints, false, crlDistPoint);
		}

		if (null != ocspUri) {
			GeneralName ocspName = new GeneralName(
					GeneralName.uniformResourceIdentifier, ocspUri);
			AuthorityInformationAccess authorityInformationAccess = new AuthorityInformationAccess(
					X509ObjectIdentifiers.ocspAccessMethod, ocspName);
            x509v3CertificateBuilder.addExtension(
					X509Extension.authorityInfoAccess, false,
					authorityInformationAccess);
		}

		if (null != keyUsage) {
            x509v3CertificateBuilder.addExtension(X509Extension.keyUsage, true,
                    keyUsage);
		}

		if (null != certificatePolicy) {
            ASN1ObjectIdentifier policyObjectIdentifier = new ASN1ObjectIdentifier(certificatePolicy);
            PolicyInformation policyInformation = new PolicyInformation(policyObjectIdentifier);
            x509v3CertificateBuilder.addExtension(
                    X509Extension.certificatePolicies, false, new DERSequence(
                    policyInformation));
		}

		if (null != qcCompliance) {
			ASN1EncodableVector vec = new ASN1EncodableVector();
			if (qcCompliance) {
				vec.add(new QCStatement(QCStatement.id_etsi_qcs_QcCompliance));
			} else {
				vec.add(new QCStatement(QCStatement.id_etsi_qcs_RetentionPeriod));
			}
            x509v3CertificateBuilder.addExtension(X509Extension.qCStatements,
					true, new DERSequence(vec));

		}

		if (tsa) {
            x509v3CertificateBuilder
					.addExtension(X509Extension.extendedKeyUsage, true,
							new ExtendedKeyUsage(
									KeyPurposeId.id_kp_timeStamping));
		}

		if (ocspResponder) {
            x509v3CertificateBuilder.addExtension(
					OCSPObjectIdentifiers.id_pkix_ocsp_nocheck, false,
					new DERNull());

            x509v3CertificateBuilder.addExtension(X509Extension.extendedKeyUsage,
					true, new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning));
		}

        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder()
                .find(signatureAlgorithm);
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder()
                .find(sigAlgId);
        AsymmetricKeyParameter
            asymmetricKeyParameter = PrivateKeyFactory
                    .createKey(issuerPrivateKey.getEncoded());

        ContentSigner contentSigner = new BcRSAContentSignerBuilder(sigAlgId, digAlgId)
                    .build(asymmetricKeyParameter);
        X509CertificateHolder x509CertificateHolder = x509v3CertificateBuilder
                .build(contentSigner);

        byte[] encodedCertificate = x509CertificateHolder.getEncoded();

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certificateFactory
                    .generateCertificate(new ByteArrayInputStream(
                            encodedCertificate));
        return certificate;
	}

	public static KeyPair generateKeyPair() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		SecureRandom random = new SecureRandom();
		keyPairGenerator.initialize(new RSAKeyGenParameterSpec(1024,
				RSAKeyGenParameterSpec.F4), random);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return keyPair;
	}

	public static X509Certificate generateSelfSignedCertificate(
			KeyPair keyPair, String subjectDn, DateTime notBefore,
			DateTime notAfter, boolean caFlag, int pathLength, String crlUri)
            throws IOException, InvalidKeyException, IllegalStateException,
            NoSuchAlgorithmException, SignatureException, CertificateException, OperatorCreationException {
		return generateSelfSignedCertificate(keyPair, subjectDn, notBefore,
				notAfter, caFlag, pathLength, crlUri, null);
	}

	public static X509Certificate generateSelfSignedCertificate(
			KeyPair keyPair, String subjectDn, DateTime notBefore,
			DateTime notAfter, boolean caFlag, int pathLength, String crlUri,
			KeyUsage keyUsage) throws IOException, InvalidKeyException,
            IllegalStateException, NoSuchAlgorithmException,
            SignatureException, CertificateException, OperatorCreationException {
		PublicKey subjectPublicKey = keyPair.getPublic();
		PrivateKey issuerPrivateKey = keyPair.getPrivate();
		X509Certificate certificate = generateCertificate(subjectPublicKey,
				subjectDn, notBefore, notAfter, null, issuerPrivateKey, caFlag,
				pathLength, crlUri, null, keyUsage, "SHA1withRSA");
		return certificate;
	}

	public static X509Certificate generateSelfSignedCertificate(
			KeyPair keyPair, String subjectDn, DateTime notBefore,
			DateTime notAfter, boolean caFlag, int pathLength, String crlUri,
			KeyUsage keyUsage, String signatureAlgorithm) throws IOException,
            InvalidKeyException, IllegalStateException,
            NoSuchAlgorithmException, SignatureException, CertificateException, OperatorCreationException {
		PublicKey subjectPublicKey = keyPair.getPublic();
		PrivateKey issuerPrivateKey = keyPair.getPrivate();
		X509Certificate certificate = generateCertificate(subjectPublicKey,
				subjectDn, notBefore, notAfter, null, issuerPrivateKey, caFlag,
				pathLength, crlUri, null, keyUsage, signatureAlgorithm);
		return certificate;
	}

	public static X509Certificate generateSelfSignedCertificate(
			KeyPair keyPair, String subjectDn, DateTime notBefore,
			DateTime notAfter, boolean caFlag, int pathLength)
            throws IOException, InvalidKeyException, IllegalStateException,
            NoSuchAlgorithmException, SignatureException, CertificateException, OperatorCreationException {
		return generateSelfSignedCertificate(keyPair, subjectDn, notBefore,
				notAfter, caFlag, pathLength, null);
	}

	public static X509Certificate generateSelfSignedCertificate(
			KeyPair keyPair, String subjectDn, DateTime notBefore,
			DateTime notAfter, boolean caFlag) throws IOException,
            InvalidKeyException, IllegalStateException,
            NoSuchAlgorithmException, SignatureException, CertificateException, OperatorCreationException {
		return generateSelfSignedCertificate(keyPair, subjectDn, notBefore,
				notAfter, caFlag, -1);
	}

	public static X509Certificate generateSelfSignedCertificate(
			KeyPair keyPair, String subjectDn, DateTime notBefore,
			DateTime notAfter, String crlUri) throws IOException,
            InvalidKeyException, IllegalStateException,
            NoSuchAlgorithmException, SignatureException, CertificateException, OperatorCreationException {
		return generateSelfSignedCertificate(keyPair, subjectDn, notBefore,
				notAfter, true, -1, crlUri);
	}

	public static X509Certificate generateSelfSignedCertificate(
			KeyPair keyPair, String subjectDn, DateTime notBefore,
			DateTime notAfter) throws IOException, InvalidKeyException,
            IllegalStateException, NoSuchAlgorithmException,
            SignatureException, CertificateException, OperatorCreationException {
		return generateSelfSignedCertificate(keyPair, subjectDn, notBefore,
				notAfter, true);
	}

	public static class RevokedCertificate {
		private final BigInteger serialNumber;
		private final DateTime revocationDate;

		public RevokedCertificate(BigInteger serialNumber,
				DateTime revocationDate) {
			this.serialNumber = serialNumber;
			this.revocationDate = revocationDate;
		}
	}

	public static X509CRL generateCrl(PrivateKey issuerPrivateKey,
			X509Certificate issuerCertificate, DateTime thisUpdate,
			DateTime nextUpdate, BigInteger... revokedCertificateSerialNumbers)
            throws InvalidKeyException, CRLException, IllegalStateException,
            NoSuchAlgorithmException, SignatureException,
            CertificateException, OperatorCreationException, IOException {

		return generateCrl(issuerPrivateKey, issuerCertificate, thisUpdate,
				nextUpdate, "SHA1withRSA", revokedCertificateSerialNumbers);
	}

	public static X509CRL generateCrl(PrivateKey issuerPrivateKey,
			X509Certificate issuerCertificate, DateTime thisUpdate,
			DateTime nextUpdate, String signatureAlgorithm,
			BigInteger... revokedCertificateSerialNumbers)
            throws InvalidKeyException, CRLException, IllegalStateException,
            NoSuchAlgorithmException, SignatureException,
            CertificateException, OperatorCreationException, IOException {

		List<RevokedCertificate> revokedCertificates = new LinkedList<RevokedCertificate>();
		for (BigInteger revokedCertificateSerialNumber : revokedCertificateSerialNumbers) {
			revokedCertificates.add(new RevokedCertificate(
					revokedCertificateSerialNumber, thisUpdate));
		}
		return generateCrl(issuerPrivateKey, issuerCertificate, thisUpdate,
				nextUpdate, null, false, revokedCertificates,
				signatureAlgorithm);
	}

	public static X509CRL generateCrl(PrivateKey issuerPrivateKey,
			X509Certificate issuerCertificate, DateTime thisUpdate,
			DateTime nextUpdate, List<RevokedCertificate> revokedCertificates)
            throws InvalidKeyException, CRLException, IllegalStateException,
            NoSuchAlgorithmException, SignatureException,
            CertificateException, OperatorCreationException, IOException {

		return generateCrl(issuerPrivateKey, issuerCertificate, thisUpdate,
				nextUpdate, null, false, revokedCertificates, "SHA1withRSA");
	}

	public static X509CRL generateCrl(PrivateKey issuerPrivateKey,
			X509Certificate issuerCertificate, DateTime thisUpdate,
			DateTime nextUpdate, List<String> deltaCrlUris,
			List<RevokedCertificate> revokedCertificates)
            throws InvalidKeyException, CRLException, IllegalStateException,
            NoSuchAlgorithmException, SignatureException,
            CertificateException, OperatorCreationException, IOException {

		return generateCrl(issuerPrivateKey, issuerCertificate, thisUpdate,
				nextUpdate, deltaCrlUris, false, revokedCertificates,
				"SHA1withRSA");
	}

	public static X509CRL generateCrl(PrivateKey issuerPrivateKey,
			X509Certificate issuerCertificate, DateTime thisUpdate,
			DateTime nextUpdate, List<String> deltaCrlUris, boolean deltaCrl,
			List<RevokedCertificate> revokedCertificates)
            throws InvalidKeyException, CRLException, IllegalStateException,
            NoSuchAlgorithmException, SignatureException,
            CertificateException, OperatorCreationException, IOException {

		return generateCrl(issuerPrivateKey, issuerCertificate, thisUpdate,
				nextUpdate, deltaCrlUris, deltaCrl, revokedCertificates,
				"SHA1withRSA");
	}

	public static X509CRL generateCrl(PrivateKey issuerPrivateKey,
			X509Certificate issuerCertificate, DateTime thisUpdate,
			DateTime nextUpdate, List<String> deltaCrlUris, boolean deltaCrl,
			List<RevokedCertificate> revokedCertificates,
			String signatureAlgorithm) throws InvalidKeyException,
            CRLException, IllegalStateException, NoSuchAlgorithmException,
            SignatureException, CertificateException, IOException, OperatorCreationException {

        X500Name issuerName = new X500Name(issuerCertificate.getSubjectX500Principal().toString());
        X509v2CRLBuilder x509v2crlBuilder = new X509v2CRLBuilder(issuerName,
                thisUpdate.toDate());
        x509v2crlBuilder.setNextUpdate(nextUpdate.toDate());

		for (RevokedCertificate revokedCertificate : revokedCertificates) {
            x509v2crlBuilder.addCRLEntry(revokedCertificate.serialNumber,
					revokedCertificate.revocationDate.toDate(),
					CRLReason.privilegeWithdrawn);
		}


        JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
        x509v2crlBuilder.addExtension(X509Extension.authorityKeyIdentifier, false,
				extensionUtils.createAuthorityKeyIdentifier(issuerCertificate));
        x509v2crlBuilder.addExtension(X509Extension.cRLNumber, false,
				new CRLNumber(BigInteger.ONE));

		if (null != deltaCrlUris && !deltaCrlUris.isEmpty()) {
			DistributionPoint[] deltaCrlDps = new DistributionPoint[deltaCrlUris
					.size()];
			for (int i = 0; i < deltaCrlUris.size(); i++) {
				deltaCrlDps[i] = getDistributionPoint(deltaCrlUris.get(i));
			}
			CRLDistPoint crlDistPoint = new CRLDistPoint(
					(DistributionPoint[]) deltaCrlDps);
            x509v2crlBuilder.addExtension(X509Extension.freshestCRL, false,
					crlDistPoint);
		}

		if (deltaCrl) {
            x509v2crlBuilder.addExtension(X509Extension.deltaCRLIndicator, true,
					new CRLNumber(BigInteger.ONE));
		}

        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder()
                .find(signatureAlgorithm);
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder()
                .find(sigAlgId);
        AsymmetricKeyParameter asymmetricKeyParameter = PrivateKeyFactory
                    .createKey(issuerPrivateKey.getEncoded());

        ContentSigner contentSigner = new BcRSAContentSignerBuilder(sigAlgId, digAlgId)
                    .build(asymmetricKeyParameter);

        X509CRLHolder x509crlHolder = x509v2crlBuilder.build(contentSigner);
        byte[] crlValue = x509crlHolder.getEncoded();
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509CRL crl = (X509CRL) certificateFactory
                .generateCRL(new ByteArrayInputStream(crlValue));
		return crl;
	}

	public static DistributionPoint getDistributionPoint(String uri) {
		GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier,
				new DERIA5String(uri));
		GeneralNames gns = new GeneralNames(gn);
		DistributionPointName dpn = new DistributionPointName(0, gns);
		return new DistributionPoint(dpn, null, null);
	}

	public static OCSPResp createOcspResp(X509Certificate certificate,
			boolean revoked, X509Certificate issuerCertificate,
			X509Certificate ocspResponderCertificate,
			PrivateKey ocspResponderPrivateKey) throws Exception {
		return createOcspResp(certificate, revoked, issuerCertificate,
				ocspResponderCertificate, ocspResponderPrivateKey,
				"SHA1WITHRSA");
	}

	public static OCSPResp createOcspResp(X509Certificate certificate,
			boolean revoked, X509Certificate issuerCertificate,
			X509Certificate ocspResponderCertificate,
			PrivateKey ocspResponderPrivateKey, String signatureAlgorithm)
			throws Exception {
		// request
        OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();
        DigestCalculatorProvider
                digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build();
        CertificateID certId = new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1),
                new JcaX509CertificateHolder(issuerCertificate), certificate.getSerialNumber());
        ocspReqBuilder.addRequest(certId);
		OCSPReq ocspReq = ocspReqBuilder.build();
        BasicOCSPRespBuilder basicOCSPRespBuilder = new JcaBasicOCSPRespBuilder(ocspResponderCertificate.getPublicKey(), digCalcProv.get(CertificateID.HASH_SHA1));

		// request processing
		Req[] requestList = ocspReq.getRequestList();
		for (Req ocspRequest : requestList) {
			CertificateID certificateID = ocspRequest.getCertID();
			CertificateStatus certificateStatus;
			if (revoked) {
				certificateStatus = new RevokedStatus(new Date(),
						CRLReason.unspecified);
			} else {
				certificateStatus = CertificateStatus.GOOD;
			}
            basicOCSPRespBuilder
					.addResponse(certificateID, certificateStatus);
		}

		// basic response generation
        X509CertificateHolder[] chain = null;
		if (!ocspResponderCertificate.equals(issuerCertificate)) {
			chain = new X509CertificateHolder[] { new X509CertificateHolder(ocspResponderCertificate.getEncoded()),
					new X509CertificateHolder(issuerCertificate.getEncoded()) };
		}

        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(ocspResponderPrivateKey);
		BasicOCSPResp basicOCSPResp = basicOCSPRespBuilder.build(contentSigner, chain, new Date());

		// response generation
        OCSPRespBuilder ocspRespBuilder = new OCSPRespBuilder();
		OCSPResp ocspResp = ocspRespBuilder.build(
                OCSPRespBuilder.SUCCESSFUL, basicOCSPResp);

		return ocspResp;
	}

	public static OCSPResp createOcspResp(X509Certificate certificate,
			boolean revoked, X509Certificate issuerCertificate,
			X509Certificate ocspResponderCertificate,
			PrivateKey ocspResponderPrivateKey, String signatureAlgorithm,
			List<X509Certificate> ocspResponderCertificateChain)
			throws Exception {
		// request
        OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();
        DigestCalculatorProvider
                digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build();
        CertificateID certId = new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1),
                new JcaX509CertificateHolder(issuerCertificate), certificate.getSerialNumber());
        ocspReqBuilder.addRequest(certId);
        OCSPReq ocspReq = ocspReqBuilder.build();
        BasicOCSPRespBuilder basicOCSPRespBuilder = new JcaBasicOCSPRespBuilder(ocspResponderCertificate.getPublicKey(), digCalcProv.get(CertificateID.HASH_SHA1));

		// request processing
		Req[] requestList = ocspReq.getRequestList();
		for (Req ocspRequest : requestList) {
			CertificateID certificateID = ocspRequest.getCertID();
			CertificateStatus certificateStatus;
			if (revoked) {
				certificateStatus = new RevokedStatus(new Date(),
						CRLReason.unspecified);
			} else {
				certificateStatus = CertificateStatus.GOOD;
			}
            basicOCSPRespBuilder
					.addResponse(certificateID, certificateStatus);
		}

		// basic response generation
        X509CertificateHolder[] chain;
		if (ocspResponderCertificateChain.isEmpty()) {
			chain = null;
		} else {
            chain = new X509CertificateHolder[ocspResponderCertificateChain.size()];
            for (int idx = 0; idx < chain.length; idx++) {
                chain[idx] = new X509CertificateHolder(ocspResponderCertificateChain.get(idx).getEncoded());
            }
        }

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA").build(ocspResponderPrivateKey);
        BasicOCSPResp basicOCSPResp = basicOCSPRespBuilder.build(contentSigner, chain, new Date());

        // response generation
        OCSPRespBuilder ocspRespBuilder = new OCSPRespBuilder();
        OCSPResp ocspResp = ocspRespBuilder.build(
                OCSPRespBuilder.SUCCESSFUL, basicOCSPResp);

		return ocspResp;
	}

	public static TimeStampToken createTimeStampToken(PrivateKey privateKey,
			List<X509Certificate> certificateChain) throws Exception {

		CollectionCertStoreParameters collectionCertStoreParameters = new CollectionCertStoreParameters(
				certificateChain);
		CertStore certStore = CertStore.getInstance("Collection",
				collectionCertStoreParameters);

		TimeStampRequestGenerator requestGen = new TimeStampRequestGenerator();
		requestGen.setCertReq(true);
		TimeStampRequest request = requestGen.generate(TSPAlgorithms.SHA1,
				new byte[20], BigInteger.valueOf(100));

		TimeStampTokenGenerator tstGen = new TimeStampTokenGenerator(
				privateKey, certificateChain.get(0), TSPAlgorithms.SHA1, "1.2");
		tstGen.setCertificatesAndCRLs(certStore);
		return tstGen.generate(request, BigInteger.ONE, new Date(), "BC");
	}

    public static X509Certificate loadCertificate(String resourceName) throws CertificateException {
        InputStream inputStream = TrustTestUtils.class.getResourceAsStream(resourceName);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
        return certificate;
    }
}
