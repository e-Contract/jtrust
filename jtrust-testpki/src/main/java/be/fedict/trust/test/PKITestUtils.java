/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
 * Copyright (C) 2014-2023 e-Contract.be BV.
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
package be.fedict.trust.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenGenerator;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @deprecated
 */
public class PKITestUtils {

	private static final Logger LOGGER = LoggerFactory.getLogger(PKITestUtils.class);

	public static X509Certificate generateCertificate(PublicKey subjectPublicKey, String subjectDn,
			LocalDateTime notBefore, LocalDateTime notAfter, X509Certificate issuerCertificate,
			PrivateKey issuerPrivateKey) throws IOException, InvalidKeyException, IllegalStateException,
			NoSuchAlgorithmException, SignatureException, CertificateException, OperatorCreationException {
		return generateCertificate(subjectPublicKey, subjectDn, notBefore, notAfter, issuerCertificate,
				issuerPrivateKey, true);
	}

	public static X509Certificate generateCertificate(PublicKey subjectPublicKey, String subjectDn,
			LocalDateTime notBefore, LocalDateTime notAfter, X509Certificate issuerCertificate,
			PrivateKey issuerPrivateKey, boolean caFlag) throws IOException, InvalidKeyException, IllegalStateException,
			NoSuchAlgorithmException, SignatureException, CertificateException, OperatorCreationException {
		return generateCertificate(subjectPublicKey, subjectDn, notBefore, notAfter, issuerCertificate,
				issuerPrivateKey, caFlag, -1);
	}

	public static X509Certificate generateCertificate(PublicKey subjectPublicKey, String subjectDn,
			LocalDateTime notBefore, LocalDateTime notAfter, X509Certificate issuerCertificate,
			PrivateKey issuerPrivateKey, boolean caFlag, int pathLength)
			throws IOException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException,
			SignatureException, CertificateException, OperatorCreationException {
		return generateCertificate(subjectPublicKey, subjectDn, notBefore, notAfter, issuerCertificate,
				issuerPrivateKey, caFlag, pathLength, null);
	}

	public static X509Certificate generateCertificate(PublicKey subjectPublicKey, String subjectDn,
			LocalDateTime notBefore, LocalDateTime notAfter, X509Certificate issuerCertificate,
			PrivateKey issuerPrivateKey, boolean caFlag, int pathLength, String crlUri)
			throws IOException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException,
			SignatureException, CertificateException, OperatorCreationException {
		return generateCertificate(subjectPublicKey, subjectDn, notBefore, notAfter, issuerCertificate,
				issuerPrivateKey, caFlag, pathLength, crlUri, null);
	}

	public static X509Certificate generateCertificate(PublicKey subjectPublicKey, String subjectDn,
			LocalDateTime notBefore, LocalDateTime notAfter, X509Certificate issuerCertificate,
			PrivateKey issuerPrivateKey, boolean caFlag, int pathLength, String crlUri, String ocspUri)
			throws IOException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException,
			SignatureException, CertificateException, OperatorCreationException {
		String signatureAlgorithm;
		if (issuerCertificate.getPublicKey().getAlgorithm().contains("RSA")) {
			signatureAlgorithm = "SHA256withRSA";
		} else {
			signatureAlgorithm = "SHA256withECDSA";
		}
		X509Certificate certificate = generateCertificate(subjectPublicKey, subjectDn, notBefore, notAfter,
				issuerCertificate, issuerPrivateKey, caFlag, pathLength, crlUri, ocspUri, null, signatureAlgorithm);
		return certificate;
	}

	public static X509Certificate generateCertificate(PublicKey subjectPublicKey, String subjectDn,
			LocalDateTime notBefore, LocalDateTime notAfter, X509Certificate issuerCertificate,
			PrivateKey issuerPrivateKey, boolean caFlag, int pathLength, String crlUri, String ocspUri,
			KeyUsage keyUsage, String signatureAlgorithm)
			throws IOException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException,
			SignatureException, CertificateException, OperatorCreationException {

		return generateCertificate(subjectPublicKey, subjectDn, notBefore, notAfter, issuerCertificate,
				issuerPrivateKey, caFlag, pathLength, crlUri, ocspUri, keyUsage, signatureAlgorithm, false);
	}

	public static X509Certificate generateCertificate(PublicKey subjectPublicKey, String subjectDn,
			LocalDateTime notBefore, LocalDateTime notAfter, X509Certificate issuerCertificate,
			PrivateKey issuerPrivateKey, boolean caFlag, int pathLength, String crlUri, String ocspUri,
			KeyUsage keyUsage, String signatureAlgorithm, boolean tsa)
			throws IOException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException,
			SignatureException, CertificateException, OperatorCreationException {

		return generateCertificate(subjectPublicKey, subjectDn, notBefore, notAfter, issuerCertificate,
				issuerPrivateKey, caFlag, pathLength, crlUri, ocspUri, keyUsage, signatureAlgorithm, tsa, true, true);
	}

	public static X509Certificate generateCertificate(PublicKey subjectPublicKey, String subjectDn,
			LocalDateTime notBefore, LocalDateTime notAfter, X509Certificate issuerCertificate,
			PrivateKey issuerPrivateKey, boolean caFlag, int pathLength, String crlUri, String ocspUri,
			KeyUsage keyUsage, String signatureAlgorithm, boolean tsa, boolean includeSKID, boolean includeAKID)
			throws IOException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException,
			SignatureException, CertificateException, OperatorCreationException {

		return generateCertificate(subjectPublicKey, subjectDn, notBefore, notAfter, issuerCertificate,
				issuerPrivateKey, caFlag, pathLength, crlUri, ocspUri, keyUsage, signatureAlgorithm, tsa, includeSKID,
				includeAKID, null);
	}

	public static X509Certificate generateCertificate(PublicKey subjectPublicKey, String subjectDn,
			LocalDateTime notBefore, LocalDateTime notAfter, X509Certificate issuerCertificate,
			PrivateKey issuerPrivateKey, boolean caFlag, int pathLength, String crlUri, String ocspUri,
			KeyUsage keyUsage, String signatureAlgorithm, boolean tsa, boolean includeSKID, boolean includeAKID,
			PublicKey akidPublicKey) throws IOException, InvalidKeyException, IllegalStateException,
			NoSuchAlgorithmException, SignatureException, CertificateException, OperatorCreationException {

		return generateCertificate(subjectPublicKey, subjectDn, notBefore, notAfter, issuerCertificate,
				issuerPrivateKey, caFlag, pathLength, crlUri, ocspUri, keyUsage, signatureAlgorithm, tsa, includeSKID,
				includeAKID, akidPublicKey, null);
	}

	public static X509Certificate generateCertificate(PublicKey subjectPublicKey, String subjectDn,
			LocalDateTime notBefore, LocalDateTime notAfter, X509Certificate issuerCertificate,
			PrivateKey issuerPrivateKey, boolean caFlag, int pathLength, String crlUri, String ocspUri,
			KeyUsage keyUsage, String signatureAlgorithm, boolean tsa, boolean includeSKID, boolean includeAKID,
			PublicKey akidPublicKey, String certificatePolicy)
			throws IOException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException,
			SignatureException, CertificateException, OperatorCreationException {

		return generateCertificate(subjectPublicKey, subjectDn, notBefore, notAfter, issuerCertificate,
				issuerPrivateKey, caFlag, pathLength, crlUri, ocspUri, keyUsage, signatureAlgorithm, tsa, includeSKID,
				includeAKID, akidPublicKey, certificatePolicy, null);
	}

	public static X509Certificate generateCertificate(PublicKey subjectPublicKey, String subjectDn,
			LocalDateTime notBefore, LocalDateTime notAfter, X509Certificate issuerCertificate,
			PrivateKey issuerPrivateKey, boolean caFlag, int pathLength, String crlUri, String ocspUri,
			KeyUsage keyUsage, String signatureAlgorithm, boolean tsa, boolean includeSKID, boolean includeAKID,
			PublicKey akidPublicKey, String certificatePolicy, Boolean qcCompliance)
			throws IOException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException,
			SignatureException, CertificateException, OperatorCreationException {

		return generateCertificate(subjectPublicKey, subjectDn, notBefore, notAfter, issuerCertificate,
				issuerPrivateKey, caFlag, pathLength, crlUri, ocspUri, keyUsage, signatureAlgorithm, tsa, includeSKID,
				includeAKID, akidPublicKey, certificatePolicy, qcCompliance, false);
	}

	public static X509Certificate generateCertificate(PublicKey subjectPublicKey, String subjectDn,
			LocalDateTime notBefore, LocalDateTime notAfter, X509Certificate issuerCertificate,
			PrivateKey issuerPrivateKey, boolean caFlag, int pathLength, String crlUri, String ocspUri,
			KeyUsage keyUsage, String signatureAlgorithm, boolean tsa, boolean includeSKID, boolean includeAKID,
			PublicKey akidPublicKey, String certificatePolicy, Boolean qcCompliance, boolean ocspResponder)
			throws IOException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException,
			SignatureException, CertificateException, OperatorCreationException {
		return generateCertificate(subjectPublicKey, subjectDn, notBefore, notAfter, issuerCertificate,
				issuerPrivateKey, caFlag, pathLength, crlUri, ocspUri, keyUsage, signatureAlgorithm, tsa, includeSKID,
				includeAKID, akidPublicKey, certificatePolicy, qcCompliance, ocspResponder, false);
	}

	public static X509Certificate generateCertificate(PublicKey subjectPublicKey, String subjectDn,
			LocalDateTime notBefore, LocalDateTime notAfter, X509Certificate issuerCertificate,
			PrivateKey issuerPrivateKey, boolean caFlag, int pathLength, String crlUri, String ocspUri,
			KeyUsage keyUsage, String signatureAlgorithm, boolean tsa, boolean includeSKID, boolean includeAKID,
			PublicKey akidPublicKey, String certificatePolicy, Boolean qcCompliance, boolean ocspResponder,
			boolean qcSSCD) throws IOException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException,
			SignatureException, CertificateException, OperatorCreationException {

		X500Name issuerName;
		if (null != issuerCertificate) {
			issuerName = new X500Name(issuerCertificate.getSubjectX500Principal().toString());
		} else {
			issuerName = new X500Name(subjectDn);
		}
		X500Name subjectName = new X500Name(subjectDn);
		BigInteger serial = new BigInteger(128, new SecureRandom());
		SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(subjectPublicKey.getEncoded());
		X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(issuerName, serial,
				Date.from(notBefore.atZone(ZoneId.systemDefault()).toInstant()),
				Date.from(notAfter.atZone(ZoneId.systemDefault()).toInstant()), subjectName, publicKeyInfo);

		JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
		if (includeSKID) {
			x509v3CertificateBuilder.addExtension(Extension.subjectKeyIdentifier, false,
					extensionUtils.createSubjectKeyIdentifier(subjectPublicKey));
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
			x509v3CertificateBuilder.addExtension(Extension.authorityKeyIdentifier, false,
					extensionUtils.createAuthorityKeyIdentifier(authorityPublicKey));
		}

		if (caFlag) {
			if (-1 == pathLength) {
				x509v3CertificateBuilder.addExtension(Extension.basicConstraints, true,
						new BasicConstraints(2147483647));
			} else {
				x509v3CertificateBuilder.addExtension(Extension.basicConstraints, true,
						new BasicConstraints(pathLength));
			}
		}

		if (null != crlUri) {
			GeneralName generalName = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(crlUri));
			GeneralNames generalNames = new GeneralNames(generalName);
			DistributionPointName distPointName = new DistributionPointName(generalNames);
			DistributionPoint distPoint = new DistributionPoint(distPointName, null, null);
			DistributionPoint[] crlDistPoints = new DistributionPoint[] { distPoint };
			CRLDistPoint crlDistPoint = new CRLDistPoint(crlDistPoints);
			x509v3CertificateBuilder.addExtension(Extension.cRLDistributionPoints, false, crlDistPoint);
		}

		if (null != ocspUri) {
			GeneralName ocspName = new GeneralName(GeneralName.uniformResourceIdentifier, ocspUri);
			AuthorityInformationAccess authorityInformationAccess = new AuthorityInformationAccess(
					X509ObjectIdentifiers.ocspAccessMethod, ocspName);
			x509v3CertificateBuilder.addExtension(Extension.authorityInfoAccess, false, authorityInformationAccess);
		}

		if (null != keyUsage) {
			x509v3CertificateBuilder.addExtension(Extension.keyUsage, true, keyUsage);
		}

		if (null != certificatePolicy) {
			ASN1ObjectIdentifier policyObjectIdentifier = new ASN1ObjectIdentifier(certificatePolicy);
			PolicyInformation policyInformation = new PolicyInformation(policyObjectIdentifier);
			x509v3CertificateBuilder.addExtension(Extension.certificatePolicies, false,
					new DERSequence(policyInformation));
		}

		if (null != qcCompliance) {
			ASN1EncodableVector vec = new ASN1EncodableVector();
			if (qcCompliance) {
				vec.add(new QCStatement(QCStatement.id_etsi_qcs_QcCompliance));
			} else {
				vec.add(new QCStatement(QCStatement.id_etsi_qcs_RetentionPeriod));
			}
			if (qcSSCD) {
				vec.add(new QCStatement(QCStatement.id_etsi_qcs_QcSSCD));
			}
			x509v3CertificateBuilder.addExtension(Extension.qCStatements, true, new DERSequence(vec));

		}

		if (tsa) {
			x509v3CertificateBuilder.addExtension(Extension.extendedKeyUsage, true,
					new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));
		}

		if (ocspResponder) {
			x509v3CertificateBuilder.addExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck, false, DERNull.INSTANCE);

			x509v3CertificateBuilder.addExtension(Extension.extendedKeyUsage, true,
					new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning));
		}

		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(signatureAlgorithm);
		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
		AsymmetricKeyParameter asymmetricKeyParameter = PrivateKeyFactory.createKey(issuerPrivateKey.getEncoded());

		ContentSigner contentSigner;
		LOGGER.debug("signature algo: {}", signatureAlgorithm);
		if (signatureAlgorithm.contains("RSA")) {
			contentSigner = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(asymmetricKeyParameter);
		} else {
			contentSigner = new BcECContentSignerBuilder(sigAlgId, digAlgId).build(asymmetricKeyParameter);
		}
		X509CertificateHolder x509CertificateHolder = x509v3CertificateBuilder.build(contentSigner);

		byte[] encodedCertificate = x509CertificateHolder.getEncoded();

		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		X509Certificate certificate = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(encodedCertificate));
		return certificate;
	}

	public static KeyPair generateKeyPair() throws Exception {
		return generateKeyPair(1024);
	}

	public static KeyPair generateKeyPair(String keyAlgorithm) throws Exception {
		return generateKeyPair(1024, keyAlgorithm);
	}

	public static KeyPair generateKeyPair(int keySize) throws Exception {
		return generateKeyPair(keySize, "RSA");
	}

	public static KeyPair generateKeyPair(int keySize, String keyAlgorithm) throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyAlgorithm);
		SecureRandom random = new SecureRandom();
		if ("RSA".equals(keyAlgorithm)) {
			keyPairGenerator.initialize(new RSAKeyGenParameterSpec(keySize, RSAKeyGenParameterSpec.F4), random);
		} else {
			keyPairGenerator.initialize(new ECGenParameterSpec("secp384r1"));
		}
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return keyPair;
	}

	public static X509Certificate generateSelfSignedCertificate(KeyPair keyPair, String subjectDn,
			LocalDateTime notBefore, LocalDateTime notAfter, boolean caFlag, int pathLength, String crlUri)
			throws IOException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException,
			SignatureException, CertificateException, OperatorCreationException {
		return generateSelfSignedCertificate(keyPair, subjectDn, notBefore, notAfter, caFlag, pathLength, crlUri, null);
	}

	public static X509Certificate generateSelfSignedCertificate(KeyPair keyPair, String subjectDn,
			LocalDateTime notBefore, LocalDateTime notAfter, boolean caFlag, int pathLength, String crlUri,
			KeyUsage keyUsage) throws IOException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException,
			SignatureException, CertificateException, OperatorCreationException {
		PublicKey subjectPublicKey = keyPair.getPublic();
		PrivateKey issuerPrivateKey = keyPair.getPrivate();
		String signatureAlgorithm;
		if (issuerPrivateKey.getAlgorithm().contains("RSA")) {
			signatureAlgorithm = "SHA256withRSA";
		} else {
			signatureAlgorithm = "SHA256withECDSA";
		}
		LOGGER.debug("signature algorithm: {}", signatureAlgorithm);
		X509Certificate certificate = generateCertificate(subjectPublicKey, subjectDn, notBefore, notAfter, null,
				issuerPrivateKey, caFlag, pathLength, crlUri, null, keyUsage, signatureAlgorithm);
		return certificate;
	}

	public static X509Certificate generateSelfSignedCertificate(KeyPair keyPair, String subjectDn,
			LocalDateTime notBefore, LocalDateTime notAfter, boolean caFlag, int pathLength, String crlUri,
			KeyUsage keyUsage, String signatureAlgorithm)
			throws IOException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException,
			SignatureException, CertificateException, OperatorCreationException {
		PublicKey subjectPublicKey = keyPair.getPublic();
		PrivateKey issuerPrivateKey = keyPair.getPrivate();
		X509Certificate certificate = generateCertificate(subjectPublicKey, subjectDn, notBefore, notAfter, null,
				issuerPrivateKey, caFlag, pathLength, crlUri, null, keyUsage, signatureAlgorithm);
		return certificate;
	}

	public static X509Certificate generateSelfSignedCertificate(KeyPair keyPair, String subjectDn,
			LocalDateTime notBefore, LocalDateTime notAfter, boolean caFlag, int pathLength)
			throws IOException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException,
			SignatureException, CertificateException, OperatorCreationException {
		return generateSelfSignedCertificate(keyPair, subjectDn, notBefore, notAfter, caFlag, pathLength, null);
	}

	public static X509Certificate generateSelfSignedCertificate(KeyPair keyPair, String subjectDn,
			LocalDateTime notBefore, LocalDateTime notAfter, boolean caFlag)
			throws IOException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException,
			SignatureException, CertificateException, OperatorCreationException {
		return generateSelfSignedCertificate(keyPair, subjectDn, notBefore, notAfter, caFlag, -1);
	}

	public static X509Certificate generateSelfSignedCertificate(KeyPair keyPair, String subjectDn,
			LocalDateTime notBefore, LocalDateTime notAfter, String crlUri)
			throws IOException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException,
			SignatureException, CertificateException, OperatorCreationException {
		return generateSelfSignedCertificate(keyPair, subjectDn, notBefore, notAfter, true, -1, crlUri);
	}

	public static X509Certificate generateSelfSignedCertificate(KeyPair keyPair, String subjectDn,
			LocalDateTime notBefore, LocalDateTime notAfter)
			throws IOException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException,
			SignatureException, CertificateException, OperatorCreationException {
		return generateSelfSignedCertificate(keyPair, subjectDn, notBefore, notAfter, true);
	}

	public static class RevokedCertificate {

		private final BigInteger serialNumber;
		private final LocalDateTime revocationDate;

		public RevokedCertificate(BigInteger serialNumber, LocalDateTime revocationDate) {
			this.serialNumber = serialNumber;
			this.revocationDate = revocationDate;
		}
	}

	public static X509CRL generateCrl(PrivateKey issuerPrivateKey, X509Certificate issuerCertificate,
			LocalDateTime thisUpdate, LocalDateTime nextUpdate, BigInteger... revokedCertificateSerialNumbers)
			throws InvalidKeyException, CRLException, IllegalStateException, NoSuchAlgorithmException,
			SignatureException, CertificateException, OperatorCreationException, IOException {

		return generateCrl(issuerPrivateKey, issuerCertificate, thisUpdate, nextUpdate, "SHA1withRSA",
				revokedCertificateSerialNumbers);
	}

	public static X509CRL generateCrl(PrivateKey issuerPrivateKey, X509Certificate issuerCertificate,
			LocalDateTime thisUpdate, LocalDateTime nextUpdate, String signatureAlgorithm,
			BigInteger... revokedCertificateSerialNumbers)
			throws InvalidKeyException, CRLException, IllegalStateException, NoSuchAlgorithmException,
			SignatureException, CertificateException, OperatorCreationException, IOException {

		List<RevokedCertificate> revokedCertificates = new LinkedList<>();
		for (BigInteger revokedCertificateSerialNumber : revokedCertificateSerialNumbers) {
			revokedCertificates.add(new RevokedCertificate(revokedCertificateSerialNumber, thisUpdate));
		}
		return generateCrl(issuerPrivateKey, issuerCertificate, thisUpdate, nextUpdate, null, false,
				revokedCertificates, signatureAlgorithm);
	}

	public static X509CRL generateCrl(PrivateKey issuerPrivateKey, X509Certificate issuerCertificate,
			LocalDateTime thisUpdate, LocalDateTime nextUpdate, List<RevokedCertificate> revokedCertificates)
			throws InvalidKeyException, CRLException, IllegalStateException, NoSuchAlgorithmException,
			SignatureException, CertificateException, OperatorCreationException, IOException {

		return generateCrl(issuerPrivateKey, issuerCertificate, thisUpdate, nextUpdate, null, false,
				revokedCertificates, "SHA1withRSA");
	}

	public static X509CRL generateCrl(PrivateKey issuerPrivateKey, X509Certificate issuerCertificate,
			LocalDateTime thisUpdate, LocalDateTime nextUpdate, List<String> deltaCrlUris,
			List<RevokedCertificate> revokedCertificates)
			throws InvalidKeyException, CRLException, IllegalStateException, NoSuchAlgorithmException,
			SignatureException, CertificateException, OperatorCreationException, IOException {

		return generateCrl(issuerPrivateKey, issuerCertificate, thisUpdate, nextUpdate, deltaCrlUris, false,
				revokedCertificates, "SHA1withRSA");
	}

	public static X509CRL generateCrl(PrivateKey issuerPrivateKey, X509Certificate issuerCertificate,
			LocalDateTime thisUpdate, LocalDateTime nextUpdate, List<String> deltaCrlUris, boolean deltaCrl,
			List<RevokedCertificate> revokedCertificates)
			throws InvalidKeyException, CRLException, IllegalStateException, NoSuchAlgorithmException,
			SignatureException, CertificateException, OperatorCreationException, IOException {

		return generateCrl(issuerPrivateKey, issuerCertificate, thisUpdate, nextUpdate, deltaCrlUris, deltaCrl,
				revokedCertificates, "SHA1withRSA");
	}

	public static X509CRL generateCrl(PrivateKey issuerPrivateKey, X509Certificate issuerCertificate,
			LocalDateTime thisUpdate, LocalDateTime nextUpdate, List<String> deltaCrlUris, boolean deltaCrl,
			List<RevokedCertificate> revokedCertificates, String signatureAlgorithm)
			throws InvalidKeyException, CRLException, IllegalStateException, NoSuchAlgorithmException,
			SignatureException, CertificateException, IOException, OperatorCreationException {
		return generateCrl(issuerPrivateKey, issuerCertificate, thisUpdate, nextUpdate, deltaCrlUris, deltaCrl,
				revokedCertificates, signatureAlgorithm, -1);
	}

	public static X509CRL generateCrl(PrivateKey issuerPrivateKey, X509Certificate issuerCertificate,
			LocalDateTime thisUpdate, LocalDateTime nextUpdate, List<String> deltaCrlUris, boolean deltaCrl,
			List<RevokedCertificate> revokedCertificates, String signatureAlgorithm, long numberOfRevokedCertificates)
			throws InvalidKeyException, CRLException, IllegalStateException, NoSuchAlgorithmException,
			SignatureException, CertificateException, IOException, OperatorCreationException {

		X500Name issuerName = new X500Name(issuerCertificate.getSubjectX500Principal().toString());
		X509v2CRLBuilder x509v2crlBuilder = new X509v2CRLBuilder(issuerName,
				Date.from(thisUpdate.atZone(ZoneId.systemDefault()).toInstant()));
		x509v2crlBuilder.setNextUpdate(Date.from(nextUpdate.atZone(ZoneId.systemDefault()).toInstant()));

		for (RevokedCertificate revokedCertificate : revokedCertificates) {
			x509v2crlBuilder.addCRLEntry(revokedCertificate.serialNumber,
					Date.from(revokedCertificate.revocationDate.atZone(ZoneId.systemDefault()).toInstant()),
					CRLReason.privilegeWithdrawn);
		}
		if (-1 != numberOfRevokedCertificates) {
			SecureRandom secureRandom = new SecureRandom();
			while (numberOfRevokedCertificates-- > 0) {
				BigInteger serialNumber = new BigInteger(128, secureRandom);
				Date revocationDate = new Date();
				x509v2crlBuilder.addCRLEntry(serialNumber, revocationDate, CRLReason.privilegeWithdrawn);
			}
		}

		JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
		x509v2crlBuilder.addExtension(Extension.authorityKeyIdentifier, false,
				extensionUtils.createAuthorityKeyIdentifier(issuerCertificate));
		x509v2crlBuilder.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.ONE));

		if (null != deltaCrlUris && !deltaCrlUris.isEmpty()) {
			DistributionPoint[] deltaCrlDps = new DistributionPoint[deltaCrlUris.size()];
			for (int i = 0; i < deltaCrlUris.size(); i++) {
				deltaCrlDps[i] = getDistributionPoint(deltaCrlUris.get(i));
			}
			CRLDistPoint crlDistPoint = new CRLDistPoint((DistributionPoint[]) deltaCrlDps);
			x509v2crlBuilder.addExtension(Extension.freshestCRL, false, crlDistPoint);
		}

		if (deltaCrl) {
			x509v2crlBuilder.addExtension(Extension.deltaCRLIndicator, true, new CRLNumber(BigInteger.ONE));
		}

		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(signatureAlgorithm);
		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
		AsymmetricKeyParameter asymmetricKeyParameter = PrivateKeyFactory.createKey(issuerPrivateKey.getEncoded());

		ContentSigner contentSigner = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(asymmetricKeyParameter);

		X509CRLHolder x509crlHolder = x509v2crlBuilder.build(contentSigner);
		byte[] crlValue = x509crlHolder.getEncoded();
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		X509CRL crl = (X509CRL) certificateFactory.generateCRL(new ByteArrayInputStream(crlValue));
		return crl;
	}

	public static DistributionPoint getDistributionPoint(String uri) {
		GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(uri));
		GeneralNames gns = new GeneralNames(gn);
		DistributionPointName dpn = new DistributionPointName(0, gns);
		return new DistributionPoint(dpn, null, null);
	}

	public static OCSPResp createOcspResp(X509Certificate certificate, boolean revoked,
			X509Certificate issuerCertificate, X509Certificate ocspResponderCertificate,
			PrivateKey ocspResponderPrivateKey) throws Exception {
		return createOcspResp(certificate, revoked, issuerCertificate, ocspResponderCertificate,
				ocspResponderPrivateKey, "SHA1WITHRSA");
	}

	public static OCSPResp createOcspResp(X509Certificate certificate, boolean revoked,
			X509Certificate issuerCertificate, X509Certificate ocspResponderCertificate,
			PrivateKey ocspResponderPrivateKey, String signatureAlgorithm) throws Exception {
		// request
		OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();
		DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder()
				.setProvider(BouncyCastleProvider.PROVIDER_NAME).build();
		CertificateID certId = new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1),
				new JcaX509CertificateHolder(issuerCertificate), certificate.getSerialNumber());
		ocspReqBuilder.addRequest(certId);
		OCSPReq ocspReq = ocspReqBuilder.build();
		BasicOCSPRespBuilder basicOCSPRespBuilder = new JcaBasicOCSPRespBuilder(ocspResponderCertificate.getPublicKey(),
				digCalcProv.get(CertificateID.HASH_SHA1));

		// request processing
		Req[] requestList = ocspReq.getRequestList();
		for (Req ocspRequest : requestList) {
			CertificateID certificateID = ocspRequest.getCertID();
			CertificateStatus certificateStatus;
			if (revoked) {
				certificateStatus = new RevokedStatus(new Date(), CRLReason.unspecified);
			} else {
				certificateStatus = CertificateStatus.GOOD;
			}
			basicOCSPRespBuilder.addResponse(certificateID, certificateStatus);
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
		OCSPResp ocspResp = ocspRespBuilder.build(OCSPRespBuilder.SUCCESSFUL, basicOCSPResp);

		return ocspResp;
	}

	public static OCSPResp createOcspResp(X509Certificate certificate, boolean revoked,
			X509Certificate issuerCertificate, X509Certificate ocspResponderCertificate,
			PrivateKey ocspResponderPrivateKey, String signatureAlgorithm,
			List<X509Certificate> ocspResponderCertificateChain) throws Exception {
		// request
		OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();
		DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder()
				.setProvider(BouncyCastleProvider.PROVIDER_NAME).build();
		CertificateID certId = new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1),
				new JcaX509CertificateHolder(issuerCertificate), certificate.getSerialNumber());
		ocspReqBuilder.addRequest(certId);
		OCSPReq ocspReq = ocspReqBuilder.build();
		BasicOCSPRespBuilder basicOCSPRespBuilder = new JcaBasicOCSPRespBuilder(ocspResponderCertificate.getPublicKey(),
				digCalcProv.get(CertificateID.HASH_SHA1));

		// request processing
		Req[] requestList = ocspReq.getRequestList();
		for (Req ocspRequest : requestList) {
			CertificateID certificateID = ocspRequest.getCertID();
			CertificateStatus certificateStatus;
			if (revoked) {
				certificateStatus = new RevokedStatus(new Date(), CRLReason.unspecified);
			} else {
				certificateStatus = CertificateStatus.GOOD;
			}
			basicOCSPRespBuilder.addResponse(certificateID, certificateStatus);
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
		OCSPResp ocspResp = ocspRespBuilder.build(OCSPRespBuilder.SUCCESSFUL, basicOCSPResp);

		return ocspResp;
	}

	public static TimeStampToken createTimeStampToken(PrivateKey privateKey, List<X509Certificate> certificateChain)
			throws Exception {

		Store certs = new JcaCertStore(certificateChain);

		TimeStampRequestGenerator requestGen = new TimeStampRequestGenerator();
		requestGen.setCertReq(true);
		TimeStampRequest request = requestGen.generate(TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));

		TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
				new JcaSimpleSignerInfoGeneratorBuilder().build("SHA1withRSA", privateKey, certificateChain.get(0)),
				new JcaDigestCalculatorProviderBuilder().build()
						.get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)),
				new ASN1ObjectIdentifier("1.2"));

		tsTokenGen.addCertificates(certs);
		return tsTokenGen.generate(request, BigInteger.ONE, new Date());
	}

	public static X509Certificate loadCertificate(String resourceName) throws CertificateException {
		InputStream inputStream = PKITestUtils.class.getResourceAsStream(resourceName);
		if (null == inputStream) {
			throw new IllegalArgumentException("unknown resource: " + resourceName);
		}
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
		return certificate;
	}
}
