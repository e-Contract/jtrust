/*
 * Java Trust Project.
 * Copyright (C) 2023 e-Contract.be BV.
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
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
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
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
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

/**
 * Builder for PKI artifacts like certificates, CRLs, and OCSP responses.
 * 
 * @author Frank Cornelis
 *
 */
public class PKIBuilder {

	private PKIBuilder() {

	}

	/**
	 * Builder for key pairs.
	 * 
	 * @author Frank Cornelis
	 *
	 */
	public static class KeyPairBuilder {

		private String keyAlgorithm = "RSA";

		private int keySize = 1024;

		/**
		 * Sets the key algorithm. Defaults to RSA.
		 * 
		 * @param keyAlgorithm RSA or EC
		 * @return
		 */
		public KeyPairBuilder withKeyAlgorithm(String keyAlgorithm) {
			this.keyAlgorithm = keyAlgorithm;
			return this;
		}

		public KeyPairBuilder withKeySize(int keySize) {
			this.keySize = keySize;
			return this;
		}

		public KeyPair build() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(this.keyAlgorithm);
			SecureRandom random = new SecureRandom();
			if ("RSA".equals(this.keyAlgorithm)) {
				keyPairGenerator.initialize(new RSAKeyGenParameterSpec(this.keySize, RSAKeyGenParameterSpec.F4),
						random);
			} else {
				keyPairGenerator.initialize(new ECGenParameterSpec("secp384r1"));
			}
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			return keyPair;
		}
	}

	/**
	 * Builder for X509 certificates.
	 * 
	 * @author Frank Cornelis
	 *
	 */
	public static class CertificateBuilder {

		private final PublicKey subjectPublicKey;
		private final PrivateKey issuerPrivateKey;
		private final X509Certificate issuerCertificate;

		private String subjectDn = "CN=Test";
		private LocalDateTime notBefore = LocalDateTime.now();
		private LocalDateTime notAfter = LocalDateTime.now().plusYears(10);
		private boolean includeSKID;
		private boolean includeAKID;
		private PublicKey akidPublicKey;
		private boolean basicConstraints;
		private boolean basicConstraintsCA;
		private Integer pathLength;
		private String crlUri;
		private String ocspUri;
		private Integer keyUsage;
		private String certificatePolicy;
		private boolean qcCompliance;
		private boolean qcRetentionPeriod;
		private boolean qcSSCD;
		private boolean qCStatements;
		private boolean timeStamping;
		private boolean extendedKeyUsage;
		private boolean ocspResponder;
		private String signatureAlgorithm;

		public CertificateBuilder(PublicKey subjectPublicKey, PrivateKey issuerPrivateKey) {
			this(subjectPublicKey, issuerPrivateKey, null);
		}

		public CertificateBuilder(PublicKey subjectPublicKey, PrivateKey issuerPrivateKey,
				X509Certificate issuerCertificate) {
			this.issuerPrivateKey = issuerPrivateKey;
			this.issuerCertificate = issuerCertificate;
			this.subjectPublicKey = subjectPublicKey;
		}

		/**
		 * Constructor for self-signed certificates.
		 * 
		 * @param keyPair
		 */
		public CertificateBuilder(KeyPair keyPair) {
			this(keyPair.getPublic(), keyPair.getPrivate(), null);
		}

		public CertificateBuilder withSubjectName(String subjectName) {
			this.subjectDn = subjectName;
			return this;
		}

		public CertificateBuilder withNotBefore(LocalDateTime notBefore) {
			this.notBefore = notBefore;
			return this;
		}

		public CertificateBuilder withNotAfter(LocalDateTime notAfter) {
			this.notAfter = notAfter;
			return this;
		}

		public CertificateBuilder withValidityYears(int years) {
			this.notAfter = notBefore.plusYears(years);
			return this;
		}

		public CertificateBuilder withValidityMonths(int months) {
			this.notAfter = notBefore.plusMonths(months);
			return this;
		}

		/**
		 * Include subject key identifier.
		 * 
		 * @return
		 */
		public CertificateBuilder withIncludeSKID() {
			this.includeSKID = true;
			return this;
		}

		/**
		 * Include authority key identifier.
		 * 
		 * @return
		 */
		public CertificateBuilder withIncludeAKID() {
			this.includeAKID = true;
			return this;
		}

		/**
		 * Make the certificate builder to use an alternative authority key identifier.
		 * 
		 * @param akidPublicKey
		 * @return
		 */
		public CertificateBuilder withAKIDPublicKey(PublicKey akidPublicKey) {
			this.akidPublicKey = akidPublicKey;
			this.includeAKID = true;
			return this;
		}

		public CertificateBuilder withBasicConstraints(boolean ca) {
			this.basicConstraints = true;
			this.basicConstraintsCA = ca;
			return this;
		}

		public CertificateBuilder withBasicConstraints(int pathLength) {
			this.basicConstraints = true;
			this.pathLength = pathLength;
			return this;
		}

		public CertificateBuilder withCrlUri(String crlUri) {
			this.crlUri = crlUri;
			return this;
		}

		public CertificateBuilder withOcspUri(String ocspUri) {
			this.ocspUri = ocspUri;
			return this;
		}

		public CertificateBuilder withKeyUsage(int keyUsage) {
			this.keyUsage = keyUsage;
			return this;
		}

		public CertificateBuilder withCertificatePolicy(String certificatePolicy) {
			this.certificatePolicy = certificatePolicy;
			return this;
		}

		public CertificateBuilder withQCCompliance() {
			this.qcCompliance = true;
			this.qCStatements = true;
			return this;
		}

		public CertificateBuilder withQCRetentionPeriod() {
			this.qcRetentionPeriod = true;
			this.qCStatements = true;
			return this;
		}

		public CertificateBuilder withQCSSCD() {
			this.qcSSCD = true;
			this.qCStatements = true;
			return this;
		}

		public CertificateBuilder withTimeStamping() {
			this.timeStamping = true;
			this.extendedKeyUsage = true;
			return this;
		}

		public CertificateBuilder withOcspResponder() {
			this.ocspResponder = true;
			this.extendedKeyUsage = true;
			return this;
		}

		public CertificateBuilder withSignatureAlgorithm(String signatureAlgorithm) {
			this.signatureAlgorithm = signatureAlgorithm;
			return this;
		}

		public X509Certificate build() throws NoSuchAlgorithmException, CertIOException, IOException,
				OperatorCreationException, CertificateException {
			X500Name issuerName;
			if (null != this.issuerCertificate) {
				issuerName = new X500Name(this.issuerCertificate.getSubjectX500Principal().toString());
			} else {
				issuerName = new X500Name(this.subjectDn);
			}
			X500Name subjectName = new X500Name(this.subjectDn);
			BigInteger serial = new BigInteger(128, new SecureRandom());
			SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(this.subjectPublicKey.getEncoded());
			X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(issuerName, serial,
					Date.from(this.notBefore.atZone(ZoneId.systemDefault()).toInstant()),
					Date.from(this.notAfter.atZone(ZoneId.systemDefault()).toInstant()), subjectName, publicKeyInfo);

			JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
			if (this.includeSKID) {
				x509v3CertificateBuilder.addExtension(Extension.subjectKeyIdentifier, false,
						extensionUtils.createSubjectKeyIdentifier(this.subjectPublicKey));
			}

			if (this.includeAKID) {
				PublicKey authorityPublicKey;
				if (null != this.akidPublicKey) {
					authorityPublicKey = this.akidPublicKey;
				} else if (null != this.issuerCertificate) {
					authorityPublicKey = this.issuerCertificate.getPublicKey();
				} else {
					authorityPublicKey = this.subjectPublicKey;
				}
				x509v3CertificateBuilder.addExtension(Extension.authorityKeyIdentifier, false,
						extensionUtils.createAuthorityKeyIdentifier(authorityPublicKey));
			}

			if (this.basicConstraints) {
				if (null == this.pathLength) {
					x509v3CertificateBuilder.addExtension(Extension.basicConstraints, true,
							new BasicConstraints(this.basicConstraintsCA));
				} else {
					x509v3CertificateBuilder.addExtension(Extension.basicConstraints, true,
							new BasicConstraints(this.pathLength));
				}
			}

			if (null != this.crlUri) {
				GeneralName generalName = new GeneralName(GeneralName.uniformResourceIdentifier,
						new DERIA5String(this.crlUri));
				GeneralNames generalNames = new GeneralNames(generalName);
				DistributionPointName distPointName = new DistributionPointName(generalNames);
				DistributionPoint distPoint = new DistributionPoint(distPointName, null, null);
				DistributionPoint[] crlDistPoints = new DistributionPoint[] { distPoint };
				CRLDistPoint crlDistPoint = new CRLDistPoint(crlDistPoints);
				x509v3CertificateBuilder.addExtension(Extension.cRLDistributionPoints, false, crlDistPoint);
			}

			if (null != this.ocspUri) {
				GeneralName ocspName = new GeneralName(GeneralName.uniformResourceIdentifier, this.ocspUri);
				AuthorityInformationAccess authorityInformationAccess = new AuthorityInformationAccess(
						X509ObjectIdentifiers.ocspAccessMethod, ocspName);
				x509v3CertificateBuilder.addExtension(Extension.authorityInfoAccess, false, authorityInformationAccess);
			}

			if (null != this.keyUsage) {
				x509v3CertificateBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(this.keyUsage));
			}

			if (null != this.certificatePolicy) {
				ASN1ObjectIdentifier policyObjectIdentifier = new ASN1ObjectIdentifier(this.certificatePolicy);
				PolicyInformation policyInformation = new PolicyInformation(policyObjectIdentifier);
				x509v3CertificateBuilder.addExtension(Extension.certificatePolicies, false,
						new DERSequence(policyInformation));
			}

			if (this.qCStatements) {
				ASN1EncodableVector vec = new ASN1EncodableVector();
				if (this.qcCompliance) {
					vec.add(new QCStatement(QCStatement.id_etsi_qcs_QcCompliance));
				}
				if (this.qcRetentionPeriod) {
					vec.add(new QCStatement(QCStatement.id_etsi_qcs_RetentionPeriod));
				}
				if (this.qcSSCD) {
					vec.add(new QCStatement(QCStatement.id_etsi_qcs_QcSSCD));
				}
				x509v3CertificateBuilder.addExtension(Extension.qCStatements, true, new DERSequence(vec));

			}

			if (this.extendedKeyUsage) {
				List<KeyPurposeId> keyPurposes = new LinkedList<>();
				if (this.ocspResponder) {
					x509v3CertificateBuilder.addExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck, false,
							DERNull.INSTANCE);
					keyPurposes.add(KeyPurposeId.id_kp_OCSPSigning);
				}
				if (this.timeStamping) {
					keyPurposes.add(KeyPurposeId.id_kp_timeStamping);
				}

				x509v3CertificateBuilder.addExtension(Extension.extendedKeyUsage, true,
						new ExtendedKeyUsage(keyPurposes.toArray(new KeyPurposeId[0])));
			}

			if (null == this.signatureAlgorithm) {
				if (this.issuerPrivateKey.getAlgorithm().contains("RSA")) {
					this.signatureAlgorithm = "SHA256withRSA";
				} else {
					this.signatureAlgorithm = "SHA256withECDSA";
				}
			}
			AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder()
					.find(this.signatureAlgorithm);
			AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
			AsymmetricKeyParameter asymmetricKeyParameter = PrivateKeyFactory
					.createKey(this.issuerPrivateKey.getEncoded());

			ContentSigner contentSigner;
			if (this.signatureAlgorithm.contains("RSA")) {
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
	}

	/**
	 * Builder for X509 CRLs.
	 * 
	 * @author Frank Cornelis
	 *
	 */
	public static class CRLBuilder {

		private final PrivateKey issuerPrivateKey;
		private final X509Certificate issuerCertificate;

		private LocalDateTime thisUpdate = LocalDateTime.now();
		private LocalDateTime nextUpdate = LocalDateTime.now().plusHours(1);

		private String signatureAlgorithm;

		private List<RevokedCertificate> revokedCertificates = new LinkedList<>();

		private static class RevokedCertificate {

			private final BigInteger serialNumber;
			private final LocalDateTime revocationDate;

			public RevokedCertificate(BigInteger serialNumber, LocalDateTime revocationDate) {
				this.serialNumber = serialNumber;
				this.revocationDate = revocationDate;
			}

			public RevokedCertificate(X509Certificate certificate, LocalDateTime revocationDate) {
				this(certificate.getSerialNumber(), revocationDate);
			}

			public RevokedCertificate(X509Certificate certificate) {
				this(certificate.getSerialNumber(), LocalDateTime.now());
			}
		}

		public CRLBuilder(PrivateKey issuerPrivateKey, X509Certificate issuerCertificate) {
			this.issuerPrivateKey = issuerPrivateKey;
			this.issuerCertificate = issuerCertificate;
		}

		public CRLBuilder withThisUpdate(LocalDateTime thisUpdate) {
			this.thisUpdate = thisUpdate;
			this.nextUpdate = LocalDateTime.now().plusHours(1);
			return this;
		}

		public CRLBuilder withNextUpdate(LocalDateTime nextUpdate) {
			this.nextUpdate = nextUpdate;
			return this;
		}

		public CRLBuilder withValidityHours(int hours) {
			this.nextUpdate = this.thisUpdate.plusHours(hours);
			return this;
		}

		public CRLBuilder withValidityDays(int days) {
			this.nextUpdate = this.thisUpdate.plusDays(days);
			return this;
		}

		public CRLBuilder withValidityMonths(int months) {
			this.nextUpdate = this.thisUpdate.plusMonths(months);
			return this;
		}

		public CRLBuilder withSignatureAlgorithm(String signatureAlgorithm) {
			this.signatureAlgorithm = signatureAlgorithm;
			return this;
		}

		public CRLBuilder withRevokedCertificate(X509Certificate certificate) {
			RevokedCertificate revokedCertificate = new RevokedCertificate(certificate);
			this.revokedCertificates.add(revokedCertificate);
			return this;
		}

		public CRLBuilder withRevokedCertificate(X509Certificate certificate, LocalDateTime revocationDateTime) {
			RevokedCertificate revokedCertificate = new RevokedCertificate(certificate, revocationDateTime);
			this.revokedCertificates.add(revokedCertificate);
			return this;
		}

		public X509CRL build()
				throws InvalidKeyException, CRLException, IllegalStateException, NoSuchAlgorithmException,
				SignatureException, CertificateException, IOException, OperatorCreationException {

			X500Name issuerName = new X500Name(this.issuerCertificate.getSubjectX500Principal().toString());
			X509v2CRLBuilder x509v2crlBuilder = new X509v2CRLBuilder(issuerName,
					Date.from(this.thisUpdate.atZone(ZoneId.systemDefault()).toInstant()));
			x509v2crlBuilder.setNextUpdate(Date.from(this.nextUpdate.atZone(ZoneId.systemDefault()).toInstant()));

			for (RevokedCertificate revokedCertificate : this.revokedCertificates) {
				x509v2crlBuilder.addCRLEntry(revokedCertificate.serialNumber,
						Date.from(revokedCertificate.revocationDate.atZone(ZoneId.systemDefault()).toInstant()),
						CRLReason.privilegeWithdrawn);
			}

			JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
			x509v2crlBuilder.addExtension(Extension.authorityKeyIdentifier, false,
					extensionUtils.createAuthorityKeyIdentifier(this.issuerCertificate));
			x509v2crlBuilder.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.ONE));

			if (null == this.signatureAlgorithm) {
				if (this.issuerPrivateKey.getAlgorithm().equals("RSA")) {
					this.signatureAlgorithm = "SHA256withRSA";
				} else {
					this.signatureAlgorithm = "SHA256withECDSA";
				}
			}
			AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder()
					.find(this.signatureAlgorithm);
			AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
			AsymmetricKeyParameter asymmetricKeyParameter = PrivateKeyFactory
					.createKey(this.issuerPrivateKey.getEncoded());

			ContentSigner contentSigner;
			if (this.signatureAlgorithm.contains("RSA")) {
				contentSigner = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(asymmetricKeyParameter);
			} else {
				contentSigner = new BcECContentSignerBuilder(sigAlgId, digAlgId).build(asymmetricKeyParameter);
			}

			X509CRLHolder x509crlHolder = x509v2crlBuilder.build(contentSigner);
			byte[] crlValue = x509crlHolder.getEncoded();
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			X509CRL crl = (X509CRL) certificateFactory.generateCRL(new ByteArrayInputStream(crlValue));
			return crl;
		}
	}

	/**
	 * Builder for OCSP responses.
	 * 
	 * @author Frank Cornelis
	 *
	 */
	public static class OCSPBuilder {

		private final PrivateKey ocspResponderPrivateKey;

		private final X509Certificate ocspResponderCertificate;

		private final X509Certificate certificate;
		private final X509Certificate issuerCertificate;

		private String signatureAlgorithm = "SHA256withRSA";

		private boolean revoked;

		private List<X509Certificate> ocspResponderCertificateChain = null;

		/**
		 * 
		 * @param ocspResponderPrivateKey  the OCSP responder private key.
		 * @param ocspResponderCertificate the OCSP responder certificate.
		 * @param certificate              the certificate subject to the OCSP
		 *                                 request/response.
		 * @param issuerCertificate        the issuer of the certificate in question.
		 */
		public OCSPBuilder(PrivateKey ocspResponderPrivateKey, X509Certificate ocspResponderCertificate,
				X509Certificate certificate, X509Certificate issuerCertificate) {
			this.ocspResponderPrivateKey = ocspResponderPrivateKey;
			this.ocspResponderCertificate = ocspResponderCertificate;
			this.certificate = certificate;
			this.issuerCertificate = issuerCertificate;
		}

		/**
		 * Mark our certificate as being revoked.
		 * 
		 * @return
		 */
		public OCSPBuilder withRevoked() {
			this.revoked = true;
			return this;
		}

		public OCSPBuilder withSignatureAlgorithm(String signtureAlgorithm) {
			this.signatureAlgorithm = signtureAlgorithm;
			return this;
		}

		/**
		 * Attaches a certificate to the embedded OCSP responder certificate chain.
		 * 
		 * @param certificate
		 * @return
		 */
		public OCSPBuilder withResponderChain(X509Certificate certificate) {
			if (null == this.ocspResponderCertificateChain) {
				this.ocspResponderCertificateChain = new LinkedList<>();
			}
			this.ocspResponderCertificateChain.add(certificate);
			return this;
		}

		public OCSPResp build() throws Exception {
			// request
			DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder()
					.setProvider(BouncyCastleProvider.PROVIDER_NAME).build();
			CertificateID certId = new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1),
					new JcaX509CertificateHolder(this.issuerCertificate), this.certificate.getSerialNumber());

			BasicOCSPRespBuilder basicOCSPRespBuilder = new JcaBasicOCSPRespBuilder(
					this.ocspResponderCertificate.getPublicKey(), digCalcProv.get(CertificateID.HASH_SHA1));

			CertificateStatus certificateStatus;
			if (this.revoked) {
				certificateStatus = new RevokedStatus(new Date(), CRLReason.unspecified);
			} else {
				certificateStatus = CertificateStatus.GOOD;
			}
			basicOCSPRespBuilder.addResponse(certId, certificateStatus);

			X509CertificateHolder[] chain = null;
			if (null == this.ocspResponderCertificateChain) {
				if (!this.ocspResponderCertificate.equals(this.issuerCertificate)) {
					chain = new X509CertificateHolder[] {
							new X509CertificateHolder(this.ocspResponderCertificate.getEncoded()),
							new X509CertificateHolder(this.issuerCertificate.getEncoded()) };
				}
			} else {
				chain = new X509CertificateHolder[this.ocspResponderCertificateChain.size()];
				for (int idx = 0; idx < chain.length; idx++) {
					chain[idx] = new X509CertificateHolder(this.ocspResponderCertificateChain.get(idx).getEncoded());
				}
			}

			ContentSigner contentSigner = new JcaContentSignerBuilder(this.signatureAlgorithm)
					.build(this.ocspResponderPrivateKey);
			BasicOCSPResp basicOCSPResp = basicOCSPRespBuilder.build(contentSigner, chain, new Date());

			// response generation
			OCSPRespBuilder ocspRespBuilder = new OCSPRespBuilder();
			OCSPResp ocspResp = ocspRespBuilder.build(OCSPRespBuilder.SUCCESSFUL, basicOCSPResp);

			return ocspResp;
		}
	}
}
