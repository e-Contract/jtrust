/*
 * Java Trust Project.
 * Copyright (C) 2018-2023 e-Contract.be BV.
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
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;

/**
 * A certification authority. Can issue certificates and expose revocation
 * services.
 * 
 * @author Frank Cornelis
 *
 */
public class CertificationAuthority {

	private String name;

	private final CertificationAuthority issuer;

	private X509Certificate certificate;

	private KeyPair keyPair;

	private final List<RevocationService> revocationServices;

	private final World world;

	private final List<X509Certificate> issuedCertificates;

	// value is revocation date
	private final Map<X509Certificate, LocalDateTime> revokedCertificates;

	private String signatureAlgorithm;

	/**
	 * Creates a new certification authority, issued by another CA.
	 * 
	 * @param world
	 * @param name   the DN of this CA.
	 * @param issuer the issuing CA.
	 */
	public CertificationAuthority(World world, String name, CertificationAuthority issuer) {
		this.world = world;
		this.name = name;
		this.issuer = issuer;
		this.revocationServices = new LinkedList<>();
		this.issuedCertificates = new LinkedList<>();
		this.revokedCertificates = new HashMap<>();
		this.signatureAlgorithm = "SHA256withRSA";
	}

	/**
	 * Creates a root certification authority.
	 * 
	 * @param world
	 * @param name  the DN of the CA.
	 */
	public CertificationAuthority(World world, String name) {
		this(world, name, null);
	}

	/**
	 * Gives back the used signature algorithm for issuing certificates and such.
	 * 
	 * @return
	 */
	public String getSignatureAlgorithm() {
		return this.signatureAlgorithm;
	}

	/**
	 * Sets the signature algorithm for issing certificates and such.
	 * 
	 * @param signatureAlgorithm
	 */
	public void setSignatureAlgorithm(String signatureAlgorithm) {
		this.signatureAlgorithm = signatureAlgorithm;
	}

	/**
	 * The issuer of this CA. In case this is a root CA, returns <code>null</code>.
	 * 
	 * @return
	 */
	public CertificationAuthority getIssuer() {
		return this.issuer;
	}

	/**
	 * Gives back the clock to be used.
	 * 
	 * @return
	 */
	public Clock getClock() {
		return this.world.getClock();
	}

	/**
	 * Adds a revocation service for this CA. The issued certificates by this CA
	 * will have the appropriate extensions.
	 * 
	 * @param revocationService
	 */
	public void addRevocationService(RevocationService revocationService) {
		this.revocationServices.add(revocationService);
		revocationService.setCertificationAuthority(this);
		this.world.addEndpointProvider(revocationService);
	}

	/**
	 * Issues another CA, signed by this CA.
	 * 
	 * @param publicKey the public key of the new CA.
	 * @param name      the DN of the new CA.
	 * @return the new CA certificate.
	 * @throws Exception
	 */
	public X509Certificate issueCertificationAuthority(PublicKey publicKey, String name) throws Exception {
		if (!this.world.isRunning()) {
			throw new IllegalStateException();
		}
		// make sure our CA certificate is generated before the issued certificate
		X509Certificate caCert = getCertificate();

		Clock clock = this.world.getClock();
		LocalDateTime notBefore = clock.getTime();
		LocalDateTime notAfter = caCert.getNotAfter().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();

		X500Name issuerName = new X500Name(this.name);
		X500Name subjectName = new X500Name(name);

		BigInteger serial = new BigInteger(128, new SecureRandom());
		SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
		X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(issuerName, serial,
				Date.from(notBefore.atZone(ZoneId.systemDefault()).toInstant()),
				Date.from(notAfter.atZone(ZoneId.systemDefault()).toInstant()), subjectName, publicKeyInfo);

		JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
		x509v3CertificateBuilder.addExtension(Extension.subjectKeyIdentifier, false,
				extensionUtils.createSubjectKeyIdentifier(publicKey));

		x509v3CertificateBuilder.addExtension(Extension.authorityKeyIdentifier, false,
				extensionUtils.createAuthorityKeyIdentifier(this.getPublicKey()));

		x509v3CertificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

		KeyUsage keyUsage = new KeyUsage(KeyUsage.cRLSign | KeyUsage.keyCertSign);
		x509v3CertificateBuilder.addExtension(Extension.keyUsage, true, keyUsage);

		for (RevocationService revocationService : this.revocationServices) {
			revocationService.addExtension(x509v3CertificateBuilder);
		}

		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(this.signatureAlgorithm);
		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
		AsymmetricKeyParameter asymmetricKeyParameter = PrivateKeyFactory
				.createKey(this.keyPair.getPrivate().getEncoded());

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

		this.issuedCertificates.add(certificate);
		return certificate;
	}

	/**
	 * Gives back the private key of this CA. Useful for implementation of certain
	 * revocation services (like CRL signing).
	 * 
	 * @return
	 * @throws Exception
	 */
	public PrivateKey getPrivateKey() throws Exception {
		if (!this.world.isRunning()) {
			throw new IllegalArgumentException();
		}
		getCertificate();
		return this.keyPair.getPrivate();
	}

	/**
	 * Gives back the public key of this CA.
	 * 
	 * @return
	 * @throws Exception
	 */
	public PublicKey getPublicKey() throws Exception {
		if (!this.world.isRunning()) {
			throw new IllegalArgumentException();
		}
		getCertificate();
		return this.keyPair.getPublic();
	}

	/**
	 * Gives back the certificate of this CA.
	 * 
	 * @return
	 * @throws Exception
	 */
	public X509Certificate getCertificate() throws Exception {
		if (!this.world.isRunning()) {
			throw new IllegalStateException();
		}
		if (null != this.certificate) {
			return this.certificate;
		}
		if (this.issuer != null) {
			// make sure that the issuer is already issued
			this.issuer.getCertificate();
		}
		if (this.signatureAlgorithm.contains("RSA")) {
			this.keyPair = new PKIBuilder.KeyPairBuilder().build();
		} else {
			this.keyPair = new PKIBuilder.KeyPairBuilder().withKeyAlgorithm("EC").build();
		}
		if (this.issuer == null) {
			this.certificate = generateSelfSignedCertificate();
		} else {
			this.certificate = this.issuer.issueCertificationAuthority(this.keyPair.getPublic(), this.name);
		}
		return this.certificate;
	}

	/**
	 * Reissue the CA certificate using the new DN.
	 * 
	 * @param name
	 * @throws Exception
	 */
	public void reissueCertificate(String name) throws Exception {
		if (!this.world.isRunning()) {
			throw new IllegalStateException();
		}
		this.name = name;

		if (this.issuer != null) {
			// make sure that the issuer is already issued
			this.issuer.getCertificate();
		}
		if (this.signatureAlgorithm.contains("RSA")) {
			this.keyPair = new PKIBuilder.KeyPairBuilder().build();
		} else {
			this.keyPair = new PKIBuilder.KeyPairBuilder().withKeyAlgorithm("EC").build();
		}
		if (this.issuer == null) {
			this.certificate = generateSelfSignedCertificate();
		} else {
			this.certificate = this.issuer.issueCertificationAuthority(this.keyPair.getPublic(), this.name);
		}
	}

	private X509Certificate generateSelfSignedCertificate() throws Exception {
		Clock clock = this.world.getClock();
		LocalDateTime notBefore = clock.getTime();
		LocalDateTime notAfter = notBefore.plusYears(1);

		X500Name issuerName = new X500Name(this.name);
		X500Name subjectName = new X500Name(this.name);

		BigInteger serial = new BigInteger(128, new SecureRandom());
		SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(this.keyPair.getPublic().getEncoded());
		X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(issuerName, serial,
				Date.from(notBefore.atZone(ZoneId.systemDefault()).toInstant()),
				Date.from(notAfter.atZone(ZoneId.systemDefault()).toInstant()), subjectName, publicKeyInfo);

		JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
		x509v3CertificateBuilder.addExtension(Extension.subjectKeyIdentifier, false,
				extensionUtils.createSubjectKeyIdentifier(this.keyPair.getPublic()));

		x509v3CertificateBuilder.addExtension(Extension.authorityKeyIdentifier, false,
				extensionUtils.createAuthorityKeyIdentifier(this.keyPair.getPublic()));

		x509v3CertificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

		KeyUsage keyUsage = new KeyUsage(KeyUsage.cRLSign | KeyUsage.keyCertSign);
		x509v3CertificateBuilder.addExtension(Extension.keyUsage, true, keyUsage);

		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(this.signatureAlgorithm);
		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
		AsymmetricKeyParameter asymmetricKeyParameter = PrivateKeyFactory
				.createKey(this.keyPair.getPrivate().getEncoded());

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

		this.issuedCertificates.add(certificate);
		return certificate;
	}

	/**
	 * Issues an OCSP Responder certificate.
	 * 
	 * @param publicKey the public key of the OCSP responder.
	 * @param name      the DN of the OCSP responder.
	 * @return
	 * @throws Exception
	 */
	public X509Certificate issueOCSPResponder(PublicKey publicKey, String name) throws Exception {
		if (!this.world.isRunning()) {
			throw new IllegalStateException();
		}
		// make sure our CA certificate is generated before the issued certificate
		X509Certificate caCertificate = getCertificate();

		Clock clock = this.world.getClock();
		LocalDateTime notBefore = clock.getTime();
		LocalDateTime notAfter = caCertificate.getNotAfter().toInstant().atZone(ZoneId.systemDefault())
				.toLocalDateTime();

		X500Name issuerName = new X500Name(this.name);
		X500Name subjectName = new X500Name(name);

		BigInteger serial = new BigInteger(128, new SecureRandom());
		SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
		X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(issuerName, serial,
				Date.from(notBefore.atZone(ZoneId.systemDefault()).toInstant()),
				Date.from(notAfter.atZone(ZoneId.systemDefault()).toInstant()), subjectName, publicKeyInfo);

		JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
		x509v3CertificateBuilder.addExtension(Extension.subjectKeyIdentifier, false,
				extensionUtils.createSubjectKeyIdentifier(publicKey));

		x509v3CertificateBuilder.addExtension(Extension.authorityKeyIdentifier, false,
				extensionUtils.createAuthorityKeyIdentifier(this.getPublicKey()));

		x509v3CertificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

		for (RevocationService revocationService : this.revocationServices) {
			revocationService.addExtension(x509v3CertificateBuilder);
		}

		x509v3CertificateBuilder.addExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck, false, DERNull.INSTANCE);
		x509v3CertificateBuilder.addExtension(Extension.extendedKeyUsage, true,
				new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning));

		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(this.signatureAlgorithm);
		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
		AsymmetricKeyParameter asymmetricKeyParameter = PrivateKeyFactory
				.createKey(this.keyPair.getPrivate().getEncoded());

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

		this.issuedCertificates.add(certificate);
		return certificate;
	}

	/**
	 * Issues a timestamp authority certificate.
	 * 
	 * @param publicKey the public key of the TSA.
	 * @param name      the DN of the TSA.
	 * @return
	 * @throws Exception
	 */
	public X509Certificate issueTimeStampAuthority(PublicKey publicKey, String name) throws Exception {
		if (!this.world.isRunning()) {
			throw new IllegalStateException();
		}
		// make sure our CA certificate is generated before the issued certificate
		X509Certificate caCert = getCertificate();

		Clock clock = this.world.getClock();
		LocalDateTime notBefore = clock.getTime();
		LocalDateTime notAfter = caCert.getNotAfter().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();

		X500Name issuerName = new X500Name(this.name);
		X500Name subjectName = new X500Name(name);

		BigInteger serial = new BigInteger(128, new SecureRandom());
		SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
		X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(issuerName, serial,
				Date.from(notBefore.atZone(ZoneId.systemDefault()).toInstant()),
				Date.from(notAfter.atZone(ZoneId.systemDefault()).toInstant()), subjectName, publicKeyInfo);

		JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
		x509v3CertificateBuilder.addExtension(Extension.subjectKeyIdentifier, false,
				extensionUtils.createSubjectKeyIdentifier(publicKey));

		x509v3CertificateBuilder.addExtension(Extension.authorityKeyIdentifier, false,
				extensionUtils.createAuthorityKeyIdentifier(this.getPublicKey()));

		x509v3CertificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

		for (RevocationService revocationService : this.revocationServices) {
			revocationService.addExtension(x509v3CertificateBuilder);
		}

		x509v3CertificateBuilder.addExtension(Extension.extendedKeyUsage, true,
				new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));

		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(this.signatureAlgorithm);
		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
		AsymmetricKeyParameter asymmetricKeyParameter = PrivateKeyFactory
				.createKey(this.keyPair.getPrivate().getEncoded());

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

		this.issuedCertificates.add(certificate);
		return certificate;
	}

	/**
	 * Issues a signing end-entity certificate.
	 * 
	 * @param publicKey the public key of the end-entity certificate.
	 * @param name      the DN of the end-entity certificate.
	 * @return
	 * @throws Exception
	 */
	public X509Certificate issueSigningCertificate(PublicKey publicKey, String name) throws Exception {
		if (!this.world.isRunning()) {
			throw new IllegalStateException();
		}
		// make sure our CA certificate is generated before the issued certificate
		X509Certificate caCert = getCertificate();
		LocalDateTime notAfter = caCert.getNotAfter().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
		return issueSigningCertificate(publicKey, name, notAfter);
	}

	/**
	 * Issues a signing end-entity certificate.
	 * 
	 * @param publicKey the public key of the end-entity certificate.
	 * @param name      the DN of the end-entity certificate.
	 * @param notAfter  expiration date of issued certificate.
	 * @return
	 * @throws Exception
	 */
	public X509Certificate issueSigningCertificate(PublicKey publicKey, String name, LocalDateTime notAfter)
			throws Exception {
		if (!this.world.isRunning()) {
			throw new IllegalStateException();
		}
		// make sure our CA certificate is generated before the issued certificate
		getCertificate();

		Clock clock = this.world.getClock();
		LocalDateTime notBefore = clock.getTime();

		X500Name issuerName = new X500Name(this.name);
		X500Name subjectName = new X500Name(name);

		BigInteger serial = new BigInteger(128, new SecureRandom());
		SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
		X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(issuerName, serial,
				Date.from(notBefore.atZone(ZoneId.systemDefault()).toInstant()),
				Date.from(notAfter.atZone(ZoneId.systemDefault()).toInstant()), subjectName, publicKeyInfo);

		JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
		x509v3CertificateBuilder.addExtension(Extension.subjectKeyIdentifier, false,
				extensionUtils.createSubjectKeyIdentifier(publicKey));

		x509v3CertificateBuilder.addExtension(Extension.authorityKeyIdentifier, false,
				extensionUtils.createAuthorityKeyIdentifier(this.getPublicKey()));

		x509v3CertificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

		for (RevocationService revocationService : this.revocationServices) {
			revocationService.addExtension(x509v3CertificateBuilder);
		}

		ASN1EncodableVector vec = new ASN1EncodableVector();
		vec.add(new QCStatement(QCStatement.id_etsi_qcs_QcCompliance));
		vec.add(new QCStatement(QCStatement.id_etsi_qcs_QcSSCD));
		x509v3CertificateBuilder.addExtension(Extension.qCStatements, true, new DERSequence(vec));

		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(this.signatureAlgorithm);
		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
		AsymmetricKeyParameter asymmetricKeyParameter = PrivateKeyFactory
				.createKey(this.keyPair.getPrivate().getEncoded());

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

		this.issuedCertificates.add(certificate);
		return certificate;
	}

	public X509Certificate issueCertificate(PublicKey publicKey, String name, LocalDateTime notAfter) throws Exception {
		if (!this.world.isRunning()) {
			throw new IllegalStateException();
		}
		// make sure our CA certificate is generated before the issued certificate
		getCertificate();

		Clock clock = this.world.getClock();
		LocalDateTime notBefore = clock.getTime();

		X500Name issuerName = new X500Name(this.name);
		X500Name subjectName = new X500Name(name);

		BigInteger serial = new BigInteger(128, new SecureRandom());
		SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
		X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(issuerName, serial,
				Date.from(notBefore.atZone(ZoneId.systemDefault()).toInstant()),
				Date.from(notAfter.atZone(ZoneId.systemDefault()).toInstant()), subjectName, publicKeyInfo);

		JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
		x509v3CertificateBuilder.addExtension(Extension.subjectKeyIdentifier, false,
				extensionUtils.createSubjectKeyIdentifier(publicKey));

		x509v3CertificateBuilder.addExtension(Extension.authorityKeyIdentifier, false,
				extensionUtils.createAuthorityKeyIdentifier(this.getPublicKey()));

		x509v3CertificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

		for (RevocationService revocationService : this.revocationServices) {
			revocationService.addExtension(x509v3CertificateBuilder);
		}

		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(this.signatureAlgorithm);
		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
		AsymmetricKeyParameter asymmetricKeyParameter = PrivateKeyFactory
				.createKey(this.keyPair.getPrivate().getEncoded());

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

		this.issuedCertificates.add(certificate);
		return certificate;
	}

	/**
	 * Revoked a given certificate.
	 * 
	 * @param certificate
	 */
	public void revoke(X509Certificate certificate) {
		if (!this.issuedCertificates.contains(certificate)) {
			throw new IllegalArgumentException();
		}
		if (this.revokedCertificates.containsKey(certificate)) {
			throw new IllegalArgumentException();
		}
		LocalDateTime revocationDate = this.world.getClock().getTime();
		this.revokedCertificates.put(certificate, revocationDate);
	}

	/**
	 * Gives back all certificates (including revoked onces) issued by this CA.
	 * 
	 * @return
	 */
	public List<X509Certificate> getIssuedCertificates() {
		return this.issuedCertificates;
	}

	/**
	 * Gives back all revoked certificates issued by this CA.
	 * 
	 * @return
	 */
	public Map<X509Certificate, LocalDateTime> getRevokedCertificates() {
		return this.revokedCertificates;
	}
}
