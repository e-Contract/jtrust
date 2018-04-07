/*
 * Java Trust Project.
 * Copyright (C) 2018 e-Contract.be BVBA.
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
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.joda.time.DateTime;

public class CertificationAuthority {

	private final String name;

	private final CertificationAuthority issuer;

	private X509Certificate certificate;

	private KeyPair keyPair;

	private final List<RevocationService> revocationServices;

	private final World world;

	public CertificationAuthority(World world, String name, CertificationAuthority issuer) {
		this.world = world;
		this.name = name;
		this.issuer = issuer;
		this.revocationServices = new LinkedList<>();
	}

	public CertificationAuthority(World world, String name) {
		this(world, name, null);
	}

	public void addRevocationService(RevocationService revocationService) {
		this.revocationServices.add(revocationService);
		revocationService.setCertificationAuthority(this);
		this.world.addEndpointProvider(revocationService);
	}

	public X509Certificate issueCertificationAuthority(PublicKey publicKey, String name) throws Exception {
		if (!this.world.isRunning()) {
			throw new IllegalStateException();
		}
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);

		X500Name issuerName = new X500Name(this.name);
		X500Name subjectName = new X500Name(name);

		BigInteger serial = new BigInteger(128, new SecureRandom());
		SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
		X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(issuerName, serial,
				notBefore.toDate(), notAfter.toDate(), subjectName, publicKeyInfo);

		JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
		x509v3CertificateBuilder.addExtension(Extension.subjectKeyIdentifier, false,
				extensionUtils.createSubjectKeyIdentifier(publicKey));

		x509v3CertificateBuilder.addExtension(Extension.authorityKeyIdentifier, false,
				extensionUtils.createAuthorityKeyIdentifier(this.keyPair.getPublic()));

		x509v3CertificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));

		for (RevocationService revocationService : this.revocationServices) {
			revocationService.addExtension(x509v3CertificateBuilder);
		}

		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
		AsymmetricKeyParameter asymmetricKeyParameter = PrivateKeyFactory
				.createKey(this.keyPair.getPrivate().getEncoded());

		ContentSigner contentSigner = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(asymmetricKeyParameter);
		X509CertificateHolder x509CertificateHolder = x509v3CertificateBuilder.build(contentSigner);

		byte[] encodedCertificate = x509CertificateHolder.getEncoded();

		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		X509Certificate certificate = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(encodedCertificate));

		return certificate;
	}

	public PrivateKey getPrivateKey() throws Exception {
		if (!this.world.isRunning()) {
			throw new IllegalArgumentException();
		}
		getCertificate();
		return this.keyPair.getPrivate();
	}

	public X509Certificate getCertificate() throws Exception {
		if (!this.world.isRunning()) {
			throw new IllegalStateException();
		}
		if (null != this.certificate) {
			return this.certificate;
		}
		this.keyPair = PKITestUtils.generateKeyPair();
		if (this.issuer == null) {
			DateTime notBefore = new DateTime();
			DateTime notAfter = notBefore.plusYears(1);
			this.certificate = PKITestUtils.generateSelfSignedCertificate(this.keyPair, this.name, notBefore, notAfter);
		} else {
			this.certificate = this.issuer.issueCertificationAuthority(this.keyPair.getPublic(), this.name);
		}
		return this.certificate;
	}
}
