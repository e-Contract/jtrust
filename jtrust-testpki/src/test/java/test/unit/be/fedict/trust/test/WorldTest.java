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
package test.unit.be.fedict.trust.test;

import java.io.DataInputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.fedict.trust.test.CRLRevocationService;
import be.fedict.trust.test.CertificationAuthority;
import be.fedict.trust.test.OCSPRevocationService;
import be.fedict.trust.test.PKIBuilder;
import be.fedict.trust.test.World;

public class WorldTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(WorldTest.class);

	static {
		System.setProperty("ocsp.enable", "true");
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void testRootCA() throws Exception {
		try (World world = new World()) {
			CertificationAuthority rootCertificationAuthority = new CertificationAuthority(world, "CN=Root CA");
			world.start();

			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			TrustAnchor trustAnchor = new TrustAnchor(rootCertificationAuthority.getCertificate(), null);
			Set<TrustAnchor> trustAnchors = Collections.singleton(trustAnchor);

			CertPath certPath = certificateFactory.generateCertPath(
					Arrays.asList(new X509Certificate[] { rootCertificationAuthority.getCertificate() }));

			PKIXParameters pkixParameters = new PKIXParameters(trustAnchors);
			pkixParameters.setRevocationEnabled(false);

			CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");
			PKIXCertPathValidatorResult certPathValidatorResult = (PKIXCertPathValidatorResult) certPathValidator
					.validate(certPath, pkixParameters);
		}
	}

	@Test
	public void testCertificate() throws Exception {
		try (World world = new World()) {
			CertificationAuthority rootCertificationAuthority = new CertificationAuthority(world, "CN=Root CA");
			world.start();

			KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
			X509Certificate certificate = rootCertificationAuthority.issueCertificate(keyPair.getPublic(),
					"CN=Test Cert", LocalDateTime.now().plusMonths(1));

			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			TrustAnchor trustAnchor = new TrustAnchor(rootCertificationAuthority.getCertificate(), null);
			Set<TrustAnchor> trustAnchors = Collections.singleton(trustAnchor);

			CertPath certPath = certificateFactory
					.generateCertPath(Arrays.asList(new X509Certificate[] { certificate }));

			PKIXParameters pkixParameters = new PKIXParameters(trustAnchors);
			pkixParameters.setRevocationEnabled(false);

			CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");
			PKIXCertPathValidatorResult certPathValidatorResult = (PKIXCertPathValidatorResult) certPathValidator
					.validate(certPath, pkixParameters);
		}
	}

	@Test
	public void testCertificateRevocationEnabled() throws Exception {
		try (World world = new World()) {
			CertificationAuthority rootCertificationAuthority = new CertificationAuthority(world, "CN=Root CA");
			CRLRevocationService crlRevocationService = new CRLRevocationService();
			rootCertificationAuthority.addRevocationService(crlRevocationService);
			world.start();

			KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
			X509Certificate certificate = rootCertificationAuthority.issueCertificate(keyPair.getPublic(),
					"CN=Test Cert", LocalDateTime.now().plusMonths(1));
			LOGGER.debug("certificate: {}", certificate);

			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			TrustAnchor trustAnchor = new TrustAnchor(rootCertificationAuthority.getCertificate(), null);
			Set<TrustAnchor> trustAnchors = Collections.singleton(trustAnchor);

			CertPath certPath = certificateFactory
					.generateCertPath(Arrays.asList(new X509Certificate[] { certificate }));

			PKIXParameters pkixParameters = new PKIXParameters(trustAnchors);
			pkixParameters.setRevocationEnabled(true);

			String crlUrl = crlRevocationService.getCrlUri();
			URLConnection connection = new URL(crlUrl).openConnection();
			connection.setDoInput(true);
			connection.setUseCaches(false);
			X509CRL crl;
			try (DataInputStream inStream = new DataInputStream(connection.getInputStream())) {
				crl = (X509CRL) certificateFactory.generateCRL(inStream);
			}
			pkixParameters.addCertStore(CertStore.getInstance("Collection",
					new CollectionCertStoreParameters(Collections.singletonList(crl))));

			CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");
			PKIXCertPathValidatorResult certPathValidatorResult = (PKIXCertPathValidatorResult) certPathValidator
					.validate(certPath, pkixParameters);
		}
	}

	@Test
	public void testBouncyCastleCRL() throws Exception {
		try (World world = new World()) {
			CertificationAuthority rootCertificationAuthority = new CertificationAuthority(world, "CN=Root CA");
			CRLRevocationService crlRevocationService = new CRLRevocationService();
			rootCertificationAuthority.addRevocationService(crlRevocationService);
			world.start();

			KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
			X509Certificate certificate = rootCertificationAuthority.issueCertificate(keyPair.getPublic(),
					"CN=Test Cert", LocalDateTime.now().plusMonths(1));
			LOGGER.debug("certificate: {}", certificate);

			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			TrustAnchor trustAnchor = new TrustAnchor(rootCertificationAuthority.getCertificate(), null);
			Set<TrustAnchor> trustAnchors = Collections.singleton(trustAnchor);

			CertPath certPath = certificateFactory
					.generateCertPath(Arrays.asList(new X509Certificate[] { certificate }));

			PKIXParameters pkixParameters = new PKIXParameters(trustAnchors);
			pkixParameters.setRevocationEnabled(true);

			String crlUrl = crlRevocationService.getCrlUri();
			URLConnection connection = new URL(crlUrl).openConnection();
			connection.setDoInput(true);
			connection.setUseCaches(false);
			X509CRL crl;
			try (DataInputStream inStream = new DataInputStream(connection.getInputStream())) {
				crl = (X509CRL) certificateFactory.generateCRL(inStream);
			}
			pkixParameters.addCertStore(CertStore.getInstance("Collection",
					new CollectionCertStoreParameters(Collections.singletonList(crl))));

			CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX",
					BouncyCastleProvider.PROVIDER_NAME);
			PKIXCertPathValidatorResult certPathValidatorResult = (PKIXCertPathValidatorResult) certPathValidator
					.validate(certPath, pkixParameters);
		}
	}

	@Test
	public void testCRLDistributionPoint() throws Exception {
		try (World world = new World()) {
			CertificationAuthority rootCertificationAuthority = new CertificationAuthority(world, "CN=Root CA");
			CRLRevocationService crlRevocationService = new CRLRevocationService();
			rootCertificationAuthority.addRevocationService(crlRevocationService);
			world.start();

			KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
			X509Certificate certificate = rootCertificationAuthority.issueCertificate(keyPair.getPublic(),
					"CN=Test Cert", LocalDateTime.now().plusMonths(1));
			LOGGER.debug("certificate: {}", certificate);

			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			TrustAnchor trustAnchor = new TrustAnchor(rootCertificationAuthority.getCertificate(), null);
			Set<TrustAnchor> trustAnchors = Collections.singleton(trustAnchor);

			CertPath certPath = certificateFactory
					.generateCertPath(Arrays.asList(new X509Certificate[] { certificate }));

			PKIXParameters pkixParameters = new PKIXParameters(trustAnchors);
			pkixParameters.setRevocationEnabled(true);

			System.setProperty("com.sun.security.enableCRLDP", "true");

			CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");
			PKIXCertPathValidatorResult certPathValidatorResult = (PKIXCertPathValidatorResult) certPathValidator
					.validate(certPath, pkixParameters);
		}
	}

	@Test
	public void testOCSP() throws Exception {
		try (World world = new World()) {
			CertificationAuthority rootCertificationAuthority = new CertificationAuthority(world, "CN=Root CA");
			rootCertificationAuthority.addRevocationService(new CRLRevocationService());

			CertificationAuthority intermediateCertificationAuthority = new CertificationAuthority(world,
					"CN=Intermediate CA", rootCertificationAuthority);
			OCSPRevocationService ocspRevocationService = new OCSPRevocationService();
			intermediateCertificationAuthority.addRevocationService(ocspRevocationService);

			world.start();

			KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
			X509Certificate certificate = intermediateCertificationAuthority.issueCertificate(keyPair.getPublic(),
					"CN=Test Cert", LocalDateTime.now().plusMonths(1));
			LOGGER.debug("certificate: {}", certificate);

			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			TrustAnchor trustAnchor = new TrustAnchor(rootCertificationAuthority.getCertificate(), null);
			Set<TrustAnchor> trustAnchors = Collections.singleton(trustAnchor);

			CertPath certPath = certificateFactory.generateCertPath(Arrays.asList(
					new X509Certificate[] { certificate, intermediateCertificationAuthority.getCertificate() }));

			PKIXParameters pkixParameters = new PKIXParameters(trustAnchors);
			pkixParameters.setRevocationEnabled(false);

			LOGGER.debug("OCSP responder URL: {}", ocspRevocationService.getOcspUrl());

			CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");
			PKIXRevocationChecker revocationChecker = (PKIXRevocationChecker) certPathValidator.getRevocationChecker();
			pkixParameters.addCertPathChecker(revocationChecker);
			PKIXCertPathValidatorResult certPathValidatorResult = (PKIXCertPathValidatorResult) certPathValidator
					.validate(certPath, pkixParameters);
		}
	}

	@Test
	public void testOCSPRevoked() throws Exception {
		try (World world = new World()) {
			CertificationAuthority rootCertificationAuthority = new CertificationAuthority(world, "CN=Root CA");
			rootCertificationAuthority.addRevocationService(new CRLRevocationService());

			CertificationAuthority intermediateCertificationAuthority = new CertificationAuthority(world,
					"CN=Intermediate CA", rootCertificationAuthority);
			OCSPRevocationService ocspRevocationService = new OCSPRevocationService();
			intermediateCertificationAuthority.addRevocationService(ocspRevocationService);

			world.start();

			KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
			X509Certificate certificate = intermediateCertificationAuthority.issueCertificate(keyPair.getPublic(),
					"CN=Test Cert", LocalDateTime.now().plusMonths(1));
			LOGGER.debug("certificate: {}", certificate);
			intermediateCertificationAuthority.revoke(certificate);

			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			TrustAnchor trustAnchor = new TrustAnchor(rootCertificationAuthority.getCertificate(), null);
			Set<TrustAnchor> trustAnchors = Collections.singleton(trustAnchor);

			CertPath certPath = certificateFactory.generateCertPath(Arrays.asList(
					new X509Certificate[] { certificate, intermediateCertificationAuthority.getCertificate() }));

			PKIXParameters pkixParameters = new PKIXParameters(trustAnchors);
			pkixParameters.setRevocationEnabled(false);

			LOGGER.debug("OCSP responder URL: {}", ocspRevocationService.getOcspUrl());

			CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");
			PKIXRevocationChecker revocationChecker = (PKIXRevocationChecker) certPathValidator.getRevocationChecker();
			pkixParameters.addCertPathChecker(revocationChecker);
			CertPathValidatorException exception = Assertions.assertThrows(CertPathValidatorException.class, () -> {
				certPathValidator.validate(certPath, pkixParameters);
			});
			LOGGER.debug("reason: {}", exception.getReason());
			LOGGER.debug("reason type: {}", exception.getReason().getClass().getName());
			Assertions.assertEquals(CertPathValidatorException.BasicReason.REVOKED, exception.getReason());
		}
	}

	@Test
	public void testCRLRevoked() throws Exception {
		try (World world = new World()) {
			CertificationAuthority rootCertificationAuthority = new CertificationAuthority(world, "CN=Root CA");
			rootCertificationAuthority.addRevocationService(new CRLRevocationService());

			CertificationAuthority intermediateCertificationAuthority = new CertificationAuthority(world,
					"CN=Intermediate CA", rootCertificationAuthority);
			intermediateCertificationAuthority.addRevocationService(new CRLRevocationService());

			world.start();

			KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
			X509Certificate certificate = intermediateCertificationAuthority.issueCertificate(keyPair.getPublic(),
					"CN=Test Cert", LocalDateTime.now().plusMonths(1));
			LOGGER.debug("certificate: {}", certificate);
			intermediateCertificationAuthority.revoke(certificate);

			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			TrustAnchor trustAnchor = new TrustAnchor(rootCertificationAuthority.getCertificate(), null);
			Set<TrustAnchor> trustAnchors = Collections.singleton(trustAnchor);

			CertPath certPath = certificateFactory.generateCertPath(Arrays.asList(
					new X509Certificate[] { certificate, intermediateCertificationAuthority.getCertificate() }));

			PKIXParameters pkixParameters = new PKIXParameters(trustAnchors);
			pkixParameters.setRevocationEnabled(false);

			CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");
			PKIXRevocationChecker revocationChecker = (PKIXRevocationChecker) certPathValidator.getRevocationChecker();
			pkixParameters.addCertPathChecker(revocationChecker);
			CertPathValidatorException exception = Assertions.assertThrows(CertPathValidatorException.class, () -> {
				certPathValidator.validate(certPath, pkixParameters);
			});
			LOGGER.debug("reason: {}", exception.getReason());
			LOGGER.debug("reason type: {}", exception.getReason().getClass().getName());
			Assertions.assertEquals(CertPathValidatorException.BasicReason.REVOKED, exception.getReason());
		}
	}
}
