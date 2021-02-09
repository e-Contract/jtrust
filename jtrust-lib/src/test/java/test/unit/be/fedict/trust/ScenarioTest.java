/*
 * Java Trust Project.
 * Copyright (C) 2018-2021 e-Contract.be BV.
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.fedict.trust.TrustValidator;
import be.fedict.trust.TrustValidatorDecorator;
import be.fedict.trust.crl.OnlineCrlRepository;
import be.fedict.trust.linker.TrustLinkerResultException;
import be.fedict.trust.repository.MemoryCertificateRepository;
import be.fedict.trust.test.BasicFailBehavior;
import be.fedict.trust.test.BasicOCSPFailBehavior;
import be.fedict.trust.test.CRLRevocationService;
import be.fedict.trust.test.CertificationAuthority;
import be.fedict.trust.test.Clock;
import be.fedict.trust.test.FixedClock;
import be.fedict.trust.test.OCSPRevocationService;
import be.fedict.trust.test.PKITestUtils;
import be.fedict.trust.test.TimeStampAuthority;
import be.fedict.trust.test.World;

public class ScenarioTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(ScenarioTest.class);

	@BeforeAll
	public static void oneTimeSetUp() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void testRootCA() throws Exception {
		try (World world = new World()) {
			CertificationAuthority certificationAuthority = new CertificationAuthority(world, "CN=Root CA");
			world.start();

			X509Certificate rootCert = certificationAuthority.getCertificate();

			MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();
			memoryCertificateRepository.addTrustPoint(rootCert);
			TrustValidator trustValidator = new TrustValidator(memoryCertificateRepository);

			trustValidator.isTrusted(Collections.singletonList(rootCert));
		}
	}

	@Test
	public void testUntrustedRoot() throws Exception {
		try (World world = new World()) {
			CertificationAuthority certificationAuthority = new CertificationAuthority(world, "CN=Root CA");
			world.start();

			X509Certificate rootCert = certificationAuthority.getCertificate();

			MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();
			TrustValidator trustValidator = new TrustValidator(memoryCertificateRepository);

			try {
				trustValidator.isTrusted(Collections.singletonList(rootCert));
				fail();
			} catch (TrustLinkerResultException e) {
				// expected
			}
		}
	}

	@Test
	public void testRootCA_SHA256withRSA() throws Exception {
		try (World world = new World()) {
			CertificationAuthority certificationAuthority = new CertificationAuthority(world, "CN=Root CA");
			certificationAuthority.setSignatureAlgorithm("SHA256withRSA");
			world.start();

			X509Certificate rootCert = certificationAuthority.getCertificate();

			MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();
			memoryCertificateRepository.addTrustPoint(rootCert);
			TrustValidator trustValidator = new TrustValidator(memoryCertificateRepository);

			trustValidator.isTrusted(Collections.singletonList(rootCert));
		}
	}

	@Test
	public void testRootCA_ECC() throws Exception {
		try (World world = new World()) {
			CertificationAuthority certificationAuthority = new CertificationAuthority(world, "CN=Root CA");
			certificationAuthority.setSignatureAlgorithm("SHA256withECDSA");
			world.start();

			X509Certificate rootCert = certificationAuthority.getCertificate();
			LOGGER.debug("certificate: {}", rootCert);

			MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();
			memoryCertificateRepository.addTrustPoint(rootCert);
			TrustValidator trustValidator = new TrustValidator(memoryCertificateRepository);

			trustValidator.isTrusted(Collections.singletonList(rootCert));
		}
	}

	@Test
	public void testTSA_ECC() throws Exception {
		try (World world = new World()) {
			CertificationAuthority certificationAuthority = new CertificationAuthority(world, "CN=Root CA");
			certificationAuthority.setSignatureAlgorithm("SHA256withECDSA");
			TimeStampAuthority timeStampAuthority = new TimeStampAuthority(world, certificationAuthority);
			timeStampAuthority.setKeyAlgorithm("EC");
			world.start();

			X509Certificate rootCert = certificationAuthority.getCertificate();
			LOGGER.debug("certificate: {}", rootCert);

			MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();
			memoryCertificateRepository.addTrustPoint(rootCert);
			TrustValidator trustValidator = new TrustValidator(memoryCertificateRepository);

			trustValidator.isTrusted(Collections.singletonList(rootCert));

			assertEquals("EC", timeStampAuthority.getCertificate().getPublicKey().getAlgorithm());
		}
	}

	@Test
	public void testECCSigningCertificate() throws Exception {
		try (World world = new World()) {
			CertificationAuthority certificationAuthority = new CertificationAuthority(world, "CN=Root CA");
			certificationAuthority.setSignatureAlgorithm("SHA256withECDSA");
			world.start();

			KeyPair keyPair = PKITestUtils.generateKeyPair("EC");
			X509Certificate certificate = certificationAuthority.issueSigningCertificate(keyPair.getPublic(),
					"CN=Signing");

			X509Certificate rootCert = certificationAuthority.getCertificate();
			LOGGER.debug("certificate: {}", rootCert);

			MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();
			memoryCertificateRepository.addTrustPoint(rootCert);
			TrustValidator trustValidator = new TrustValidator(memoryCertificateRepository);

			trustValidator.isTrusted(Collections.singletonList(rootCert));
		}
	}

	@Test
	public void testRevocation() throws Exception {
		try (World world = new World()) {
			CertificationAuthority certificationAuthority = new CertificationAuthority(world, "CN=Root CA");
			certificationAuthority.setSignatureAlgorithm("SHA256withRSA");
			certificationAuthority.addRevocationService(new CRLRevocationService());
			world.start();

			X509Certificate rootCert = certificationAuthority.getCertificate();

			KeyPair validKeyPair = PKITestUtils.generateKeyPair();
			X509Certificate validCertificate = certificationAuthority.issueSigningCertificate(validKeyPair.getPublic(),
					"CN=Valid");
			List<X509Certificate> validCertificateChain = Arrays
					.asList(new X509Certificate[] { validCertificate, rootCert });

			KeyPair revokedKeyPair = PKITestUtils.generateKeyPair();
			X509Certificate revokedCertificate = certificationAuthority
					.issueSigningCertificate(revokedKeyPair.getPublic(), "CN=Revoked");
			certificationAuthority.revoke(revokedCertificate);
			List<X509Certificate> revokedCertificationChain = Arrays
					.asList(new X509Certificate[] { revokedCertificate, rootCert });

			MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();
			memoryCertificateRepository.addTrustPoint(rootCert);
			TrustValidator trustValidator = new TrustValidator(memoryCertificateRepository);

			TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator();
			trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator);

			trustValidator.isTrusted(validCertificateChain);

			try {
				trustValidator.isTrusted(revokedCertificationChain);
				fail();
			} catch (Exception e) {
				// expected
			}
		}
	}

	@Test
	public void testRevocationOCSP() throws Exception {
		try (World world = new World()) {
			CertificationAuthority certificationAuthority = new CertificationAuthority(world, "CN=Root CA");
			certificationAuthority.setSignatureAlgorithm("SHA256withRSA");
			certificationAuthority.addRevocationService(new OCSPRevocationService());
			world.start();

			X509Certificate rootCert = certificationAuthority.getCertificate();

			KeyPair validKeyPair = PKITestUtils.generateKeyPair();
			X509Certificate validCertificate = certificationAuthority.issueSigningCertificate(validKeyPair.getPublic(),
					"CN=Valid");
			List<X509Certificate> validCertificateChain = Arrays
					.asList(new X509Certificate[] { validCertificate, rootCert });

			KeyPair revokedKeyPair = PKITestUtils.generateKeyPair();
			X509Certificate revokedCertificate = certificationAuthority
					.issueSigningCertificate(revokedKeyPair.getPublic(), "CN=Revoked");
			certificationAuthority.revoke(revokedCertificate);
			List<X509Certificate> revokedCertificationChain = Arrays
					.asList(new X509Certificate[] { revokedCertificate, rootCert });

			MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();
			memoryCertificateRepository.addTrustPoint(rootCert);
			TrustValidator trustValidator = new TrustValidator(memoryCertificateRepository);

			TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator();
			trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator);

			trustValidator.isTrusted(validCertificateChain);

			try {
				trustValidator.isTrusted(revokedCertificationChain);
				fail();
			} catch (Exception e) {
				// expected
			}
		}
	}

	@Test
	public void testNoProxy() throws Exception {
		try (World world = new World()) {
			CertificationAuthority certificationAuthority = new CertificationAuthority(world, "CN=Root CA");
			certificationAuthority.addRevocationService(new OCSPRevocationService());
			world.start();

			X509Certificate rootCert = certificationAuthority.getCertificate();

			KeyPair validKeyPair = PKITestUtils.generateKeyPair();
			X509Certificate validCertificate = certificationAuthority.issueSigningCertificate(validKeyPair.getPublic(),
					"CN=Valid");
			List<X509Certificate> validCertificateChain = Arrays
					.asList(new X509Certificate[] { validCertificate, rootCert });

			KeyPair proxyKeyPair = PKITestUtils.generateKeyPair();
			LocalDateTime notBefore = LocalDateTime.now();
			LocalDateTime notAfter = notBefore.plusMonths(1);
			X509Certificate proxyCertificate = PKITestUtils.generateCertificate(proxyKeyPair.getPublic(), "CN=Proxy",
					notBefore, notAfter, validCertificate, validKeyPair.getPrivate());
			List<X509Certificate> proxyCertificationChain = Arrays
					.asList(new X509Certificate[] { proxyCertificate, validCertificate, rootCert });

			MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();
			memoryCertificateRepository.addTrustPoint(rootCert);
			TrustValidator trustValidator = new TrustValidator(memoryCertificateRepository);

			TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator();
			trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator);

			trustValidator.isTrusted(validCertificateChain);

			try {
				trustValidator.isTrusted(proxyCertificationChain);
				fail();
			} catch (Exception e) {
				// expected
			}
		}
	}

	@Test
	public void testTwoCAs_ECC() throws Exception {
		try (World world = new World()) {
			CertificationAuthority rootCertificationAuthority = new CertificationAuthority(world, "CN=Root CA");
			rootCertificationAuthority.setSignatureAlgorithm("SHA256withECDSA");
			rootCertificationAuthority.addRevocationService(new CRLRevocationService());
			CertificationAuthority certificationAuthority = new CertificationAuthority(world, "CN=CA",
					rootCertificationAuthority);
			certificationAuthority.setSignatureAlgorithm("SHA256withECDSA");
			world.start();

			X509Certificate rootCert = rootCertificationAuthority.getCertificate();
			X509Certificate cert = certificationAuthority.getCertificate();
			List<X509Certificate> certChain = new LinkedList<>();
			certChain.add(cert);
			certChain.add(rootCert);

			MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();
			memoryCertificateRepository.addTrustPoint(rootCert);
			TrustValidator trustValidator = new TrustValidator(memoryCertificateRepository);

			TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator();
			trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator);

			trustValidator.isTrusted(certChain);
		}
	}

	@Test
	public void testTwoCAs() throws Exception {
		try (World world = new World()) {
			CertificationAuthority rootCertificationAuthority = new CertificationAuthority(world, "CN=Root CA");
			rootCertificationAuthority.setSignatureAlgorithm("SHA256withRSA");
			rootCertificationAuthority.addRevocationService(new CRLRevocationService());
			CertificationAuthority certificationAuthority = new CertificationAuthority(world, "CN=CA",
					rootCertificationAuthority);
			certificationAuthority.setSignatureAlgorithm("SHA256withRSA");
			world.start();

			X509Certificate rootCert = rootCertificationAuthority.getCertificate();
			X509Certificate cert = certificationAuthority.getCertificate();
			List<X509Certificate> certChain = new LinkedList<>();
			certChain.add(cert);
			certChain.add(rootCert);

			MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();
			memoryCertificateRepository.addTrustPoint(rootCert);
			TrustValidator trustValidator = new TrustValidator(memoryCertificateRepository);

			TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator();
			trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator);

			trustValidator.isTrusted(certChain);
		}
	}

	@Test
	public void testFailingCRL() throws Exception {
		try (World world = new World()) {
			CertificationAuthority rootCertificationAuthority = new CertificationAuthority(world, "CN=Root CA");
			rootCertificationAuthority.setSignatureAlgorithm("SHA256withRSA");
			CRLRevocationService crlRevocationService = new CRLRevocationService();
			BasicFailBehavior crlFailBehavior = new BasicFailBehavior();
			crlRevocationService.setFailureBehavior(crlFailBehavior);
			rootCertificationAuthority.addRevocationService(crlRevocationService);
			CertificationAuthority certificationAuthority = new CertificationAuthority(world, "CN=Intermediate CA",
					rootCertificationAuthority);
			certificationAuthority.setSignatureAlgorithm("SHA256withRSA");
			world.start();

			X509Certificate rootCert = rootCertificationAuthority.getCertificate();
			X509Certificate cert = certificationAuthority.getCertificate();
			List<X509Certificate> certChain = new LinkedList<>();
			certChain.add(cert);
			certChain.add(rootCert);

			MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();
			memoryCertificateRepository.addTrustPoint(rootCert);
			TrustValidator trustValidator = new TrustValidator(memoryCertificateRepository);

			TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator();
			trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator);

			crlFailBehavior.setFailing(true);
			assertThrows(TrustLinkerResultException.class, () -> trustValidator.isTrusted(certChain));
		}
	}

	@Test
	public void testTwoCAsOCSP() throws Exception {
		try (World world = new World()) {
			CertificationAuthority rootCertificationAuthority = new CertificationAuthority(world, "CN=Root CA");
			rootCertificationAuthority.addRevocationService(new OCSPRevocationService());
			CertificationAuthority certificationAuthority = new CertificationAuthority(world, "CN=CA",
					rootCertificationAuthority);
			world.start();

			X509Certificate rootCert = rootCertificationAuthority.getCertificate();
			X509Certificate cert = certificationAuthority.getCertificate();
			List<X509Certificate> certChain = new LinkedList<>();
			certChain.add(cert);
			certChain.add(rootCert);

			MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();
			memoryCertificateRepository.addTrustPoint(rootCert);
			TrustValidator trustValidator = new TrustValidator(memoryCertificateRepository);

			TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator();
			trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator);

			trustValidator.isTrusted(certChain);
		}
	}

	@Test
	public void testTwoCAsOCSP_ECC() throws Exception {
		try (World world = new World()) {
			CertificationAuthority rootCertificationAuthority = new CertificationAuthority(world, "CN=Root CA");
			rootCertificationAuthority.setSignatureAlgorithm("SHA256withECDSA");
			rootCertificationAuthority.addRevocationService(new OCSPRevocationService());
			CertificationAuthority certificationAuthority = new CertificationAuthority(world, "CN=CA",
					rootCertificationAuthority);
			certificationAuthority.setSignatureAlgorithm("SHA256withECDSA");
			world.start();

			X509Certificate rootCert = rootCertificationAuthority.getCertificate();
			X509Certificate cert = certificationAuthority.getCertificate();
			List<X509Certificate> certChain = new LinkedList<>();
			certChain.add(cert);
			certChain.add(rootCert);

			MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();
			memoryCertificateRepository.addTrustPoint(rootCert);
			TrustValidator trustValidator = new TrustValidator(memoryCertificateRepository);

			TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator();
			trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator);

			trustValidator.isTrusted(certChain);
		}
	}

	@Test
	public void testTwoCAsOCSPResponderCert() throws Exception {
		try (World world = new World()) {
			CertificationAuthority rootCertificationAuthority = new CertificationAuthority(world, "CN=Root CA");
			rootCertificationAuthority.addRevocationService(new OCSPRevocationService(true));
			CertificationAuthority certificationAuthority = new CertificationAuthority(world, "CN=CA",
					rootCertificationAuthority);
			world.start();

			X509Certificate rootCert = rootCertificationAuthority.getCertificate();
			X509Certificate cert = certificationAuthority.getCertificate();
			List<X509Certificate> certChain = new LinkedList<>();
			certChain.add(cert);
			certChain.add(rootCert);

			MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();
			memoryCertificateRepository.addTrustPoint(rootCert);
			TrustValidator trustValidator = new TrustValidator(memoryCertificateRepository);

			TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator();
			trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator);

			trustValidator.isTrusted(certChain);
		}
	}

	@Test
	public void testTwoCAsOCSPResponderCert_ECC() throws Exception {
		try (World world = new World()) {
			CertificationAuthority rootCertificationAuthority = new CertificationAuthority(world, "CN=Root CA");
			rootCertificationAuthority.setSignatureAlgorithm("SHA256withECDSA");
			rootCertificationAuthority.addRevocationService(new OCSPRevocationService(true));
			CertificationAuthority certificationAuthority = new CertificationAuthority(world, "CN=CA",
					rootCertificationAuthority);
			certificationAuthority.setSignatureAlgorithm("SHA256withECDSA");
			world.start();

			X509Certificate rootCert = rootCertificationAuthority.getCertificate();
			X509Certificate cert = certificationAuthority.getCertificate();
			List<X509Certificate> certChain = new LinkedList<>();
			certChain.add(cert);
			certChain.add(rootCert);

			MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();
			memoryCertificateRepository.addTrustPoint(rootCert);
			TrustValidator trustValidator = new TrustValidator(memoryCertificateRepository);

			TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator();
			trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator);

			trustValidator.isTrusted(certChain);
		}
	}

	@Test
	public void testExpiredRootCA() throws Exception {
		Clock clock = new FixedClock(LocalDateTime.now().minusYears(10));
		try (World world = new World(clock)) {
			CertificationAuthority certificationAuthority = new CertificationAuthority(world, "CN=Root CA");
			world.start();

			X509Certificate rootCert = certificationAuthority.getCertificate();

			MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();
			memoryCertificateRepository.addTrustPoint(rootCert);
			TrustValidator trustValidator = new TrustValidator(memoryCertificateRepository);

			trustValidator.isTrusted(Collections.singletonList(rootCert),
					Date.from(clock.getTime().atZone(ZoneId.systemDefault()).toInstant()));

			try {
				trustValidator.isTrusted(Collections.singletonList(rootCert));
				fail();
			} catch (TrustLinkerResultException e) {
				// expected
			}
		}
	}

	@Test
	public void testTwoCAsExpired() throws Exception {
		Clock clock = new FixedClock(LocalDateTime.now().minusYears(10));
		try (World world = new World(clock)) {
			CertificationAuthority rootCertificationAuthority = new CertificationAuthority(world, "CN=Root CA");
			rootCertificationAuthority.addRevocationService(new CRLRevocationService());
			CertificationAuthority certificationAuthority = new CertificationAuthority(world, "CN=CA",
					rootCertificationAuthority);
			world.start();

			X509Certificate rootCert = rootCertificationAuthority.getCertificate();
			X509Certificate cert = certificationAuthority.getCertificate();
			List<X509Certificate> certChain = new LinkedList<>();
			certChain.add(cert);
			certChain.add(rootCert);

			MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();
			memoryCertificateRepository.addTrustPoint(rootCert);
			TrustValidator trustValidator = new TrustValidator(memoryCertificateRepository);

			TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator();
			trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator);

			trustValidator.isTrusted(certChain, Date.from(clock.getTime().atZone(ZoneId.systemDefault()).toInstant()));

			try {
				trustValidator.isTrusted(certChain);
				fail();
			} catch (TrustLinkerResultException e) {
				// expected
			}
		}
	}

	@Test
	public void testExpiredCRL() throws Exception {
		Clock clock = new FixedClock(LocalDateTime.now().minusYears(10));
		try (World world = new World(clock)) {
			CertificationAuthority rootCertificationAuthority = new CertificationAuthority(world, "CN=Root CA");
			rootCertificationAuthority.addRevocationService(new CRLRevocationService());
			CertificationAuthority certificationAuthority = new CertificationAuthority(world, "CN=CA",
					rootCertificationAuthority);
			world.start();

			X509Certificate rootCert = rootCertificationAuthority.getCertificate();
			X509Certificate cert = certificationAuthority.getCertificate();
			List<X509Certificate> certChain = new LinkedList<>();
			certChain.add(cert);
			certChain.add(rootCert);

			MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();
			memoryCertificateRepository.addTrustPoint(rootCert);
			TrustValidator trustValidator = new TrustValidator(memoryCertificateRepository);

			TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator();
			trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator);

			trustValidator.isTrusted(certChain, Date.from(clock.getTime().atZone(ZoneId.systemDefault()).toInstant()));

			try {
				LocalDateTime crlExpiredDateTime = clock.getTime().plusDays(2);
				trustValidator.isTrusted(certChain, crlExpiredDateTime);
				fail();
			} catch (TrustLinkerResultException e) {
				// expected
			}
		}
	}

	@Test
	public void testExpiredOCSP() throws Exception {
		Clock clock = new FixedClock(LocalDateTime.now().minusYears(10));
		try (World world = new World(clock)) {
			CertificationAuthority rootCertificationAuthority = new CertificationAuthority(world, "CN=Root CA");
			rootCertificationAuthority.addRevocationService(new OCSPRevocationService());
			CertificationAuthority certificationAuthority = new CertificationAuthority(world, "CN=CA",
					rootCertificationAuthority);
			world.start();

			X509Certificate rootCert = rootCertificationAuthority.getCertificate();
			X509Certificate cert = certificationAuthority.getCertificate();
			List<X509Certificate> certChain = new LinkedList<>();
			certChain.add(cert);
			certChain.add(rootCert);

			MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();
			memoryCertificateRepository.addTrustPoint(rootCert);
			TrustValidator trustValidator = new TrustValidator(memoryCertificateRepository);

			TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator();
			trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator);

			trustValidator.isTrusted(certChain, Date.from(clock.getTime().atZone(ZoneId.systemDefault()).toInstant()));

			try {
				LocalDateTime ocspExpiredDateTime = clock.getTime().plusDays(2);
				trustValidator.isTrusted(certChain,
						Date.from(ocspExpiredDateTime.atZone(ZoneId.systemDefault()).toInstant()));
				fail();
			} catch (TrustLinkerResultException e) {
				// expected
			}
		}
	}

	@Test
	public void testReissueCRL() throws Exception {
		try (World world = new World()) {
			CertificationAuthority rootCertificationAuthority = new CertificationAuthority(world, "CN=Root CA");
			rootCertificationAuthority.addRevocationService(new CRLRevocationService());

			CertificationAuthority certificationAuthority = new CertificationAuthority(world, "CN=CA",
					rootCertificationAuthority);
			certificationAuthority.addRevocationService(new CRLRevocationService());

			world.start();

			KeyPair keyPair = PKITestUtils.generateKeyPair();
			X509Certificate certificate = certificationAuthority.issueSigningCertificate(keyPair.getPublic(),
					"CN=End Entity");

			X509Certificate rootCert = rootCertificationAuthority.getCertificate();
			X509Certificate caCert = certificationAuthority.getCertificate();
			List<X509Certificate> certChain = new LinkedList<>();
			certChain.add(certificate);
			certChain.add(caCert);
			certChain.add(rootCert);

			MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();
			memoryCertificateRepository.addTrustPoint(rootCert);
			TrustValidator trustValidator = new TrustValidator(memoryCertificateRepository);

			TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator();
			trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator, null, false, new OnlineCrlRepository());

			trustValidator.isTrusted(certChain);

			certificationAuthority.reissueCertificate("CN=CA");

			try {
				trustValidator.isTrusted(certChain);
				fail();
			} catch (TrustLinkerResultException e) {
				// expected
			}
		}
	}

	@Test
	public void testFailingOCSPResponder() throws Exception {
		try (World world = new World()) {
			CertificationAuthority rootCertificationAuthority = new CertificationAuthority(world, "CN=Root CA");
			rootCertificationAuthority.addRevocationService(new CRLRevocationService());

			CertificationAuthority certificationAuthority = new CertificationAuthority(world, "CN=Intermediate CA",
					rootCertificationAuthority);
			OCSPRevocationService ocspRevocationService = new OCSPRevocationService();
			BasicFailBehavior ocspFailBehavior = new BasicFailBehavior();
			ocspRevocationService.setFailureBehavior(ocspFailBehavior);
			certificationAuthority.addRevocationService(ocspRevocationService);
			certificationAuthority.addRevocationService(new CRLRevocationService());

			world.start();

			KeyPair keyPair = PKITestUtils.generateKeyPair();
			X509Certificate certificate = certificationAuthority.issueSigningCertificate(keyPair.getPublic(),
					"CN=End Entity");

			X509Certificate rootCert = rootCertificationAuthority.getCertificate();
			X509Certificate caCert = certificationAuthority.getCertificate();
			List<X509Certificate> certChain = new LinkedList<>();
			certChain.add(certificate);
			certChain.add(caCert);
			certChain.add(rootCert);

			MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();
			memoryCertificateRepository.addTrustPoint(rootCert);
			TrustValidator trustValidator = new TrustValidator(memoryCertificateRepository);

			TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator();
			trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator);

			ocspFailBehavior.setFailing(true);
			trustValidator.isTrusted(certChain);
		}
	}

	@Test
	public void testFailingOCSPClock() throws Exception {
		try (World world = new World()) {
			CertificationAuthority rootCertificationAuthority = new CertificationAuthority(world, "CN=Root CA");
			rootCertificationAuthority.addRevocationService(new CRLRevocationService());

			CertificationAuthority certificationAuthority = new CertificationAuthority(world, "CN=Intermediate CA",
					rootCertificationAuthority);
			OCSPRevocationService ocspRevocationService = new OCSPRevocationService();
			BasicOCSPFailBehavior ocspFailBehavior = new BasicOCSPFailBehavior();
			ocspRevocationService.setFailureBehavior(ocspFailBehavior);
			certificationAuthority.addRevocationService(ocspRevocationService);

			world.start();

			KeyPair keyPair = PKITestUtils.generateKeyPair();
			X509Certificate certificate = certificationAuthority.issueSigningCertificate(keyPair.getPublic(),
					"CN=End Entity");

			X509Certificate rootCert = rootCertificationAuthority.getCertificate();
			X509Certificate caCert = certificationAuthority.getCertificate();
			List<X509Certificate> certChain = new LinkedList<>();
			certChain.add(certificate);
			certChain.add(caCert);
			certChain.add(rootCert);

			MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();
			memoryCertificateRepository.addTrustPoint(rootCert);
			TrustValidator trustValidator = new TrustValidator(memoryCertificateRepository);

			TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator();
			trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator);

			ocspFailBehavior.setFailingClock(new FixedClock(LocalDateTime.now().plusHours(1)));
			assertThrows(TrustLinkerResultException.class, () -> trustValidator.isTrusted(certChain));
		}
	}

	@Test
	public void testReissueOCSP() throws Exception {
		try (World world = new World()) {
			CertificationAuthority rootCertificationAuthority = new CertificationAuthority(world, "CN=Root CA");
			rootCertificationAuthority.addRevocationService(new OCSPRevocationService());

			CertificationAuthority certificationAuthority = new CertificationAuthority(world, "CN=CA",
					rootCertificationAuthority);
			OCSPRevocationService ocspRevocationService = new OCSPRevocationService();
			certificationAuthority.addRevocationService(ocspRevocationService);

			world.start();

			KeyPair keyPair = PKITestUtils.generateKeyPair();
			X509Certificate certificate = certificationAuthority.issueSigningCertificate(keyPair.getPublic(),
					"CN=End Entity");

			X509Certificate rootCert = rootCertificationAuthority.getCertificate();
			X509Certificate caCert = certificationAuthority.getCertificate();
			List<X509Certificate> certChain = new LinkedList<>();
			certChain.add(certificate);
			certChain.add(caCert);
			certChain.add(rootCert);

			MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();
			memoryCertificateRepository.addTrustPoint(rootCert);
			TrustValidator trustValidator = new TrustValidator(memoryCertificateRepository);

			TrustValidatorDecorator trustValidatorDecorator = new TrustValidatorDecorator();
			trustValidatorDecorator.addDefaultTrustLinkerConfig(trustValidator);

			trustValidator.isTrusted(certChain);

			certificationAuthority.reissueCertificate("CN=CA");
			ocspRevocationService.reissueCertificate("CN=OCSP Responder");

			try {
				trustValidator.isTrusted(certChain);
				fail();
			} catch (TrustLinkerResultException e) {
				// expected
			}
		}
	}
}
