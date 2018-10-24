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

package test.unit.be.fedict.trust;

import static org.junit.Assert.fail;

import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.joda.time.DateTime;
import org.junit.BeforeClass;
import org.junit.Test;

import be.fedict.trust.TrustValidator;
import be.fedict.trust.TrustValidatorDecorator;
import be.fedict.trust.crl.OnlineCrlRepository;
import be.fedict.trust.linker.TrustLinkerResultException;
import be.fedict.trust.repository.MemoryCertificateRepository;
import be.fedict.trust.test.CRLRevocationService;
import be.fedict.trust.test.CertificationAuthority;
import be.fedict.trust.test.Clock;
import be.fedict.trust.test.FixedClock;
import be.fedict.trust.test.OCSPRevocationService;
import be.fedict.trust.test.PKITestUtils;
import be.fedict.trust.test.World;

public class ScenarioTest {

	@BeforeClass
	public static void oneTimeSetUp() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void testRootCA() throws Exception {
		World world = new World();
		CertificationAuthority certificationAuthority = new CertificationAuthority(world, "CN=Root CA");
		world.start();

		X509Certificate rootCert = certificationAuthority.getCertificate();

		MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();
		memoryCertificateRepository.addTrustPoint(rootCert);
		TrustValidator trustValidator = new TrustValidator(memoryCertificateRepository);

		trustValidator.isTrusted(Collections.singletonList(rootCert));

		world.stop();
	}

	@Test
	public void testRevocation() throws Exception {
		World world = new World();
		CertificationAuthority certificationAuthority = new CertificationAuthority(world, "CN=Root CA");
		certificationAuthority.addRevocationService(new CRLRevocationService());
		world.start();

		X509Certificate rootCert = certificationAuthority.getCertificate();

		KeyPair validKeyPair = PKITestUtils.generateKeyPair();
		X509Certificate validCertificate = certificationAuthority.issueSigningCertificate(validKeyPair.getPublic(),
				"CN=Valid");
		List<X509Certificate> validCertificateChain = Arrays
				.asList(new X509Certificate[] { validCertificate, rootCert });

		KeyPair revokedKeyPair = PKITestUtils.generateKeyPair();
		X509Certificate revokedCertificate = certificationAuthority.issueSigningCertificate(revokedKeyPair.getPublic(),
				"CN=Revoked");
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

		world.stop();
	}

	@Test
	public void testRevocationOCSP() throws Exception {
		World world = new World();
		CertificationAuthority certificationAuthority = new CertificationAuthority(world, "CN=Root CA");
		certificationAuthority.addRevocationService(new OCSPRevocationService());
		world.start();

		X509Certificate rootCert = certificationAuthority.getCertificate();

		KeyPair validKeyPair = PKITestUtils.generateKeyPair();
		X509Certificate validCertificate = certificationAuthority.issueSigningCertificate(validKeyPair.getPublic(),
				"CN=Valid");
		List<X509Certificate> validCertificateChain = Arrays
				.asList(new X509Certificate[] { validCertificate, rootCert });

		KeyPair revokedKeyPair = PKITestUtils.generateKeyPair();
		X509Certificate revokedCertificate = certificationAuthority.issueSigningCertificate(revokedKeyPair.getPublic(),
				"CN=Revoked");
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

		world.stop();
	}

	@Test
	public void testNoProxy() throws Exception {
		World world = new World();
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
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
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

		world.stop();
	}

	@Test
	public void testTwoCAs() throws Exception {
		World world = new World();
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

		trustValidator.isTrusted(certChain);

		world.stop();
	}

	@Test
	public void testTwoCAsOCSP() throws Exception {
		World world = new World();
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

		world.stop();
	}

	@Test
	public void testTwoCAsOCSPResponderCert() throws Exception {
		World world = new World();
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

		world.stop();
	}

	@Test
	public void testExpiredRootCA() throws Exception {
		Clock clock = new FixedClock(new DateTime().minusYears(10));
		World world = new World(clock);
		CertificationAuthority certificationAuthority = new CertificationAuthority(world, "CN=Root CA");
		world.start();

		X509Certificate rootCert = certificationAuthority.getCertificate();

		MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();
		memoryCertificateRepository.addTrustPoint(rootCert);
		TrustValidator trustValidator = new TrustValidator(memoryCertificateRepository);

		trustValidator.isTrusted(Collections.singletonList(rootCert), clock.getTime().toDate());

		try {
			trustValidator.isTrusted(Collections.singletonList(rootCert));
			fail();
		} catch (TrustLinkerResultException e) {
			// expected
		} finally {
			world.stop();
		}
	}

	@Test
	public void testTwoCAsExpired() throws Exception {
		Clock clock = new FixedClock(new DateTime().minusYears(10));
		World world = new World(clock);
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

		trustValidator.isTrusted(certChain, clock.getTime().toDate());

		try {
			trustValidator.isTrusted(certChain);
			fail();
		} catch (TrustLinkerResultException e) {
			// expected
		} finally {
			world.stop();
		}
	}

	@Test
	public void testExpiredCRL() throws Exception {
		Clock clock = new FixedClock(new DateTime().minusYears(10));
		World world = new World(clock);
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

		trustValidator.isTrusted(certChain, clock.getTime().toDate());

		try {
			DateTime crlExpiredDateTime = clock.getTime().plusDays(2);
			trustValidator.isTrusted(certChain, crlExpiredDateTime.toDate());
			fail();
		} catch (TrustLinkerResultException e) {
			// expected
		} finally {
			world.stop();
		}
	}

	@Test
	public void testExpiredOCSP() throws Exception {
		Clock clock = new FixedClock(new DateTime().minusYears(10));
		World world = new World(clock);
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

		trustValidator.isTrusted(certChain, clock.getTime().toDate());

		try {
			DateTime ocspExpiredDateTime = clock.getTime().plusDays(2);
			trustValidator.isTrusted(certChain, ocspExpiredDateTime.toDate());
			fail();
		} catch (TrustLinkerResultException e) {
			// expected
		} finally {
			world.stop();
		}
	}

	@Test
	public void testReissueCRL() throws Exception {
		World world = new World();
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

		world.stop();
	}

	@Test
	public void testReissueOCSP() throws Exception {
		World world = new World();
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

		world.stop();
	}
}
