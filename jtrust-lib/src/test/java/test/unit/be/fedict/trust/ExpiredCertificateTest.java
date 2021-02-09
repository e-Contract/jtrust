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

import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
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
import be.fedict.trust.repository.MemoryCertificateRepository;
import be.fedict.trust.test.CRLRevocationService;
import be.fedict.trust.test.CertificationAuthority;
import be.fedict.trust.test.Clock;
import be.fedict.trust.test.FixedClock;
import be.fedict.trust.test.World;

public class ExpiredCertificateTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(ExpiredCertificateTest.class);

	@BeforeAll
	public static void oneTimeSetUp() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
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

			trustValidator.isTrusted(Collections.singletonList(rootCert), true);
		}
	}

	@Test
	public void testExpiredRootCAJava8DateTimeAPI() throws Exception {
		Clock clock = new FixedClock(LocalDateTime.now().minusYears(10));
		try (World world = new World(clock)) {
			CertificationAuthority certificationAuthority = new CertificationAuthority(world, "CN=Root CA");
			world.start();

			X509Certificate rootCert = certificationAuthority.getCertificate();

			MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();
			memoryCertificateRepository.addTrustPoint(rootCert);
			TrustValidator trustValidator = new TrustValidator(memoryCertificateRepository);

			LOGGER.debug("isTrusted test");
			trustValidator.isTrusted(Collections.singletonList(rootCert), clock.getTime().plusMonths(2));

			LOGGER.debug("isTrusted test expired mode");
			trustValidator.isTrusted(Collections.singletonList(rootCert), true);
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
			trustValidatorDecorator.addTrustLinkerConfigWithoutRevocationStatus(trustValidator);

			trustValidator.isTrusted(certChain, Date.from(clock.getTime().atZone(ZoneId.systemDefault()).toInstant()));

			LocalDateTime crlExpiredDateTime = clock.getTime().plusDays(2);
			trustValidator.isTrusted(certChain,
					Date.from(crlExpiredDateTime.atZone(ZoneId.systemDefault()).toInstant()), true);

			trustValidator.isTrusted(certChain, true);
		}
	}
}
