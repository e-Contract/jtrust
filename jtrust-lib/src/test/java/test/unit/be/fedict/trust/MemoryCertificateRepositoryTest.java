/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
 * Copyright (C) 2019-2021 e-Contract.be BV.
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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.fedict.trust.repository.MemoryCertificateRepository;
import be.fedict.trust.test.PKITestUtils;

public class MemoryCertificateRepositoryTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(MemoryCertificateRepositoryTest.class);

	@Test
	public void trustPointFound() throws Exception {

		// setup
		LocalDateTime notBefore = LocalDateTime.now();
		LocalDateTime notAfter = notBefore.plusMonths(1);
		KeyPair keyPair = PKITestUtils.generateKeyPair();
		X509Certificate certificate = PKITestUtils.generateSelfSignedCertificate(keyPair, "CN=Test", notBefore,
				notAfter);

		MemoryCertificateRepository testedInstance = new MemoryCertificateRepository();
		testedInstance.addTrustPoint(certificate);

		// operate
		assertTrue(testedInstance.isTrustPoint(certificate));
	}

	@Test
	public void trustPointNotFound() throws Exception {

		// setup
		LocalDateTime notBefore = LocalDateTime.now();
		LocalDateTime notAfter = notBefore.plusMonths(1);
		KeyPair keyPair = PKITestUtils.generateKeyPair();
		X509Certificate certificate = PKITestUtils.generateSelfSignedCertificate(keyPair, "CN=Test", notBefore,
				notAfter);
		X509Certificate certificate2 = PKITestUtils.generateSelfSignedCertificate(keyPair, "CN=Test2", notBefore,
				notAfter);

		MemoryCertificateRepository testedInstance = new MemoryCertificateRepository();
		testedInstance.addTrustPoint(certificate);

		// operate
		assertFalse(testedInstance.isTrustPoint(certificate2));
	}

	@Test
	public void trustPointFoundByDifferentCryptoProvider() throws Exception {

		// setup
		LocalDateTime notBefore = LocalDateTime.now();
		LocalDateTime notAfter = notBefore.plusMonths(1);
		KeyPair keyPair = PKITestUtils.generateKeyPair();
		X509Certificate trustPoint = PKITestUtils.generateSelfSignedCertificate(keyPair, "CN=Test", notBefore,
				notAfter);
		LOGGER.debug("trust point certificate impl class: {}", trustPoint.getClass().getName());

		MemoryCertificateRepository testedInstance = new MemoryCertificateRepository();
		testedInstance.addTrustPoint(trustPoint);

		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", new BouncyCastleProvider());
		X509Certificate certificate = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(trustPoint.getEncoded()));
		LOGGER.debug("certificate impl class: {}", certificate.getClass().getName());

		// operate
		assertFalse(certificate.getClass().equals(trustPoint.getClass()));
		assertTrue(testedInstance.isTrustPoint(certificate));
	}
}
