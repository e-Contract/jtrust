/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
 * Copyright (C) 2019-2023 e-Contract.be BV.
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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.fedict.trust.repository.MemoryCertificateRepository;
import be.fedict.trust.test.PKIBuilder;

public class MemoryCertificateRepositoryTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(MemoryCertificateRepositoryTest.class);

	@Test
	public void trustPointFound() throws Exception {
		// setup
		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair).withSubjectName("CN=Test")
				.withValidityMonths(1).build();

		MemoryCertificateRepository testedInstance = new MemoryCertificateRepository();
		testedInstance.addTrustPoint(certificate);

		// operate
		assertTrue(testedInstance.isTrustPoint(certificate));
	}

	@Test
	public void trustPointNotFound() throws Exception {
		// setup
		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair).withSubjectName("CN=Test")
				.withValidityMonths(1).build();
		X509Certificate certificate2 = new PKIBuilder.CertificateBuilder(keyPair).withSubjectName("CN=Test2")
				.withValidityMonths(1).build();

		MemoryCertificateRepository testedInstance = new MemoryCertificateRepository();
		testedInstance.addTrustPoint(certificate);

		// operate
		assertFalse(testedInstance.isTrustPoint(certificate2));
	}

	@Test
	public void trustPointFoundByDifferentCryptoProvider() throws Exception {
		// setup
		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate trustPoint = new PKIBuilder.CertificateBuilder(keyPair).withSubjectName("CN=Test")
				.withValidityMonths(1).build();
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
