/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.joda.time.DateTime;
import org.junit.Test;

import be.fedict.trust.MemoryCertificateRepository;

public class MemoryCertificateRepositoryTest {

	private static final Log LOG = LogFactory
			.getLog(MemoryCertificateRepositoryTest.class);

	@Test
	public void trustPointFound() throws Exception {

		// setup
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils
				.generateSelfSignedCertificate(keyPair, "CN=Test", notBefore,
						notAfter);

		MemoryCertificateRepository testedInstance = new MemoryCertificateRepository();
		testedInstance.addTrustPoint(certificate);

		// operate
		assertTrue(testedInstance.isTrustPoint(certificate));
	}

	@Test
	public void trustPointNotFound() throws Exception {

		// setup
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils
				.generateSelfSignedCertificate(keyPair, "CN=Test", notBefore,
						notAfter);
		X509Certificate certificate2 = TrustTestUtils
				.generateSelfSignedCertificate(keyPair, "CN=Test2", notBefore,
						notAfter);

		MemoryCertificateRepository testedInstance = new MemoryCertificateRepository();
		testedInstance.addTrustPoint(certificate);

		// operate
		assertFalse(testedInstance.isTrustPoint(certificate2));
	}

	@Test
	public void trustPointFoundByDifferentCryptoProvider() throws Exception {

		// setup
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate trustPoint = TrustTestUtils
				.generateSelfSignedCertificate(keyPair, "CN=Test", notBefore,
						notAfter);
		LOG.debug("trust point certificate impl class: "
				+ trustPoint.getClass().getName());

		MemoryCertificateRepository testedInstance = new MemoryCertificateRepository();
		testedInstance.addTrustPoint(trustPoint);

		CertificateFactory certificateFactory = CertificateFactory.getInstance(
				"X.509", new BouncyCastleProvider());
		X509Certificate certificate = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(trustPoint
						.getEncoded()));
		LOG.debug("certificate impl class: " + certificate.getClass().getName());

		// operate
		assertFalse(certificate.getClass().equals(trustPoint.getClass()));
		assertTrue(testedInstance.isTrustPoint(certificate));
	}
}
