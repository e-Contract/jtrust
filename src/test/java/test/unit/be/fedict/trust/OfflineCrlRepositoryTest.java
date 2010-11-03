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

import be.fedict.trust.crl.OfflineCrlRepository;
import org.joda.time.DateTime;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.net.URI;
import java.security.KeyPair;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;

import static org.junit.Assert.*;

public class OfflineCrlRepositoryTest {

	private Date validationDate;

	@Before
	public void setUp() throws Exception {
		this.validationDate = new Date();
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testCrlFound() throws Exception {

		// setup
		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = TrustTestUtils
				.generateSelfSignedCertificate(keyPair, "CN=Test", notBefore,
						notAfter);
		X509CRL crl = TrustTestUtils.generateCrl(keyPair.getPrivate(),
				certificate, notBefore, notAfter);

		OfflineCrlRepository testedInstance = new OfflineCrlRepository(
				Collections.singletonList(crl.getEncoded()));

		// operate
		X509CRL resultCrl = testedInstance.findCrl(
				new URI("http://foo.org/bar"), certificate, validationDate);

		// verify
		assertNotNull(resultCrl);
		assertEquals(crl, resultCrl);
	}

	@Test
	public void testCrlNotFound() throws Exception {

		// setup
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils
				.generateSelfSignedCertificate(keyPair, "CN=Test", notBefore,
						notAfter);

		KeyPair otherKeyPair = TrustTestUtils.generateKeyPair();
		X509Certificate otherCertificate = TrustTestUtils
				.generateSelfSignedCertificate(otherKeyPair, "CN=TestOther",
						notBefore, notAfter);

		X509CRL crl = TrustTestUtils.generateCrl(otherKeyPair.getPrivate(),
				otherCertificate, notBefore, notAfter);

		OfflineCrlRepository testedInstance = new OfflineCrlRepository(
				Collections.singletonList(crl.getEncoded()));

		// operate
		X509CRL resultCrl = testedInstance.findCrl(
				new URI("http://foo.org/bar"), certificate, validationDate);

		// verify
		assertNull(resultCrl);
	}
}
