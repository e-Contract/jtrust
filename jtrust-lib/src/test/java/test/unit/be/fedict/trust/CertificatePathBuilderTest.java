/*
 * Java Trust Project.
 * Copyright (C) 2011 FedICT.
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;

import be.fedict.trust.CertificatePathBuilder;

public class CertificatePathBuilderTest {

	private CertificatePathBuilder testedInstance;

	@Before
	public void setUp() throws Exception {
		this.testedInstance = new CertificatePathBuilder();
	}

	@Test
	public void testSelfSignedCertificate() throws Exception {
		// setup
		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = TrustTestUtils
				.generateSelfSignedCertificate(keyPair, "CN=TestCA", notBefore,
						notAfter);

		// operate
		List<X509Certificate> result = this.testedInstance
				.buildPath(Collections.singletonList(certificate));

		// verify
		assertNotNull(result);
		assertEquals(1, result.size());
		assertEquals(result.get(0), certificate);
	}

}
