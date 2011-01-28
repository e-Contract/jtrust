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

package test.unit.be.fedict.trust.constraints;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;

import test.unit.be.fedict.trust.TrustTestUtils;

import be.fedict.trust.constraints.TSACertificateConstraint;

public class TSACertificateConstraintTest {

	private TSACertificateConstraint testedInstance;

	@Before
	public void setUp() throws Exception {
		this.testedInstance = new TSACertificateConstraint();
	}

	@Test
	public void testValidTSAConstraint() throws Exception {
		// setup
		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=TestTSA", notBefore, notAfter, null,
				keyPair.getPrivate(), true, -1, null, null, null,
				"SHA1withRSA", true);

		// operate
		assertTrue(this.testedInstance.check(certificate));
	}

	@Test
	public void testInvalidTSAConstraint() throws Exception {
		// setup
		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=TestTSA", notBefore, notAfter, null,
				keyPair.getPrivate(), true, -1, null, null, null,
				"SHA1withRSA", false);

		// operate
		assertFalse(this.testedInstance.check(certificate));
	}
}
