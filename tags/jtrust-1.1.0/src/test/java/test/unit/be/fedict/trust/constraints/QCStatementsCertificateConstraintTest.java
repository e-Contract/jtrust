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
import org.junit.Test;

import test.unit.be.fedict.trust.TrustTestUtils;
import be.fedict.trust.constraints.QCStatementsCertificateConstraint;

public class QCStatementsCertificateConstraintTest {

	@Test
	public void testNoQCStatements() throws Exception {

		// setup
		QCStatementsCertificateConstraint testedInstance = new QCStatementsCertificateConstraint(
				Boolean.TRUE);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = TrustTestUtils
				.generateSelfSignedCertificate(keyPair, "CN=Test", notBefore,
						notAfter);

		// operate
		assertFalse(testedInstance.check(certificate));
	}

	@Test
	public void testQCComplianceMatch() throws Exception {

		// setup
		QCStatementsCertificateConstraint testedInstance = new QCStatementsCertificateConstraint(
				Boolean.TRUE);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter, null,
				keyPair.getPrivate(), true, -1, null, null, null,
				"SHA1withRSA", false, false, false, null, null, Boolean.TRUE);

		// operate
		assertTrue(testedInstance.check(certificate));
	}

	@Test
	public void testQCComplianceMisMatch() throws Exception {

		// setup
		QCStatementsCertificateConstraint testedInstance = new QCStatementsCertificateConstraint(
				Boolean.TRUE);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter, null,
				keyPair.getPrivate(), true, -1, null, null, null,
				"SHA1withRSA", false, false, false, null, null, Boolean.FALSE);

		// operate
		assertFalse(testedInstance.check(certificate));
	}

	@Test
	public void testNoQCComplianceNeeded() throws Exception {

		// setup
		QCStatementsCertificateConstraint testedInstance = new QCStatementsCertificateConstraint(
				null);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter, null,
				keyPair.getPrivate(), true, -1, null, null, null,
				"SHA1withRSA", false, false, false, null, null, Boolean.TRUE);

		// operate
		assertTrue(testedInstance.check(certificate));
	}
}
