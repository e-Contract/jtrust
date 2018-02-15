/*
 * Java Trust Project.
 * Copyright (C) 2012 FedICT.
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;

import be.fedict.trust.constraints.CodeSigningCertificateConstraint;
import be.fedict.trust.linker.TrustLinkerResultException;
import be.fedict.trust.linker.TrustLinkerResultReason;
import be.fedict.trust.test.PKITestUtils;

public class CodeSigningCertificateConstraintTest {

	private CodeSigningCertificateConstraint testedInstance;

	@Before
	public void setUp() throws Exception {
		this.testedInstance = new CodeSigningCertificateConstraint();
	}

	@Test
	public void testCodeSigningCertificatePasses() throws Exception {
		// setup
		final X509Certificate certificate = PKITestUtils
				.loadCertificate("/code-signing-fedict.der");

		// operate
		this.testedInstance.check(certificate);
	}

	@Test
	public void testNonCodeSigningCertificateFails() throws Exception {
		// setup
		final KeyPair keyPair = PKITestUtils.generateKeyPair();
		final DateTime notBefore = new DateTime();
		final DateTime notAfter = notBefore.plusMonths(1);
		final X509Certificate certificate = PKITestUtils
				.generateSelfSignedCertificate(keyPair, "CN=Test", notBefore,
						notAfter);

		// operate & verify
		try {
			this.testedInstance.check(certificate);
			fail();
		} catch (final TrustLinkerResultException e) {
			assertEquals(TrustLinkerResultReason.CONSTRAINT_VIOLATION,
					e.getReason());
		}
	}
}
