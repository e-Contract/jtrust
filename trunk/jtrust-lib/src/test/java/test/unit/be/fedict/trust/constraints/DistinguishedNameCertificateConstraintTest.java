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

import java.security.KeyPair;
import java.security.cert.X509Certificate;

import be.fedict.trust.TrustLinkerResultException;
import be.fedict.trust.TrustLinkerResultReason;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;

import test.unit.be.fedict.trust.TrustTestUtils;
import be.fedict.trust.constraints.DistinguishedNameCertificateConstraint;

import static org.junit.Assert.*;

public class DistinguishedNameCertificateConstraintTest {

	private DistinguishedNameCertificateConstraint testedInstance;

	private final String validSubjectName = "CN=Test";

	@Before
	public void setUp() throws Exception {
		this.testedInstance = new DistinguishedNameCertificateConstraint(
				validSubjectName);
	}

	@Test
	public void testDistinguishedNameMisMatch() throws Exception {
		// setup
		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = TrustTestUtils
				.generateSelfSignedCertificate(keyPair, "CN=F00", notBefore,
						notAfter);

		// operate
        try {
            this.testedInstance.check(certificate);
            fail();
        } catch (TrustLinkerResultException e) {
            assertEquals(TrustLinkerResultReason.CONSTRAINT_VIOLATION, e.getReason());
        }
	}

	@Test
	public void testDistinguishedNameMatch() throws Exception {
		// setup
		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = TrustTestUtils
				.generateSelfSignedCertificate(keyPair, "CN=Test", notBefore,
						notAfter);

		// operate
		this.testedInstance.check(certificate);
	}
}