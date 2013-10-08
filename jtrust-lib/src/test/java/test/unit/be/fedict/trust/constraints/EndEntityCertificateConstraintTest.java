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

import be.fedict.trust.linker.TrustLinkerResultException;
import be.fedict.trust.linker.TrustLinkerResultReason;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;

import test.unit.be.fedict.trust.TrustTestUtils;
import be.fedict.trust.constraints.EndEntityCertificateConstraint;

import static org.junit.Assert.*;

public class EndEntityCertificateConstraintTest {

	private EndEntityCertificateConstraint testedInstance;

	@Before
	public void setUp() throws Exception {
		this.testedInstance = new EndEntityCertificateConstraint();
	}

	@Test
	public void testEmptyEndEntities() throws Exception {
		// setup
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);

		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils
				.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
						notAfter, rootCertificate, rootKeyPair.getPrivate(),
						false, 0, null, null);

		// operate
        try {
            this.testedInstance.check(certificate);
            fail();
        } catch (TrustLinkerResultException e) {
            assertEquals(TrustLinkerResultReason.CONSTRAINT_VIOLATION, e.getReason());
        }
	}

	@Test
	public void testEndEntityMisMatch() throws Exception {
		// setup
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);

		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils
				.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
						notAfter, rootCertificate, rootKeyPair.getPrivate(),
						false, 0, null, null);

		KeyPair endKeyPair = TrustTestUtils.generateKeyPair();
		X509Certificate endCertificate = TrustTestUtils.generateCertificate(
				endKeyPair.getPublic(), "CN=TestEnd", notBefore, notAfter,
				certificate, keyPair.getPrivate(), false, 0, null, null);

		this.testedInstance.addEndEntity(endCertificate);

		// operate
        try {
            this.testedInstance.check(certificate);
            fail();
        } catch (TrustLinkerResultException e) {
            assertEquals(TrustLinkerResultReason.CONSTRAINT_VIOLATION, e.getReason());
        }
	}

	@Test
	public void testEndEntityMatch() throws Exception {
		// setup
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);

		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils
				.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
						notAfter, rootCertificate, rootKeyPair.getPrivate(),
						false, 0, null, null);

		this.testedInstance.addEndEntity(certificate);

		// operate
		this.testedInstance.check(certificate);
	}
}
