/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
 * Copyright (C) 2020-2021 e-Contract.be BV.
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import be.fedict.trust.constraints.DistinguishedNameCertificateConstraint;
import be.fedict.trust.linker.TrustLinkerResultException;
import be.fedict.trust.linker.TrustLinkerResultReason;
import be.fedict.trust.test.PKITestUtils;

public class DistinguishedNameCertificateConstraintTest {

	private DistinguishedNameCertificateConstraint testedInstance;

	private final String validSubjectName = "CN=Test";

	@BeforeEach
	public void setUp() throws Exception {
		this.testedInstance = new DistinguishedNameCertificateConstraint(validSubjectName);
	}

	@Test
	public void testDistinguishedNameMisMatch() throws Exception {
		// setup
		KeyPair keyPair = PKITestUtils.generateKeyPair();
		LocalDateTime notBefore = LocalDateTime.now();
		LocalDateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = PKITestUtils.generateSelfSignedCertificate(keyPair, "CN=F00", notBefore,
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
		KeyPair keyPair = PKITestUtils.generateKeyPair();
		LocalDateTime notBefore = LocalDateTime.now();
		LocalDateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = PKITestUtils.generateSelfSignedCertificate(keyPair, "CN=Test", notBefore,
				notAfter);

		// operate
		this.testedInstance.check(certificate);
	}
}
