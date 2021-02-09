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

import be.fedict.trust.constraints.TSACertificateConstraint;
import be.fedict.trust.linker.TrustLinkerResultException;
import be.fedict.trust.linker.TrustLinkerResultReason;
import be.fedict.trust.test.PKITestUtils;

public class TSACertificateConstraintTest {

	private TSACertificateConstraint testedInstance;

	@BeforeEach
	public void setUp() throws Exception {
		this.testedInstance = new TSACertificateConstraint();
	}

	@Test
	public void testValidTSAConstraint() throws Exception {
		// setup
		KeyPair keyPair = PKITestUtils.generateKeyPair();
		LocalDateTime notBefore = LocalDateTime.now();
		LocalDateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = PKITestUtils.generateCertificate(keyPair.getPublic(), "CN=TestTSA", notBefore,
				notAfter, null, keyPair.getPrivate(), true, -1, null, null, null, "SHA1withRSA", true);

		// operate
		this.testedInstance.check(certificate);
	}

	@Test
	public void testInvalidTSAConstraint() throws Exception {
		// setup
		KeyPair keyPair = PKITestUtils.generateKeyPair();
		LocalDateTime notBefore = LocalDateTime.now();
		LocalDateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = PKITestUtils.generateCertificate(keyPair.getPublic(), "CN=TestTSA", notBefore,
				notAfter, null, keyPair.getPrivate(), true, -1, null, null, null, "SHA1withRSA", false);

		// operate
		try {
			this.testedInstance.check(certificate);
			fail();
		} catch (TrustLinkerResultException e) {
			assertEquals(TrustLinkerResultReason.CONSTRAINT_VIOLATION, e.getReason());
		}
	}
}
