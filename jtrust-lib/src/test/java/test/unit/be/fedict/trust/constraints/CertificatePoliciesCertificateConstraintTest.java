/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
 * Copyright (C) 2020-2023 e-Contract.be BV.
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

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import be.fedict.trust.constraints.CertificatePoliciesCertificateConstraint;
import be.fedict.trust.linker.TrustLinkerResultException;
import be.fedict.trust.linker.TrustLinkerResultReason;
import be.fedict.trust.test.PKIBuilder;
import be.fedict.trust.test.PKITestUtils;

public class CertificatePoliciesCertificateConstraintTest {

	private CertificatePoliciesCertificateConstraint testedInstance;

	@BeforeEach
	public void setUp() throws Exception {
		this.testedInstance = new CertificatePoliciesCertificateConstraint();
	}

	@Test
	public void testNoCertificatePolicies() throws Exception {
		// setup
		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		LocalDateTime notBefore = LocalDateTime.now();
		LocalDateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = PKITestUtils.generateSelfSignedCertificate(keyPair, "CN=Test", notBefore,
				notAfter);

		// operate
		TrustLinkerResultException result = Assertions.assertThrows(TrustLinkerResultException.class, () -> {
			this.testedInstance.check(certificate);
		});
		assertEquals(TrustLinkerResultReason.CONSTRAINT_VIOLATION, result.getReason());
	}

	@Test
	public void testCertificatePoliciesMismatch() throws Exception {
		// setup
		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		LocalDateTime notBefore = LocalDateTime.now();
		LocalDateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = PKITestUtils.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
				notAfter, null, keyPair.getPrivate(), true, -1, null, null, null, "SHA1withRSA", false, true, true,
				null, "1.5.6.7");

		this.testedInstance.addCertificatePolicy("1.2.3.4");

		// operate
		TrustLinkerResultException result = Assertions.assertThrows(TrustLinkerResultException.class, () -> {
			this.testedInstance.check(certificate);
		});
		assertEquals(TrustLinkerResultReason.CONSTRAINT_VIOLATION, result.getReason());
	}

	@Test
	public void testCertificatePoliciesMatch() throws Exception {
		// setup
		String certificatePolicy = "1.2.3.4.5";
		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		LocalDateTime notBefore = LocalDateTime.now();
		LocalDateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = PKITestUtils.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
				notAfter, null, keyPair.getPrivate(), true, -1, null, null, null, "SHA1withRSA", false, true, true,
				null, certificatePolicy);

		this.testedInstance.addCertificatePolicy(certificatePolicy);

		// operate
		this.testedInstance.check(certificate);
	}
}
