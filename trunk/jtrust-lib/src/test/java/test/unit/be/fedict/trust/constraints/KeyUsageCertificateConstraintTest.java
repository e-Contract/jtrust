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

import org.bouncycastle.asn1.x509.KeyUsage;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;

import test.unit.be.fedict.trust.TrustTestUtils;
import be.fedict.trust.constraints.KeyUsageCertificateConstraint;

public class KeyUsageCertificateConstraintTest {

	private KeyUsageCertificateConstraint testedInstance;

	@Before
	public void setUp() throws Exception {
		this.testedInstance = new KeyUsageCertificateConstraint();
	}

	@Test
	public void testNoKeyUsage() throws Exception {
		// setup
		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = TrustTestUtils
				.generateSelfSignedCertificate(keyPair, "CN=Test", notBefore,
						notAfter);

		// operate
		assertFalse(this.testedInstance.check(certificate));
	}

	@Test
	public void testFailingOnFalseNonRepudiationFilter() throws Exception {
		// setup
		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = TrustTestUtils
				.generateSelfSignedCertificate(keyPair, "CN=Test", notBefore,
						notAfter);

		this.testedInstance.setNonRepudiationFilter(false);

		// operate
		assertFalse(this.testedInstance.check(certificate));
	}

	@Test
	public void testFailingOnTrueNonRepudiationFilter() throws Exception {
		// setup
		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = TrustTestUtils
				.generateSelfSignedCertificate(keyPair, "CN=Test", notBefore,
						notAfter);

		this.testedInstance.setNonRepudiationFilter(true);

		// operate
		assertFalse(this.testedInstance.check(certificate));
	}

	@Test
	public void testDigitalSignatureKeyUsage() throws Exception {
		// setup
		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature);
		X509Certificate certificate = TrustTestUtils
				.generateSelfSignedCertificate(keyPair, "CN=Test", notBefore,
						notAfter, true, 0, null, keyUsage);

		this.testedInstance.setDigitalSignatureFilter(true);

		// operate
		assertTrue(this.testedInstance.check(certificate));
	}

	@Test
	public void testDigitalSignatureNoNonRepudiationKeyUsage() throws Exception {
		// setup
		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature);
		X509Certificate certificate = TrustTestUtils
				.generateSelfSignedCertificate(keyPair, "CN=Test", notBefore,
						notAfter, true, 0, null, keyUsage);

		this.testedInstance.setDigitalSignatureFilter(true);
		this.testedInstance.setNonRepudiationFilter(false);

		// operate
		assertTrue(this.testedInstance.check(certificate));
	}

	@Test
	public void testFailingOnUnexpectedKeyUsageKeyEncipherment()
			throws Exception {
		// setup
		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		KeyUsage keyUsage = new KeyUsage(KeyUsage.keyEncipherment);
		X509Certificate certificate = TrustTestUtils
				.generateSelfSignedCertificate(keyPair, "CN=Test", notBefore,
						notAfter, true, 0, null, keyUsage);

		this.testedInstance.setKeyEnciphermentFilter(false);

		// operate
		assertFalse(this.testedInstance.check(certificate));
	}

	@Test
	public void testFailingOnUnexpectedKeyUsageDataEncipherment()
			throws Exception {
		// setup
		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		KeyUsage keyUsage = new KeyUsage(KeyUsage.dataEncipherment);
		X509Certificate certificate = TrustTestUtils
				.generateSelfSignedCertificate(keyPair, "CN=Test", notBefore,
						notAfter, true, 0, null, keyUsage);

		this.testedInstance.setDataEnciphermentFilter(false);

		// operate
		assertFalse(this.testedInstance.check(certificate));
	}

	@Test
	public void testFailingOnUnexpectedKeyUsageKeyAgreement() throws Exception {
		// setup
		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		KeyUsage keyUsage = new KeyUsage(KeyUsage.keyAgreement);
		X509Certificate certificate = TrustTestUtils
				.generateSelfSignedCertificate(keyPair, "CN=Test", notBefore,
						notAfter, true, 0, null, keyUsage);

		this.testedInstance.setKeyAgreementFilter(false);

		// operate
		assertFalse(this.testedInstance.check(certificate));
	}

	@Test
	public void testFailingOnUnexpectedKeyUsageKeyCertSign() throws Exception {
		// setup
		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign);
		X509Certificate certificate = TrustTestUtils
				.generateSelfSignedCertificate(keyPair, "CN=Test", notBefore,
						notAfter, true, 0, null, keyUsage);

		this.testedInstance.setKeyCertificateSigningFilter(false);

		// operate
		assertFalse(this.testedInstance.check(certificate));
	}

	@Test
	public void testFailingOnUnexpectedKeyUsageCrlSign() throws Exception {
		// setup
		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		KeyUsage keyUsage = new KeyUsage(KeyUsage.cRLSign);
		X509Certificate certificate = TrustTestUtils
				.generateSelfSignedCertificate(keyPair, "CN=Test", notBefore,
						notAfter, true, 0, null, keyUsage);

		this.testedInstance.setCRLSigningFilter(false);

		// operate
		assertFalse(this.testedInstance.check(certificate));
	}

	@Test
	public void testFailingOnUnexpectedKeyUsageEncypherOnly() throws Exception {
		// setup
		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		KeyUsage keyUsage = new KeyUsage(KeyUsage.encipherOnly);
		X509Certificate certificate = TrustTestUtils
				.generateSelfSignedCertificate(keyPair, "CN=Test", notBefore,
						notAfter, true, 0, null, keyUsage);

		this.testedInstance.setEncipherOnlyFilter(false);

		// operate
		assertFalse(this.testedInstance.check(certificate));
	}

	@Test
	public void testFailingOnUnexpectedKeyUsageDecypherOnly() throws Exception {
		// setup
		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		KeyUsage keyUsage = new KeyUsage(KeyUsage.decipherOnly);
		X509Certificate certificate = TrustTestUtils
				.generateSelfSignedCertificate(keyPair, "CN=Test", notBefore,
						notAfter, true, 0, null, keyUsage);

		this.testedInstance.setDecipherOnlyFilter(false);

		// operate
		assertFalse(this.testedInstance.check(certificate));
	}

	@Test
	public void testFailingOnMissingKeyUsage() throws Exception {
		// setup
		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		KeyUsage keyUsage = new KeyUsage(KeyUsage.decipherOnly);
		X509Certificate certificate = TrustTestUtils
				.generateSelfSignedCertificate(keyPair, "CN=Test", notBefore,
						notAfter, true, 0, null, keyUsage);

		this.testedInstance.setCRLSigningFilter(true);

		// operate
		assertFalse(this.testedInstance.check(certificate));
	}
}
