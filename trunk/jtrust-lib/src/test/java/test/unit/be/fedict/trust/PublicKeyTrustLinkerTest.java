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

package test.unit.be.fedict.trust;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;

import be.fedict.trust.linker.PublicKeyTrustLinker;
import be.fedict.trust.linker.TrustLinkerResult;
import be.fedict.trust.linker.TrustLinkerResultException;
import be.fedict.trust.linker.TrustLinkerResultReason;
import be.fedict.trust.policy.DefaultAlgorithmPolicy;
import be.fedict.trust.revocation.RevocationData;

public class PublicKeyTrustLinkerTest {

	@Before
	public void setUp() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void testHasTrustLink() throws Exception {
		// setup
		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate());

		PublicKeyTrustLinker publicKeyTrustLinker = new PublicKeyTrustLinker();

		Date validationDate = new Date();

		// operate
		TrustLinkerResult result = publicKeyTrustLinker.hasTrustLink(
				certificate, rootCertificate, validationDate,
				new RevocationData(), new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.UNDECIDED, result);
	}

	@Test
	public void testExpiredCertificate() throws Exception {
		// setup
		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate());

		PublicKeyTrustLinker publicKeyTrustLinker = new PublicKeyTrustLinker();

		Date validationDate = notAfter.plusDays(1).toDate();

		// operate
		try {
			publicKeyTrustLinker.hasTrustLink(certificate, rootCertificate,
					validationDate, new RevocationData(),
					new DefaultAlgorithmPolicy());
			fail();
		} catch (TrustLinkerResultException e) {
			assertEquals(TrustLinkerResultReason.INVALID_VALIDITY_INTERVAL,
					e.getReason());
		}
	}

	@Test
	public void testCertificateNotYetValid() throws Exception {
		// setup
		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate());

		PublicKeyTrustLinker publicKeyTrustLinker = new PublicKeyTrustLinker();

		Date validationDate = notBefore.minusDays(1).toDate();

		// operate
		try {
			publicKeyTrustLinker.hasTrustLink(certificate, rootCertificate,
					validationDate, new RevocationData(),
					new DefaultAlgorithmPolicy());
			fail();
		} catch (TrustLinkerResultException e) {
			assertEquals(TrustLinkerResultReason.INVALID_VALIDITY_INTERVAL,
					e.getReason());
		}
	}

	// @Test
	// XXX: there are production CAs that have no CA flag set.
	public void testNoCaFlagFails() throws Exception {
		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter, false);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate());

		PublicKeyTrustLinker publicKeyTrustLinker = new PublicKeyTrustLinker();

		Date validationDate = new Date();

		TrustLinkerResult result = publicKeyTrustLinker.hasTrustLink(
				certificate, rootCertificate, validationDate,
				new RevocationData(), new DefaultAlgorithmPolicy());
		assertNotNull(result);
		// assertFalse(result.isValid());
	}

	@Test
	public void testChildNotAllowToBeCA() throws Exception {
		// setup
		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter, true, 0);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), true);

		PublicKeyTrustLinker publicKeyTrustLinker = new PublicKeyTrustLinker();

		Date validationDate = new Date();

		// operate & verify
		try {
			publicKeyTrustLinker.hasTrustLink(certificate, rootCertificate,
					validationDate, new RevocationData(),
					new DefaultAlgorithmPolicy());
			fail();
		} catch (TrustLinkerResultException e) {
			assertEquals(TrustLinkerResultReason.NO_TRUST, e.getReason());
		}
	}

	@Test
	public void testNoChildFails() throws Exception {
		// setup
		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		KeyPair root2keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate root2Certificate = TrustTestUtils
				.generateSelfSignedCertificate(root2keyPair, "CN=TestRoot2",
						notBefore, notAfter);

		PublicKeyTrustLinker publicKeyTrustLinker = new PublicKeyTrustLinker();

		Date validationDate = new Date();

		// operate & verify
		try {
			publicKeyTrustLinker.hasTrustLink(root2Certificate,
					rootCertificate, validationDate, new RevocationData(),
					new DefaultAlgorithmPolicy());
			fail();
		} catch (TrustLinkerResultException e) {
			assertEquals(TrustLinkerResultReason.NO_TRUST, e.getReason());
		}
	}

	@Test
	public void testCACertificateNoSKID() throws Exception {
		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = TrustTestUtils.generateCertificate(
				rootKeyPair.getPublic(), "CN=TestRoot", notBefore, notAfter,
				null, rootKeyPair.getPrivate(), true, -1, null, null, null,
				"SHA1withRSA", false, false, true);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate());

		PublicKeyTrustLinker publicKeyTrustLinker = new PublicKeyTrustLinker();

		Date validationDate = new Date();

		try {
			publicKeyTrustLinker.hasTrustLink(certificate, rootCertificate,
					validationDate, new RevocationData(),
					new DefaultAlgorithmPolicy());
			fail();
		} catch (TrustLinkerResultException e) {
			assertEquals(TrustLinkerResultReason.NO_TRUST, e.getReason());
		}
	}

	@Test
	public void testChildCACertificateNoAKIDNotSelfSigned() throws Exception {
		// setup
		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), true, -1, null,
				null, null, "SHA1withRSA", false, true, false);

		PublicKeyTrustLinker publicKeyTrustLinker = new PublicKeyTrustLinker();

		Date validationDate = new Date();

		// operate
		TrustLinkerResult result = publicKeyTrustLinker.hasTrustLink(
				certificate, rootCertificate, validationDate,
				new RevocationData(), new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.UNDECIDED, result);
	}

	@Test
	public void testAKIDMisMatchSKID() throws Exception {
		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		KeyPair akidKeyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), true, -1, null,
				null, null, "SHA1withRSA", false, true, true,
				akidKeyPair.getPublic());

		PublicKeyTrustLinker publicKeyTrustLinker = new PublicKeyTrustLinker();

		Date validationDate = new Date();

		try {
			publicKeyTrustLinker.hasTrustLink(certificate, rootCertificate,
					validationDate, new RevocationData(),
					new DefaultAlgorithmPolicy());
			fail();
		} catch (TrustLinkerResultException e) {
			assertEquals(TrustLinkerResultReason.NO_TRUST, e.getReason());
		}
	}
}
