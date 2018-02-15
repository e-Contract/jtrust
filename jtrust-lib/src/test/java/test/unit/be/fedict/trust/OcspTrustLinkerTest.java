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
import static org.junit.Assert.fail;

import java.net.URI;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;

import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.easymock.EasyMock;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;

import be.fedict.trust.ServerNotAvailableException;
import be.fedict.trust.ServerType;
import be.fedict.trust.linker.TrustLinkerResult;
import be.fedict.trust.linker.TrustLinkerResultException;
import be.fedict.trust.linker.TrustLinkerResultReason;
import be.fedict.trust.ocsp.OcspRepository;
import be.fedict.trust.ocsp.OcspTrustLinker;
import be.fedict.trust.policy.DefaultAlgorithmPolicy;
import be.fedict.trust.revocation.RevocationData;
import be.fedict.trust.test.PKITestUtils;

public class OcspTrustLinkerTest {

	@Before
	public void setUp() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void noOcspUriInCertificate() throws Exception {
		final KeyPair rootKeyPair = PKITestUtils.generateKeyPair();
		final DateTime notBefore = new DateTime();
		final DateTime notAfter = notBefore.plusMonths(1);
		final X509Certificate rootCertificate = PKITestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		final KeyPair keyPair = PKITestUtils.generateKeyPair();
		final X509Certificate certificate = PKITestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate());

		final OcspRepository mockOcspRepository = EasyMock
				.createMock(OcspRepository.class);

		final OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(
				mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		final TrustLinkerResult result = ocspTrustLinker.hasTrustLink(certificate,
				rootCertificate, null, new RevocationData(),
				new DefaultAlgorithmPolicy());

		assertEquals(TrustLinkerResult.UNDECIDED, result);
		EasyMock.verify(mockOcspRepository);
	}

	@Test
	public void noOcspResponseInRepository() throws Exception {
		final KeyPair rootKeyPair = PKITestUtils.generateKeyPair();
		final DateTime notBefore = new DateTime();
		final DateTime notAfter = notBefore.plusMonths(1);
		final X509Certificate rootCertificate = PKITestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		final KeyPair keyPair = PKITestUtils.generateKeyPair();
		final X509Certificate certificate = PKITestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1, null,
				"ocsp-uri");

		final OcspRepository mockOcspRepository = EasyMock
				.createMock(OcspRepository.class);
		EasyMock.expect(
				mockOcspRepository.findOcspResponse(new URI("ocsp-uri"),
						certificate, rootCertificate, null)).andReturn(null);

		final OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(
				mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		// operate
		final TrustLinkerResult result = ocspTrustLinker.hasTrustLink(certificate,
				rootCertificate, null, new RevocationData(),
				new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.UNDECIDED, result);
		EasyMock.verify(mockOcspRepository);
	}

	@Test
	public void validOcspResponse() throws Exception {
		final KeyPair rootKeyPair = PKITestUtils.generateKeyPair();
		final DateTime notBefore = new DateTime();
		final DateTime notAfter = notBefore.plusMonths(1);
		final X509Certificate rootCertificate = PKITestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		final KeyPair keyPair = PKITestUtils.generateKeyPair();
		final X509Certificate certificate = PKITestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1, null,
				"ocsp-uri");

		final OCSPResp ocspResp = PKITestUtils.createOcspResp(certificate, false,
				rootCertificate, rootCertificate, rootKeyPair.getPrivate());

		final OcspRepository mockOcspRepository = EasyMock
				.createMock(OcspRepository.class);
		EasyMock.expect(
				mockOcspRepository.findOcspResponse(
						EasyMock.eq(new URI("ocsp-uri")),
						EasyMock.eq(certificate), EasyMock.eq(rootCertificate),
						EasyMock.anyObject(Date.class))).andReturn(ocspResp);

		final OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(
				mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		final Date validationDate = new Date();

		// operate
		final TrustLinkerResult result = ocspTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData(),
				new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.TRUSTED, result);
		EasyMock.verify(mockOcspRepository);
	}

	@Test
	public void ocspResponder() throws Exception {
		final KeyPair rootKeyPair = PKITestUtils.generateKeyPair();
		final DateTime notBefore = new DateTime();
		final DateTime notAfter = notBefore.plusMonths(1);
		final X509Certificate rootCertificate = PKITestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		final KeyPair keyPair = PKITestUtils.generateKeyPair();
		final X509Certificate certificate = PKITestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1, null,
				"ocsp-uri");

		final OCSPResp ocspResp = PKITestUtils.createOcspResp(certificate, false,
				rootCertificate, rootCertificate, rootKeyPair.getPrivate());

		final OcspRepository mockOcspRepository = EasyMock
				.createMock(OcspRepository.class);
		EasyMock.expect(
				mockOcspRepository.findOcspResponse(
						EasyMock.eq(new URI("ocsp-uri")),
						EasyMock.eq(certificate), EasyMock.eq(rootCertificate),
						EasyMock.anyObject(Date.class))).andReturn(ocspResp);

		final OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(
				mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		final Date validationDate = new Date();

		// operate
		final TrustLinkerResult result = ocspTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData(),
				new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.TRUSTED, result);
		EasyMock.verify(mockOcspRepository);
	}

	@Test
	public void ocspResponseWronglySigned() throws Exception {
		final KeyPair rootKeyPair = PKITestUtils.generateKeyPair();
		final DateTime notBefore = new DateTime();
		final DateTime notAfter = notBefore.plusMonths(1);
		final X509Certificate rootCertificate = PKITestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		final KeyPair keyPair = PKITestUtils.generateKeyPair();
		final X509Certificate certificate = PKITestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1, null,
				"ocsp-uri");

		final KeyPair ocspResponderKeyPair = PKITestUtils.generateKeyPair();
		final OCSPResp ocspResp = PKITestUtils.createOcspResp(certificate, false,
				rootCertificate, rootCertificate,
				ocspResponderKeyPair.getPrivate());

		final OcspRepository mockOcspRepository = EasyMock
				.createMock(OcspRepository.class);
		EasyMock.expect(
				mockOcspRepository.findOcspResponse(
						EasyMock.eq(new URI("ocsp-uri")),
						EasyMock.eq(certificate), EasyMock.eq(rootCertificate),
						EasyMock.anyObject(Date.class))).andReturn(ocspResp);

		final OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(
				mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		final Date validationDate = new Date();

		// operate
		final TrustLinkerResult result = ocspTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData(),
				new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.UNDECIDED, result);
		EasyMock.verify(mockOcspRepository);
	}

	@Test
	public void ocspResponseMD5Signature() throws Exception {
		final KeyPair rootKeyPair = PKITestUtils.generateKeyPair();
		final DateTime notBefore = new DateTime();
		final DateTime notAfter = notBefore.plusMonths(1);
		final X509Certificate rootCertificate = PKITestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		final KeyPair keyPair = PKITestUtils.generateKeyPair();
		final X509Certificate certificate = PKITestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1, null,
				"ocsp-uri", null, "MD5withRSA");

		final OCSPResp ocspResp = PKITestUtils.createOcspResp(certificate, false,
				rootCertificate, rootCertificate, rootKeyPair.getPrivate(),
				"MD5WITHRSA");

		final OcspRepository mockOcspRepository = EasyMock
				.createMock(OcspRepository.class);
		EasyMock.expect(
				mockOcspRepository.findOcspResponse(
						EasyMock.eq(new URI("ocsp-uri")),
						EasyMock.eq(certificate), EasyMock.eq(rootCertificate),
						EasyMock.anyObject(Date.class))).andReturn(ocspResp);

		final OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(
				mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		final Date validationDate = new Date();

		// operate
		try {
			ocspTrustLinker.hasTrustLink(certificate, rootCertificate,
					validationDate, new RevocationData(),
					new DefaultAlgorithmPolicy());
			fail();
		} catch (final TrustLinkerResultException e) {
			assertEquals(TrustLinkerResultReason.INVALID_ALGORITHM,
					e.getReason());
		}

		// verify
		EasyMock.verify(mockOcspRepository);
	}

	@Test
	public void ocspNotFresh() throws Exception {
		final KeyPair rootKeyPair = PKITestUtils.generateKeyPair();
		final DateTime notBefore = new DateTime();
		final DateTime notAfter = notBefore.plusMonths(1);
		final X509Certificate rootCertificate = PKITestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		final KeyPair keyPair = PKITestUtils.generateKeyPair();
		final X509Certificate certificate = PKITestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1, null,
				"ocsp-uri");

		final OCSPResp ocspResp = PKITestUtils.createOcspResp(certificate, false,
				rootCertificate, rootCertificate, rootKeyPair.getPrivate());

		final OcspRepository mockOcspRepository = EasyMock
				.createMock(OcspRepository.class);
		EasyMock.expect(
				mockOcspRepository.findOcspResponse(
						EasyMock.eq(new URI("ocsp-uri")),
						EasyMock.eq(certificate), EasyMock.eq(rootCertificate),
						EasyMock.anyObject(Date.class))).andReturn(ocspResp);

		final OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(
				mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		final Date validationDate = notBefore.plusDays(1).toDate();

		// operate
		final TrustLinkerResult result = ocspTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData(),
				new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.UNDECIDED, result);
		EasyMock.verify(mockOcspRepository);
	}

	@Test
	public void wrongOcspResponse() throws Exception {
		final KeyPair rootKeyPair = PKITestUtils.generateKeyPair();
		final DateTime notBefore = new DateTime();
		final DateTime notAfter = notBefore.plusMonths(1);
		final X509Certificate rootCertificate = PKITestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		final KeyPair keyPair = PKITestUtils.generateKeyPair();
		final X509Certificate certificate = PKITestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1, null,
				"ocsp-uri");

		final X509Certificate certificate2 = PKITestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test2", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1, null,
				"ocsp-uri");

		final OCSPResp ocspResp2 = PKITestUtils.createOcspResp(certificate2, false,
				rootCertificate, rootCertificate, rootKeyPair.getPrivate());

		final OcspRepository mockOcspRepository = EasyMock
				.createMock(OcspRepository.class);
		EasyMock.expect(
				mockOcspRepository.findOcspResponse(
						EasyMock.eq(new URI("ocsp-uri")),
						EasyMock.eq(certificate), EasyMock.eq(rootCertificate),
						EasyMock.anyObject(Date.class))).andReturn(ocspResp2);

		final OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(
				mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		final Date validationDate = new Date();

		// operate
		final TrustLinkerResult result = ocspTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData(),
				new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.UNDECIDED, result);
		EasyMock.verify(mockOcspRepository);
	}

	@Test
	public void revokedOcsp() throws Exception {
		final KeyPair rootKeyPair = PKITestUtils.generateKeyPair();
		final DateTime notBefore = new DateTime();
		final DateTime notAfter = notBefore.plusMonths(1);
		final X509Certificate rootCertificate = PKITestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		final KeyPair keyPair = PKITestUtils.generateKeyPair();
		final X509Certificate certificate = PKITestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1, null,
				"ocsp-uri");

		final OCSPResp ocspResp = PKITestUtils.createOcspResp(certificate, true,
				rootCertificate, rootCertificate, rootKeyPair.getPrivate());

		final OcspRepository mockOcspRepository = EasyMock
				.createMock(OcspRepository.class);
		EasyMock.expect(
				mockOcspRepository.findOcspResponse(
						EasyMock.eq(new URI("ocsp-uri")),
						EasyMock.eq(certificate), EasyMock.eq(rootCertificate),
						EasyMock.anyObject(Date.class))).andReturn(ocspResp);

		final OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(
				mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		final Date validationDate = new Date();

		// operate
		try {
			ocspTrustLinker.hasTrustLink(certificate, rootCertificate,
					validationDate, new RevocationData(),
					new DefaultAlgorithmPolicy());
			fail();
		} catch (final TrustLinkerResultException e) {
			assertEquals(TrustLinkerResultReason.INVALID_REVOCATION_STATUS,
					e.getReason());
		}

		// verify
		EasyMock.verify(mockOcspRepository);
	}

	@Test
	public void validDedicatedAuthorizedOcspResponse() throws Exception {

		final DateTime notBefore = new DateTime();
		final DateTime notAfter = notBefore.plusMonths(1);

		final KeyPair rootKeyPair = PKITestUtils.generateKeyPair();
		final X509Certificate rootCertificate = PKITestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		final KeyPair ocspResponderKeyPair = PKITestUtils.generateKeyPair();
		final X509Certificate ocspResponderCertificate = PKITestUtils
				.generateCertificate(ocspResponderKeyPair.getPublic(),
						"CN=OCSPResp", notBefore, notAfter, rootCertificate,
						rootKeyPair.getPrivate(), false, -1, null, null, null,
						"SHA1withRSA", false, false, false, null, null, null,
						true);

		final KeyPair keyPair = PKITestUtils.generateKeyPair();
		final X509Certificate certificate = PKITestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1, null,
				"ocsp-uri");

		final OCSPResp ocspResp = PKITestUtils.createOcspResp(certificate, false,
				rootCertificate, ocspResponderCertificate,
				ocspResponderKeyPair.getPrivate());

		final OcspRepository mockOcspRepository = EasyMock
				.createMock(OcspRepository.class);
		EasyMock.expect(
				mockOcspRepository.findOcspResponse(
						EasyMock.eq(new URI("ocsp-uri")),
						EasyMock.eq(certificate), EasyMock.eq(rootCertificate),
						EasyMock.anyObject(Date.class))).andReturn(ocspResp);

		final OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(
				mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		final Date validationDate = new Date();

		// operate
		final TrustLinkerResult result = ocspTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData(),
				new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.TRUSTED, result);
		EasyMock.verify(mockOcspRepository);
	}

	@Test
	public void rootCAIssuesOcspResponseNoCertInResponse() throws Exception {

		final DateTime notBefore = new DateTime();
		final DateTime notAfter = notBefore.plusMonths(1);

		final KeyPair rootKeyPair = PKITestUtils.generateKeyPair();
		final X509Certificate rootCertificate = PKITestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		final KeyPair keyPair = PKITestUtils.generateKeyPair();
		final X509Certificate certificate = PKITestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1, null,
				"ocsp-uri");

		final OCSPResp ocspResp = PKITestUtils.createOcspResp(certificate, false,
				rootCertificate, rootCertificate, rootKeyPair.getPrivate());

		final OcspRepository mockOcspRepository = EasyMock
				.createMock(OcspRepository.class);
		EasyMock.expect(
				mockOcspRepository.findOcspResponse(
						EasyMock.eq(new URI("ocsp-uri")),
						EasyMock.eq(certificate), EasyMock.eq(rootCertificate),
						EasyMock.anyObject(Date.class))).andReturn(ocspResp);

		final OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(
				mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		final Date validationDate = new Date();

		// operate
		final TrustLinkerResult result = ocspTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData(),
				new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.TRUSTED, result);
		EasyMock.verify(mockOcspRepository);
	}

	@Test
	public void rootCAIssuesOcspResponseRootCACertInResponse() throws Exception {

		final DateTime notBefore = new DateTime();
		final DateTime notAfter = notBefore.plusMonths(1);

		final KeyPair rootKeyPair = PKITestUtils.generateKeyPair();
		final X509Certificate rootCertificate = PKITestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		final KeyPair keyPair = PKITestUtils.generateKeyPair();
		final X509Certificate certificate = PKITestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1, null,
				"ocsp-uri");

		final OCSPResp ocspResp = PKITestUtils.createOcspResp(certificate, false,
				rootCertificate, rootCertificate, rootKeyPair.getPrivate(),
				"SHA1withRSA", Collections.singletonList(rootCertificate));

		final OcspRepository mockOcspRepository = EasyMock
				.createMock(OcspRepository.class);
		EasyMock.expect(
				mockOcspRepository.findOcspResponse(
						EasyMock.eq(new URI("ocsp-uri")),
						EasyMock.eq(certificate), EasyMock.eq(rootCertificate),
						EasyMock.anyObject(Date.class))).andReturn(ocspResp);

		final OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(
				mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		final Date validationDate = new Date();

		// operate
		final TrustLinkerResult result = ocspTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData(),
				new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.TRUSTED, result);
		EasyMock.verify(mockOcspRepository);
	}

	@Test
	public void invalidDedicatedAuthorizedOcspResponse() throws Exception {

		final DateTime notBefore = new DateTime();
		final DateTime notAfter = notBefore.plusMonths(1);

		final KeyPair rootKeyPair = PKITestUtils.generateKeyPair();
		final X509Certificate rootCertificate = PKITestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		final KeyPair ocspResponderKeyPair = PKITestUtils.generateKeyPair();
		final X509Certificate ocspResponderCertificate = PKITestUtils
				.generateCertificate(ocspResponderKeyPair.getPublic(),
						"CN=OCSPResp", notBefore, notAfter, rootCertificate,
						rootKeyPair.getPrivate(), false, -1, null, null, null,
						"SHA1withRSA", false, false, false, null, null, null,
						false);

		final KeyPair keyPair = PKITestUtils.generateKeyPair();
		final X509Certificate certificate = PKITestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1, null,
				"ocsp-uri");

		final OCSPResp ocspResp = PKITestUtils.createOcspResp(certificate, false,
				rootCertificate, ocspResponderCertificate,
				ocspResponderKeyPair.getPrivate());

		final OcspRepository mockOcspRepository = EasyMock
				.createMock(OcspRepository.class);
		EasyMock.expect(
				mockOcspRepository.findOcspResponse(
						EasyMock.eq(new URI("ocsp-uri")),
						EasyMock.eq(certificate), EasyMock.eq(rootCertificate),
						EasyMock.anyObject(Date.class))).andReturn(ocspResp);

		final OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(
				mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		final Date validationDate = new Date();

		// operate
		final TrustLinkerResult result = ocspTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData(),
				new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.UNDECIDED, result);
		EasyMock.verify(mockOcspRepository);
	}

	@Test(expected = TrustLinkerResultException.class)
	public void testOcspServerUnavailable() throws Exception {
		final KeyPair rootKeyPair = PKITestUtils.generateKeyPair();
		final DateTime notBefore = new DateTime();
		final DateTime notAfter = notBefore.plusMonths(1);
		final X509Certificate rootCertificate = PKITestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		final KeyPair keyPair = PKITestUtils.generateKeyPair();
		final X509Certificate certificate = PKITestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1, null,
				"ocsp-uri");

		final OcspRepository mockOcspRepository = EasyMock.createMock(OcspRepository.class);
		EasyMock.expect(mockOcspRepository.findOcspResponse(new URI("ocsp-uri"),
						certificate, rootCertificate, null))
				.andThrow(new ServerNotAvailableException("OCSP server responded with status code 500", ServerType.OCSP));

		final OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(
				mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		// operate
		final TrustLinkerResult result = ocspTrustLinker.hasTrustLink(certificate,
				rootCertificate, null, new RevocationData(),
				new DefaultAlgorithmPolicy());

		// verify
		EasyMock.verify(mockOcspRepository);

		fail("Expected TrustLinkerResultException, but got: " + result);
	}

}
