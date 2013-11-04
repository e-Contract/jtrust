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

import be.fedict.trust.linker.TrustLinkerResult;
import be.fedict.trust.linker.TrustLinkerResultException;
import be.fedict.trust.linker.TrustLinkerResultReason;
import be.fedict.trust.ocsp.OcspRepository;
import be.fedict.trust.ocsp.OcspTrustLinker;
import be.fedict.trust.policy.DefaultAlgorithmPolicy;
import be.fedict.trust.revocation.RevocationData;

public class OcspTrustLinkerTest {

	@Before
	public void setUp() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void noOcspUriInCertificate() throws Exception {
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

		OcspRepository mockOcspRepository = EasyMock
				.createMock(OcspRepository.class);

		OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(
				mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		TrustLinkerResult result = ocspTrustLinker.hasTrustLink(certificate,
				rootCertificate, null, new RevocationData(),
				new DefaultAlgorithmPolicy());

		assertEquals(TrustLinkerResult.UNDECIDED, result);
		EasyMock.verify(mockOcspRepository);
	}

	@Test
	public void noOcspResponseInRepository() throws Exception {
		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1, null,
				"ocsp-uri");

		OcspRepository mockOcspRepository = EasyMock
				.createMock(OcspRepository.class);
		EasyMock.expect(
				mockOcspRepository.findOcspResponse(new URI("ocsp-uri"),
						certificate, rootCertificate, null)).andReturn(null);

		OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(
				mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		// operate
		TrustLinkerResult result = ocspTrustLinker.hasTrustLink(certificate,
				rootCertificate, null, new RevocationData(),
				new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.UNDECIDED, result);
		EasyMock.verify(mockOcspRepository);
	}

	@Test
	public void validOcspResponse() throws Exception {
		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1, null,
				"ocsp-uri");

		OCSPResp ocspResp = TrustTestUtils.createOcspResp(certificate, false,
				rootCertificate, rootCertificate, rootKeyPair.getPrivate());

		OcspRepository mockOcspRepository = EasyMock
				.createMock(OcspRepository.class);
		EasyMock.expect(
				mockOcspRepository.findOcspResponse(
						EasyMock.eq(new URI("ocsp-uri")),
						EasyMock.eq(certificate), EasyMock.eq(rootCertificate),
						EasyMock.anyObject(Date.class))).andReturn(ocspResp);

		OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(
				mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		Date validationDate = new Date();

		// operate
		TrustLinkerResult result = ocspTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData(),
				new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.TRUSTED, result);
		EasyMock.verify(mockOcspRepository);
	}

	@Test
	public void ocspResponder() throws Exception {
		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1, null,
				"ocsp-uri");

		OCSPResp ocspResp = TrustTestUtils.createOcspResp(certificate, false,
				rootCertificate, rootCertificate, rootKeyPair.getPrivate());

		OcspRepository mockOcspRepository = EasyMock
				.createMock(OcspRepository.class);
		EasyMock.expect(
				mockOcspRepository.findOcspResponse(
						EasyMock.eq(new URI("ocsp-uri")),
						EasyMock.eq(certificate), EasyMock.eq(rootCertificate),
						EasyMock.anyObject(Date.class))).andReturn(ocspResp);

		OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(
				mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		Date validationDate = new Date();

		// operate
		TrustLinkerResult result = ocspTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData(),
				new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.TRUSTED, result);
		EasyMock.verify(mockOcspRepository);
	}

	@Test
	public void ocspResponseWronglySigned() throws Exception {
		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1, null,
				"ocsp-uri");

		KeyPair ocspResponderKeyPair = TrustTestUtils.generateKeyPair();
		OCSPResp ocspResp = TrustTestUtils.createOcspResp(certificate, false,
				rootCertificate, rootCertificate,
				ocspResponderKeyPair.getPrivate());

		OcspRepository mockOcspRepository = EasyMock
				.createMock(OcspRepository.class);
		EasyMock.expect(
				mockOcspRepository.findOcspResponse(
						EasyMock.eq(new URI("ocsp-uri")),
						EasyMock.eq(certificate), EasyMock.eq(rootCertificate),
						EasyMock.anyObject(Date.class))).andReturn(ocspResp);

		OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(
				mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		Date validationDate = new Date();

		// operate
		TrustLinkerResult result = ocspTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData(),
				new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.UNDECIDED, result);
		EasyMock.verify(mockOcspRepository);
	}

	@Test
	public void ocspResponseMD5Signature() throws Exception {
		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1, null,
				"ocsp-uri", null, "MD5withRSA");

		OCSPResp ocspResp = TrustTestUtils.createOcspResp(certificate, false,
				rootCertificate, rootCertificate, rootKeyPair.getPrivate(),
				"MD5WITHRSA");

		OcspRepository mockOcspRepository = EasyMock
				.createMock(OcspRepository.class);
		EasyMock.expect(
				mockOcspRepository.findOcspResponse(
						EasyMock.eq(new URI("ocsp-uri")),
						EasyMock.eq(certificate), EasyMock.eq(rootCertificate),
						EasyMock.anyObject(Date.class))).andReturn(ocspResp);

		OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(
				mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		Date validationDate = new Date();

		// operate
		try {
			ocspTrustLinker.hasTrustLink(certificate, rootCertificate,
					validationDate, new RevocationData(),
					new DefaultAlgorithmPolicy());
			fail();
		} catch (TrustLinkerResultException e) {
			assertEquals(TrustLinkerResultReason.INVALID_ALGORITHM,
					e.getReason());
		}

		// verify
		EasyMock.verify(mockOcspRepository);
	}

	@Test
	public void ocspNotFresh() throws Exception {
		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1, null,
				"ocsp-uri");

		OCSPResp ocspResp = TrustTestUtils.createOcspResp(certificate, false,
				rootCertificate, rootCertificate, rootKeyPair.getPrivate());

		OcspRepository mockOcspRepository = EasyMock
				.createMock(OcspRepository.class);
		EasyMock.expect(
				mockOcspRepository.findOcspResponse(
						EasyMock.eq(new URI("ocsp-uri")),
						EasyMock.eq(certificate), EasyMock.eq(rootCertificate),
						EasyMock.anyObject(Date.class))).andReturn(ocspResp);

		OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(
				mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		Date validationDate = notBefore.plusDays(1).toDate();

		// operate
		TrustLinkerResult result = ocspTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData(),
				new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.UNDECIDED, result);
		EasyMock.verify(mockOcspRepository);
	}

	@Test
	public void wrongOcspResponse() throws Exception {
		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1, null,
				"ocsp-uri");

		X509Certificate certificate2 = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test2", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1, null,
				"ocsp-uri");

		OCSPResp ocspResp2 = TrustTestUtils.createOcspResp(certificate2, false,
				rootCertificate, rootCertificate, rootKeyPair.getPrivate());

		OcspRepository mockOcspRepository = EasyMock
				.createMock(OcspRepository.class);
		EasyMock.expect(
				mockOcspRepository.findOcspResponse(
						EasyMock.eq(new URI("ocsp-uri")),
						EasyMock.eq(certificate), EasyMock.eq(rootCertificate),
						EasyMock.anyObject(Date.class))).andReturn(ocspResp2);

		OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(
				mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		Date validationDate = new Date();

		// operate
		TrustLinkerResult result = ocspTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData(),
				new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.UNDECIDED, result);
		EasyMock.verify(mockOcspRepository);
	}

	@Test
	public void revokedOcsp() throws Exception {
		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1, null,
				"ocsp-uri");

		OCSPResp ocspResp = TrustTestUtils.createOcspResp(certificate, true,
				rootCertificate, rootCertificate, rootKeyPair.getPrivate());

		OcspRepository mockOcspRepository = EasyMock
				.createMock(OcspRepository.class);
		EasyMock.expect(
				mockOcspRepository.findOcspResponse(
						EasyMock.eq(new URI("ocsp-uri")),
						EasyMock.eq(certificate), EasyMock.eq(rootCertificate),
						EasyMock.anyObject(Date.class))).andReturn(ocspResp);

		OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(
				mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		Date validationDate = new Date();

		// operate
		try {
			ocspTrustLinker.hasTrustLink(certificate, rootCertificate,
					validationDate, new RevocationData(),
					new DefaultAlgorithmPolicy());
			fail();
		} catch (TrustLinkerResultException e) {
			assertEquals(TrustLinkerResultReason.INVALID_REVOCATION_STATUS,
					e.getReason());
		}

		// verify
		EasyMock.verify(mockOcspRepository);
	}

	@Test
	public void validDedicatedAuthorizedOcspResponse() throws Exception {

		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);

		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		KeyPair ocspResponderKeyPair = TrustTestUtils.generateKeyPair();
		X509Certificate ocspResponderCertificate = TrustTestUtils
				.generateCertificate(ocspResponderKeyPair.getPublic(),
						"CN=OCSPResp", notBefore, notAfter, rootCertificate,
						rootKeyPair.getPrivate(), false, -1, null, null, null,
						"SHA1withRSA", false, false, false, null, null, null,
						true);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1, null,
				"ocsp-uri");

		OCSPResp ocspResp = TrustTestUtils.createOcspResp(certificate, false,
				rootCertificate, ocspResponderCertificate,
				ocspResponderKeyPair.getPrivate());

		OcspRepository mockOcspRepository = EasyMock
				.createMock(OcspRepository.class);
		EasyMock.expect(
				mockOcspRepository.findOcspResponse(
						EasyMock.eq(new URI("ocsp-uri")),
						EasyMock.eq(certificate), EasyMock.eq(rootCertificate),
						EasyMock.anyObject(Date.class))).andReturn(ocspResp);

		OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(
				mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		Date validationDate = new Date();

		// operate
		TrustLinkerResult result = ocspTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData(),
				new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.TRUSTED, result);
		EasyMock.verify(mockOcspRepository);
	}

	@Test
	public void rootCAIssuesOcspResponseNoCertInResponse() throws Exception {

		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);

		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1, null,
				"ocsp-uri");

		OCSPResp ocspResp = TrustTestUtils.createOcspResp(certificate, false,
				rootCertificate, rootCertificate, rootKeyPair.getPrivate());

		OcspRepository mockOcspRepository = EasyMock
				.createMock(OcspRepository.class);
		EasyMock.expect(
				mockOcspRepository.findOcspResponse(
						EasyMock.eq(new URI("ocsp-uri")),
						EasyMock.eq(certificate), EasyMock.eq(rootCertificate),
						EasyMock.anyObject(Date.class))).andReturn(ocspResp);

		OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(
				mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		Date validationDate = new Date();

		// operate
		TrustLinkerResult result = ocspTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData(),
				new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.TRUSTED, result);
		EasyMock.verify(mockOcspRepository);
	}

	@Test
	public void rootCAIssuesOcspResponseRootCACertInResponse() throws Exception {

		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);

		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1, null,
				"ocsp-uri");

		OCSPResp ocspResp = TrustTestUtils.createOcspResp(certificate, false,
				rootCertificate, rootCertificate, rootKeyPair.getPrivate(),
				"SHA1withRSA", Collections.singletonList(rootCertificate));

		OcspRepository mockOcspRepository = EasyMock
				.createMock(OcspRepository.class);
		EasyMock.expect(
				mockOcspRepository.findOcspResponse(
						EasyMock.eq(new URI("ocsp-uri")),
						EasyMock.eq(certificate), EasyMock.eq(rootCertificate),
						EasyMock.anyObject(Date.class))).andReturn(ocspResp);

		OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(
				mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		Date validationDate = new Date();

		// operate
		TrustLinkerResult result = ocspTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData(),
				new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.TRUSTED, result);
		EasyMock.verify(mockOcspRepository);
	}

	@Test
	public void invalidDedicatedAuthorizedOcspResponse() throws Exception {

		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);

		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		KeyPair ocspResponderKeyPair = TrustTestUtils.generateKeyPair();
		X509Certificate ocspResponderCertificate = TrustTestUtils
				.generateCertificate(ocspResponderKeyPair.getPublic(),
						"CN=OCSPResp", notBefore, notAfter, rootCertificate,
						rootKeyPair.getPrivate(), false, -1, null, null, null,
						"SHA1withRSA", false, false, false, null, null, null,
						false);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1, null,
				"ocsp-uri");

		OCSPResp ocspResp = TrustTestUtils.createOcspResp(certificate, false,
				rootCertificate, ocspResponderCertificate,
				ocspResponderKeyPair.getPrivate());

		OcspRepository mockOcspRepository = EasyMock
				.createMock(OcspRepository.class);
		EasyMock.expect(
				mockOcspRepository.findOcspResponse(
						EasyMock.eq(new URI("ocsp-uri")),
						EasyMock.eq(certificate), EasyMock.eq(rootCertificate),
						EasyMock.anyObject(Date.class))).andReturn(ocspResp);

		OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(
				mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		Date validationDate = new Date();

		// operate
		TrustLinkerResult result = ocspTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData(),
				new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.UNDECIDED, result);
		EasyMock.verify(mockOcspRepository);
	}

}