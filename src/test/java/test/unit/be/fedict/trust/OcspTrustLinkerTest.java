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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.net.URI;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.BasicOCSPRespGenerator;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.CertificateStatus;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.OCSPRespGenerator;
import org.bouncycastle.ocsp.Req;
import org.bouncycastle.ocsp.RevokedStatus;
import org.easymock.EasyMock;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;

import be.fedict.trust.OcspRepository;
import be.fedict.trust.OcspTrustLinker;

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

		Boolean result = ocspTrustLinker.hasTrustLink(certificate,
				rootCertificate, null);

		assertNull(result);
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
						certificate, rootCertificate)).andReturn(null);

		OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(
				mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		// operate
		Boolean result = ocspTrustLinker.hasTrustLink(certificate,
				rootCertificate, null);

		// verify
		assertNull(result);
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

		OCSPResp ocspResp = createOcspResp(certificate, false, rootCertificate,
				rootCertificate, rootKeyPair.getPrivate());

		OcspRepository mockOcspRepository = EasyMock
				.createMock(OcspRepository.class);
		EasyMock.expect(
				mockOcspRepository.findOcspResponse(new URI("ocsp-uri"),
						certificate, rootCertificate)).andReturn(ocspResp);

		OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(
				mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		Date validationDate = new Date();

		// operate
		Boolean result = ocspTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate);

		// verify
		assertNotNull(result);
		assertTrue(result);
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

		OCSPResp ocspResp = createOcspResp(certificate, false, rootCertificate,
				rootCertificate, rootKeyPair.getPrivate());

		OcspRepository mockOcspRepository = EasyMock
				.createMock(OcspRepository.class);
		EasyMock.expect(
				mockOcspRepository.findOcspResponse(new URI("ocsp-uri"),
						certificate, rootCertificate)).andReturn(ocspResp);

		OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(
				mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		Date validationDate = notBefore.plusDays(1).toDate();

		// operate
		Boolean result = ocspTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate);

		// verify
		assertNull(result);
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

		OCSPResp ocspResp2 = createOcspResp(certificate2, false,
				rootCertificate, rootCertificate, rootKeyPair.getPrivate());

		OcspRepository mockOcspRepository = EasyMock
				.createMock(OcspRepository.class);
		EasyMock.expect(
				mockOcspRepository.findOcspResponse(new URI("ocsp-uri"),
						certificate, rootCertificate)).andReturn(ocspResp2);

		OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(
				mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		Date validationDate = new Date();

		// operate
		Boolean result = ocspTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate);

		// verify
		assertNull(result);
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

		OCSPResp ocspResp = createOcspResp(certificate, true, rootCertificate,
				rootCertificate, rootKeyPair.getPrivate());

		OcspRepository mockOcspRepository = EasyMock
				.createMock(OcspRepository.class);
		EasyMock.expect(
				mockOcspRepository.findOcspResponse(new URI("ocsp-uri"),
						certificate, rootCertificate)).andReturn(ocspResp);

		OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(
				mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		Date validationDate = new Date();

		// operate
		Boolean result = ocspTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate);

		// verify
		assertNotNull(result);
		assertFalse(result);
		EasyMock.verify(mockOcspRepository);
	}

	private OCSPResp createOcspResp(X509Certificate certificate,
			boolean revoked, X509Certificate issuerCertificate,
			X509Certificate ocspResponderCertificate,
			PrivateKey ocspResponderPrivateKey) throws Exception {
		// request
		OCSPReqGenerator ocspReqGenerator = new OCSPReqGenerator();
		CertificateID certId = new CertificateID(CertificateID.HASH_SHA1,
				issuerCertificate, certificate.getSerialNumber());
		ocspReqGenerator.addRequest(certId);
		OCSPReq ocspReq = ocspReqGenerator.generate();

		BasicOCSPRespGenerator basicOCSPRespGenerator = new BasicOCSPRespGenerator(
				ocspResponderCertificate.getPublicKey());

		// request processing
		Req[] requestList = ocspReq.getRequestList();
		for (Req ocspRequest : requestList) {
			CertificateID certificateID = ocspRequest.getCertID();
			CertificateStatus certificateStatus;
			if (revoked) {
				certificateStatus = new RevokedStatus(new Date(),
						CRLReason.unspecified);
			} else {
				certificateStatus = CertificateStatus.GOOD;
			}
			basicOCSPRespGenerator
					.addResponse(certificateID, certificateStatus);
		}

		// basic response generation
		BasicOCSPResp basicOCSPResp = basicOCSPRespGenerator.generate(
				"SHA1WITHRSA", ocspResponderPrivateKey, null, new Date(),
				BouncyCastleProvider.PROVIDER_NAME);

		// response generation
		OCSPRespGenerator ocspRespGenerator = new OCSPRespGenerator();
		OCSPResp ocspResp = ocspRespGenerator.generate(
				OCSPRespGenerator.SUCCESSFUL, basicOCSPResp);

		return ocspResp;
	}
}
