/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
 * Copyright (C) 2018-2023 e-Contract.be BV.
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

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.net.URI;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.easymock.EasyMock;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import be.fedict.trust.linker.TrustLinkerResult;
import be.fedict.trust.linker.TrustLinkerResultException;
import be.fedict.trust.linker.TrustLinkerResultReason;
import be.fedict.trust.ocsp.OcspRepository;
import be.fedict.trust.ocsp.OcspTrustLinker;
import be.fedict.trust.policy.DefaultAlgorithmPolicy;
import be.fedict.trust.revocation.RevocationData;
import be.fedict.trust.test.PKIBuilder;

public class OcspTrustLinkerTest {

	@BeforeAll
	public static void setUp() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void noOcspUriInCertificate() throws Exception {
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withValidityMonths(1).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test").withValidityMonths(1).build();

		OcspRepository mockOcspRepository = EasyMock.createMock(OcspRepository.class);
		EasyMock.expect(mockOcspRepository.findOcspResponse(null, certificate, rootCertificate, null)).andReturn(null);

		OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		TrustLinkerResult result = ocspTrustLinker.hasTrustLink(certificate, rootCertificate, null,
				new RevocationData(), new DefaultAlgorithmPolicy());

		assertEquals(TrustLinkerResult.UNDECIDED, result);
		EasyMock.verify(mockOcspRepository);
	}

	@Test
	public void noOcspResponseInRepository() throws Exception {
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withValidityMonths(1).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test").withOcspUri("ocsp-uri").withValidityMonths(1).build();

		OcspRepository mockOcspRepository = EasyMock.createMock(OcspRepository.class);
		EasyMock.expect(mockOcspRepository.findOcspResponse(new URI("ocsp-uri"), certificate, rootCertificate, null))
				.andReturn(null);

		OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		// operate
		TrustLinkerResult result = ocspTrustLinker.hasTrustLink(certificate, rootCertificate, null,
				new RevocationData(), new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.UNDECIDED, result);
		EasyMock.verify(mockOcspRepository);
	}

	@Test
	public void validOcspResponse() throws Exception {
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withValidityMonths(1).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test").withOcspUri("ocsp-uri").withValidityMonths(1).build();

		OCSPResp ocspResp = new PKIBuilder.OCSPBuilder(rootKeyPair.getPrivate(), rootCertificate, certificate,
				rootCertificate).build();

		OcspRepository mockOcspRepository = EasyMock.createMock(OcspRepository.class);
		EasyMock.expect(mockOcspRepository.findOcspResponse(EasyMock.eq(new URI("ocsp-uri")), EasyMock.eq(certificate),
				EasyMock.eq(rootCertificate), EasyMock.anyObject(Date.class))).andReturn(ocspResp);

		OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		Date validationDate = new Date();

		// operate
		TrustLinkerResult result = ocspTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate,
				new RevocationData(), new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.TRUSTED, result);
		EasyMock.verify(mockOcspRepository);
	}

	@Test
	public void ocspResponder() throws Exception {
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withValidityMonths(1).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test").withOcspUri("ocsp-uri").withValidityMonths(1).build();

		OCSPResp ocspResp = new PKIBuilder.OCSPBuilder(rootKeyPair.getPrivate(), rootCertificate, certificate,
				rootCertificate).build();

		OcspRepository mockOcspRepository = EasyMock.createMock(OcspRepository.class);
		EasyMock.expect(mockOcspRepository.findOcspResponse(EasyMock.eq(new URI("ocsp-uri")), EasyMock.eq(certificate),
				EasyMock.eq(rootCertificate), EasyMock.anyObject(Date.class))).andReturn(ocspResp);

		OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		Date validationDate = new Date();

		// operate
		TrustLinkerResult result = ocspTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate,
				new RevocationData(), new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.TRUSTED, result);
		EasyMock.verify(mockOcspRepository);
	}

	@Test
	public void ocspResponseWronglySigned() throws Exception {
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withValidityMonths(1).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test").withOcspUri("ocsp-uri").withValidityMonths(1).build();

		KeyPair ocspResponderKeyPair = new PKIBuilder.KeyPairBuilder().build();
		OCSPResp ocspResp = new PKIBuilder.OCSPBuilder(ocspResponderKeyPair.getPrivate(), rootCertificate, certificate,
				rootCertificate).build();

		OcspRepository mockOcspRepository = EasyMock.createMock(OcspRepository.class);
		EasyMock.expect(mockOcspRepository.findOcspResponse(EasyMock.eq(new URI("ocsp-uri")), EasyMock.eq(certificate),
				EasyMock.eq(rootCertificate), EasyMock.anyObject(Date.class))).andReturn(ocspResp);

		OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		Date validationDate = new Date();

		// operate
		TrustLinkerResult result = ocspTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate,
				new RevocationData(), new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.UNDECIDED, result);
		EasyMock.verify(mockOcspRepository);
	}

	@Test
	public void ocspResponseMD5Signature() throws Exception {
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withValidityMonths(1).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test").withOcspUri("ocsp-uri").withValidityMonths(1).build();

		OCSPResp ocspResp = new PKIBuilder.OCSPBuilder(rootKeyPair.getPrivate(), rootCertificate, certificate,
				rootCertificate).withSignatureAlgorithm("MD5withRSA").build();

		OcspRepository mockOcspRepository = EasyMock.createMock(OcspRepository.class);
		EasyMock.expect(mockOcspRepository.findOcspResponse(EasyMock.eq(new URI("ocsp-uri")), EasyMock.eq(certificate),
				EasyMock.eq(rootCertificate), EasyMock.anyObject(Date.class))).andReturn(ocspResp);

		OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		Date validationDate = new Date();

		// operate
		TrustLinkerResultException result = Assertions.assertThrows(TrustLinkerResultException.class, () -> {
			ocspTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate, new RevocationData(),
					new DefaultAlgorithmPolicy());
		});
		assertEquals(TrustLinkerResultReason.INVALID_ALGORITHM, result.getReason());

		// verify
		EasyMock.verify(mockOcspRepository);
	}

	@Test
	public void ocspNotFresh() throws Exception {
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		LocalDateTime notBefore = LocalDateTime.now();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withValidityMonths(1).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test").withOcspUri("ocsp-uri").withValidityMonths(1).build();

		OCSPResp ocspResp = new PKIBuilder.OCSPBuilder(rootKeyPair.getPrivate(), rootCertificate, certificate,
				rootCertificate).build();

		OcspRepository mockOcspRepository = EasyMock.createMock(OcspRepository.class);
		EasyMock.expect(mockOcspRepository.findOcspResponse(EasyMock.eq(new URI("ocsp-uri")), EasyMock.eq(certificate),
				EasyMock.eq(rootCertificate), EasyMock.anyObject(Date.class))).andReturn(ocspResp);

		OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		Date validationDate = Date.from(notBefore.plusDays(1).atZone(ZoneId.systemDefault()).toInstant());

		// operate
		TrustLinkerResult result = ocspTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate,
				new RevocationData(), new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.UNDECIDED, result);
		EasyMock.verify(mockOcspRepository);
	}

	@Test
	public void wrongOcspResponse() throws Exception {
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withValidityMonths(1).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test").withOcspUri("ocsp-uri").withValidityMonths(1).build();

		X509Certificate certificate2 = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test2").withOcspUri("ocsp-uri").withValidityMonths(1).build();

		OCSPResp ocspResp2 = new PKIBuilder.OCSPBuilder(rootKeyPair.getPrivate(), rootCertificate, certificate2,
				rootCertificate).build();

		OcspRepository mockOcspRepository = EasyMock.createMock(OcspRepository.class);
		EasyMock.expect(mockOcspRepository.findOcspResponse(EasyMock.eq(new URI("ocsp-uri")), EasyMock.eq(certificate),
				EasyMock.eq(rootCertificate), EasyMock.anyObject(Date.class))).andReturn(ocspResp2);

		OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		Date validationDate = new Date();

		// operate
		TrustLinkerResult result = ocspTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate,
				new RevocationData(), new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.UNDECIDED, result);
		EasyMock.verify(mockOcspRepository);
	}

	@Test
	public void revokedOcsp() throws Exception {
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withValidityMonths(1).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test").withOcspUri("ocsp-uri").withValidityMonths(1).build();

		OCSPResp ocspResp = new PKIBuilder.OCSPBuilder(rootKeyPair.getPrivate(), rootCertificate, certificate,
				rootCertificate).withRevoked().build();

		OcspRepository mockOcspRepository = EasyMock.createMock(OcspRepository.class);
		EasyMock.expect(mockOcspRepository.findOcspResponse(EasyMock.eq(new URI("ocsp-uri")), EasyMock.eq(certificate),
				EasyMock.eq(rootCertificate), EasyMock.anyObject(Date.class))).andReturn(ocspResp);

		OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		Date validationDate = new Date();

		// operate
		TrustLinkerResultException result = Assertions.assertThrows(TrustLinkerResultException.class, () -> {
			ocspTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate, new RevocationData(),
					new DefaultAlgorithmPolicy());
		});
		assertEquals(TrustLinkerResultReason.INVALID_REVOCATION_STATUS, result.getReason());

		// verify
		EasyMock.verify(mockOcspRepository);
	}

	@Test
	public void validDedicatedAuthorizedOcspResponse() throws Exception {
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withValidityMonths(1).build();

		KeyPair ocspResponderKeyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate ocspResponderCertificate = new PKIBuilder.CertificateBuilder(ocspResponderKeyPair.getPublic(),
				rootKeyPair.getPrivate(), rootCertificate).withSubjectName("CN=OCSPResp").withOcspResponder()
				.withValidityMonths(1).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test").withOcspUri("ocsp-uri").withValidityMonths(1).build();

		OCSPResp ocspResp = new PKIBuilder.OCSPBuilder(ocspResponderKeyPair.getPrivate(), ocspResponderCertificate,
				certificate, rootCertificate).build();

		OcspRepository mockOcspRepository = EasyMock.createMock(OcspRepository.class);
		EasyMock.expect(mockOcspRepository.findOcspResponse(EasyMock.eq(new URI("ocsp-uri")), EasyMock.eq(certificate),
				EasyMock.eq(rootCertificate), EasyMock.anyObject(Date.class))).andReturn(ocspResp);

		OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		Date validationDate = new Date();

		// operate
		TrustLinkerResult result = ocspTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate,
				new RevocationData(), new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.TRUSTED, result);
		EasyMock.verify(mockOcspRepository);
	}

	@Test
	public void rootCAIssuesOcspResponseNoCertInResponse() throws Exception {
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withValidityMonths(1).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test").withOcspUri("ocsp-uri").withValidityMonths(1).build();

		OCSPResp ocspResp = new PKIBuilder.OCSPBuilder(rootKeyPair.getPrivate(), rootCertificate, certificate,
				rootCertificate).build();

		OcspRepository mockOcspRepository = EasyMock.createMock(OcspRepository.class);
		EasyMock.expect(mockOcspRepository.findOcspResponse(EasyMock.eq(new URI("ocsp-uri")), EasyMock.eq(certificate),
				EasyMock.eq(rootCertificate), EasyMock.anyObject(Date.class))).andReturn(ocspResp);

		OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		Date validationDate = new Date();

		// operate
		TrustLinkerResult result = ocspTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate,
				new RevocationData(), new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.TRUSTED, result);
		EasyMock.verify(mockOcspRepository);
	}

	@Test
	public void rootCAIssuesOcspResponseRootCACertInResponse() throws Exception {
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withValidityMonths(1).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test").withOcspUri("ocsp-uri").withValidityMonths(1).build();

		OCSPResp ocspResp = new PKIBuilder.OCSPBuilder(rootKeyPair.getPrivate(), rootCertificate, certificate,
				rootCertificate).withResponderChain(rootCertificate).build();

		OcspRepository mockOcspRepository = EasyMock.createMock(OcspRepository.class);
		EasyMock.expect(mockOcspRepository.findOcspResponse(EasyMock.eq(new URI("ocsp-uri")), EasyMock.eq(certificate),
				EasyMock.eq(rootCertificate), EasyMock.anyObject(Date.class))).andReturn(ocspResp);

		OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		Date validationDate = new Date();

		// operate
		TrustLinkerResult result = ocspTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate,
				new RevocationData(), new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.TRUSTED, result);
		EasyMock.verify(mockOcspRepository);
	}

	@Test
	public void invalidDedicatedAuthorizedOcspResponse() throws Exception {
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withValidityMonths(1).build();

		KeyPair ocspResponderKeyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate ocspResponderCertificate = new PKIBuilder.CertificateBuilder(ocspResponderKeyPair.getPublic(),
				rootKeyPair.getPrivate(), rootCertificate).withSubjectName("CN=OCSPResp")
				// .withOcspResponder()
				.withValidityMonths(1).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test").withOcspUri("ocsp-uri").withValidityMonths(1).build();

		OCSPResp ocspResp = new PKIBuilder.OCSPBuilder(ocspResponderKeyPair.getPrivate(), ocspResponderCertificate,
				certificate, rootCertificate).build();

		OcspRepository mockOcspRepository = EasyMock.createMock(OcspRepository.class);
		EasyMock.expect(mockOcspRepository.findOcspResponse(EasyMock.eq(new URI("ocsp-uri")), EasyMock.eq(certificate),
				EasyMock.eq(rootCertificate), EasyMock.anyObject(Date.class))).andReturn(ocspResp);

		OcspTrustLinker ocspTrustLinker = new OcspTrustLinker(mockOcspRepository);

		EasyMock.replay(mockOcspRepository);

		Date validationDate = new Date();

		// operate
		TrustLinkerResult result = ocspTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate,
				new RevocationData(), new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.UNDECIDED, result);
		EasyMock.verify(mockOcspRepository);
	}

}
