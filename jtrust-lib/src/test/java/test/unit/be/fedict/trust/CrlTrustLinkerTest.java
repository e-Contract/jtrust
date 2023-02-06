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
package test.unit.be.fedict.trust;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.net.URI;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.easymock.EasyMock;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import be.fedict.trust.crl.CrlRepository;
import be.fedict.trust.crl.CrlTrustLinker;
import be.fedict.trust.linker.TrustLinkerResult;
import be.fedict.trust.linker.TrustLinkerResultException;
import be.fedict.trust.linker.TrustLinkerResultReason;
import be.fedict.trust.policy.DefaultAlgorithmPolicy;
import be.fedict.trust.revocation.RevocationData;
import be.fedict.trust.test.PKIBuilder;

public class CrlTrustLinkerTest {

	@BeforeEach
	public void setUp() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void noCrlUriInCertificate() throws Exception {
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withValidityMonths(1).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test").withValidityMonths(1).build();

		CrlRepository mockCrlRepository = EasyMock.createMock(CrlRepository.class);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);
		TrustLinkerResult result = crlTrustLinker.hasTrustLink(certificate, rootCertificate, null, new RevocationData(),
				new DefaultAlgorithmPolicy());

		EasyMock.verify(mockCrlRepository);
		assertEquals(TrustLinkerResult.UNDECIDED, result);
	}

	@Test
	public void invalidCrlUriInCertificate() throws Exception {
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withBasicConstraints(true).withValidityMonths(1).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test").withValidityMonths(1).withCrlUri("foobar").build();

		CrlRepository mockCrlRepository = EasyMock.createMock(CrlRepository.class);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		TrustLinkerResult result = crlTrustLinker.hasTrustLink(certificate, rootCertificate, null, new RevocationData(),
				new DefaultAlgorithmPolicy());
		assertEquals(TrustLinkerResult.UNDECIDED, result);
	}

	@Test
	public void noEntryInCrlRepository() throws Exception {
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withBasicConstraints(true).withValidityMonths(1).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate =

				new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(), rootCertificate)
						.withSubjectName("CN=Test").withValidityMonths(1).withCrlUri("http://crl-uri").build();

		Date validationDate = new Date();

		CrlRepository mockCrlRepository = EasyMock.createMock(CrlRepository.class);
		EasyMock.expect(mockCrlRepository.findCrl(new URI("http://crl-uri"), rootCertificate, validationDate))
				.andReturn(null);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		TrustLinkerResult result = crlTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate,
				new RevocationData(), new DefaultAlgorithmPolicy());

		assertEquals(TrustLinkerResult.UNDECIDED, result);
		EasyMock.verify(mockCrlRepository);
	}

	@Test
	public void emptyCrlPasses() throws Exception {
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		LocalDateTime notBefore = LocalDateTime.now();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withBasicConstraints(true).withKeyUsage(KeyUsage.cRLSign).withValidityMonths(1).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test").withValidityMonths(1).withCrlUri("http://crl-uri").build();

		Date validationDate = Date.from(notBefore.plusDays(1).atZone(ZoneId.systemDefault()).toInstant());

		CrlRepository mockCrlRepository = EasyMock.createMock(CrlRepository.class);
		X509CRL x509crl = new PKIBuilder.CRLBuilder(rootKeyPair.getPrivate(), rootCertificate).withValidityMonths(1)
				.build();
		EasyMock.expect(mockCrlRepository.findCrl(new URI("http://crl-uri"), rootCertificate, validationDate))
				.andReturn(x509crl);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		TrustLinkerResult result = crlTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate,
				new RevocationData(), new DefaultAlgorithmPolicy());

		assertEquals(TrustLinkerResult.TRUSTED, result);
		EasyMock.verify(mockCrlRepository);
	}

	@Test
	public void crlMissingKeyUsage() throws Exception {
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		LocalDateTime notBefore = LocalDateTime.now();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withBasicConstraints(true).withValidityMonths(1).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test").withValidityMonths(1).withCrlUri("https://crl-uri").build();

		Date validationDate = Date.from(notBefore.plusDays(1).atZone(ZoneId.systemDefault()).toInstant());

		CrlRepository mockCrlRepository = EasyMock.createMock(CrlRepository.class);
		X509CRL x509crl = new PKIBuilder.CRLBuilder(rootKeyPair.getPrivate(), rootCertificate).withValidityMonths(1)
				.build();
		EasyMock.expect(mockCrlRepository.findCrl(new URI("https://crl-uri"), rootCertificate, validationDate))
				.andReturn(x509crl);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		TrustLinkerResult result = crlTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate,
				new RevocationData(), new DefaultAlgorithmPolicy());

		assertEquals(TrustLinkerResult.TRUSTED, result);
		EasyMock.verify(mockCrlRepository);
	}

	@Test
	public void crlMissingCRLSignKeyUsage() throws Exception {
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		LocalDateTime notBefore = LocalDateTime.now();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withBasicConstraints(true).withKeyUsage(KeyUsage.dataEncipherment).withValidityMonths(1).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test").withValidityMonths(1).withCrlUri("https://crl-uri").build();

		Date validationDate = Date.from(notBefore.plusDays(1).atZone(ZoneId.systemDefault()).toInstant());

		CrlRepository mockCrlRepository = EasyMock.createMock(CrlRepository.class);
		X509CRL x509crl = new PKIBuilder.CRLBuilder(rootKeyPair.getPrivate(), rootCertificate).withValidityMonths(1)
				.build();
		EasyMock.expect(mockCrlRepository.findCrl(new URI("https://crl-uri"), rootCertificate, validationDate))
				.andReturn(x509crl);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		TrustLinkerResult result = crlTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate,
				new RevocationData(), new DefaultAlgorithmPolicy());

		assertEquals(TrustLinkerResult.UNDECIDED, result);
		EasyMock.verify(mockCrlRepository);
	}

	@Test
	public void oldCrl() throws Exception {
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		LocalDateTime notBefore = LocalDateTime.now();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withBasicConstraints(true).withKeyUsage(KeyUsage.cRLSign).withValidityMonths(1).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test").withValidityMonths(1).withCrlUri("http://crl-uri").build();

		Date validationDate = Date.from(notBefore.plusDays(1).atZone(ZoneId.systemDefault()).toInstant());

		CrlRepository mockCrlRepository = EasyMock.createMock(CrlRepository.class);
		X509CRL x509crl =

				new PKIBuilder.CRLBuilder(rootKeyPair.getPrivate(), rootCertificate)
						.withThisUpdate(LocalDateTime.now().minusMonths(2)).withValidityMonths(1).build();

		EasyMock.expect(mockCrlRepository.findCrl(new URI("http://crl-uri"), rootCertificate, validationDate))
				.andReturn(x509crl);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		TrustLinkerResult result = crlTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate,
				new RevocationData(), new DefaultAlgorithmPolicy());

		assertEquals(TrustLinkerResult.UNDECIDED, result);
		EasyMock.verify(mockCrlRepository);
	}

	@Test
	public void crlNotIssuedByRoot() throws Exception {
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		LocalDateTime notBefore = LocalDateTime.now();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withBasicConstraints(true).withKeyUsage(KeyUsage.cRLSign).withValidityMonths(1).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate =

				new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(), rootCertificate)
						.withSubjectName("CN=Test").withValidityMonths(1).withCrlUri("http://crl-uri").build();

		Date validationDate = Date.from(notBefore.plusDays(1).atZone(ZoneId.systemDefault()).toInstant());

		CrlRepository mockCrlRepository = EasyMock.createMock(CrlRepository.class);
		X509CRL x509crl = new PKIBuilder.CRLBuilder(rootKeyPair.getPrivate(), certificate)
				.withThisUpdate(LocalDateTime.now().minusMonths(2)).withValidityMonths(1).build();
		EasyMock.expect(mockCrlRepository.findCrl(new URI("http://crl-uri"), rootCertificate, validationDate))
				.andReturn(x509crl);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		TrustLinkerResult result = crlTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate,
				new RevocationData(), new DefaultAlgorithmPolicy());

		assertEquals(TrustLinkerResult.UNDECIDED, result);
		EasyMock.verify(mockCrlRepository);
	}

	@Test
	public void crlNotSignedByRoot() throws Exception {
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		LocalDateTime notBefore = LocalDateTime.now();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withBasicConstraints(true).withKeyUsage(KeyUsage.cRLSign).withValidityMonths(1).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test").withValidityMonths(1).withCrlUri("http://crl-uri").build();

		Date validationDate = Date.from(notBefore.plusDays(1).atZone(ZoneId.systemDefault()).toInstant());

		CrlRepository mockCrlRepository = EasyMock.createMock(CrlRepository.class);
		X509CRL x509crl = new PKIBuilder.CRLBuilder(keyPair.getPrivate(), rootCertificate)
				.withThisUpdate(LocalDateTime.now().minusMonths(2)).withValidityMonths(1).build();
		EasyMock.expect(mockCrlRepository.findCrl(new URI("http://crl-uri"), rootCertificate, validationDate))
				.andReturn(x509crl);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		TrustLinkerResult result = crlTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate,
				new RevocationData(), new DefaultAlgorithmPolicy());

		assertEquals(TrustLinkerResult.UNDECIDED, result);
		EasyMock.verify(mockCrlRepository);
	}

	@Test
	public void tooFreshCrl() throws Exception {
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		LocalDateTime notBefore = LocalDateTime.now();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withBasicConstraints(true).withKeyUsage(KeyUsage.cRLSign).withValidityMonths(1).build();

		Date validationDate = Date.from(notBefore.plusDays(1).atZone(ZoneId.systemDefault()).toInstant());

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test").withValidityMonths(1).withCrlUri("https://crl-uri").build();

		CrlRepository mockCrlRepository = EasyMock.createMock(CrlRepository.class);
		X509CRL x509crl = new PKIBuilder.CRLBuilder(rootKeyPair.getPrivate(), rootCertificate)
				.withThisUpdate(LocalDateTime.now().plusMonths(2)).withValidityMonths(1).build();
		EasyMock.expect(mockCrlRepository.findCrl(new URI("https://crl-uri"), rootCertificate, validationDate))
				.andReturn(x509crl);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		TrustLinkerResult result = crlTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate,
				new RevocationData(), new DefaultAlgorithmPolicy());

		assertEquals(TrustLinkerResult.UNDECIDED, result);
		EasyMock.verify(mockCrlRepository);
	}

	@Test
	public void revokedCertificate() throws Exception {
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		LocalDateTime notBefore = LocalDateTime.now();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withBasicConstraints(true).withKeyUsage(KeyUsage.cRLSign).withValidityMonths(1).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test").withValidityMonths(1).withCrlUri("https://crl-uri").build();

		Date validationDate = Date.from(notBefore.plusDays(1).atZone(ZoneId.systemDefault()).toInstant());

		CrlRepository mockCrlRepository = EasyMock.createMock(CrlRepository.class);
		X509CRL x509crl = new PKIBuilder.CRLBuilder(rootKeyPair.getPrivate(), rootCertificate).withValidityMonths(1)
				.withRevokedCertificate(certificate).build();

		EasyMock.expect(mockCrlRepository.findCrl(new URI("https://crl-uri"), rootCertificate, validationDate))
				.andReturn(x509crl);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		TrustLinkerResultException result = Assertions.assertThrows(TrustLinkerResultException.class, () -> {
			crlTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate, new RevocationData(),
					new DefaultAlgorithmPolicy());
		});
		assertEquals(TrustLinkerResultReason.INVALID_REVOCATION_STATUS, result.getReason());

		EasyMock.verify(mockCrlRepository);
	}

	@Test
	public void crlMD5Signature() throws Exception {
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		LocalDateTime notBefore = LocalDateTime.now();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withBasicConstraints(true).withKeyUsage(KeyUsage.cRLSign).withValidityMonths(1).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test").withValidityMonths(1).withCrlUri("https://crl-uri").build();

		Date validationDate = Date.from(notBefore.plusDays(1).atZone(ZoneId.systemDefault()).toInstant());

		CrlRepository mockCrlRepository = EasyMock.createMock(CrlRepository.class);
		X509CRL x509crl = new PKIBuilder.CRLBuilder(rootKeyPair.getPrivate(), rootCertificate).withValidityMonths(1)
				.withSignatureAlgorithm("MD5withRSA").build();
		EasyMock.expect(mockCrlRepository.findCrl(new URI("https://crl-uri"), rootCertificate, validationDate))
				.andReturn(x509crl);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		TrustLinkerResultException result = Assertions.assertThrows(TrustLinkerResultException.class, () -> {
			crlTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate, new RevocationData(),
					new DefaultAlgorithmPolicy());
		});
		assertEquals(TrustLinkerResultReason.INVALID_ALGORITHM, result.getReason());
		EasyMock.verify(mockCrlRepository);
	}

	@Test
	public void futureRevokedCertificate() throws Exception {
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		LocalDateTime notBefore = LocalDateTime.now();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withBasicConstraints(true).withKeyUsage(KeyUsage.cRLSign).withValidityMonths(1).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test").withValidityMonths(1).withCrlUri("http://crl-uri").build();

		Date validationDate = Date.from(notBefore.plusDays(1).atZone(ZoneId.systemDefault()).toInstant());

		CrlRepository mockCrlRepository = EasyMock.createMock(CrlRepository.class);
		X509CRL x509crl = new PKIBuilder.CRLBuilder(rootKeyPair.getPrivate(), rootCertificate).withValidityMonths(1)
				.withRevokedCertificate(certificate, LocalDateTime.now().plusDays(2)).build();
		EasyMock.expect(mockCrlRepository.findCrl(new URI("http://crl-uri"), rootCertificate, validationDate))
				.andReturn(x509crl);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		TrustLinkerResult result = crlTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate,
				new RevocationData(), new DefaultAlgorithmPolicy());

		assertEquals(TrustLinkerResult.TRUSTED, result);
		EasyMock.verify(mockCrlRepository);
	}

	@Test
	public void testNullX509CRL() throws Exception {
		final KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		LocalDateTime notBefore = LocalDateTime.now();
		final X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair)
				.withSubjectName("CN=TestRoot").withBasicConstraints(true).withKeyUsage(KeyUsage.cRLSign)
				.withValidityMonths(1).build();

		final KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		final X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(),
				rootKeyPair.getPrivate(), rootCertificate).withSubjectName("CN=Test").withValidityMonths(1)
				.withCrlUri("http://crl-uri").build();

		final Date validationDate = Date.from(notBefore.plusDays(1).atZone(ZoneId.systemDefault()).toInstant());

		final CrlRepository mockCrlRepository = EasyMock.createMock(CrlRepository.class);
		EasyMock.expect(mockCrlRepository.findCrl(new URI("http://crl-uri"), rootCertificate, validationDate))
				.andReturn(null);

		EasyMock.replay(mockCrlRepository);

		final CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);
		final TrustLinkerResult result = crlTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate,
				new RevocationData(), new DefaultAlgorithmPolicy());

		EasyMock.verify(mockCrlRepository);

		assertEquals(TrustLinkerResult.UNDECIDED, result);
	}
}
