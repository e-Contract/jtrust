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
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import be.fedict.trust.linker.PublicKeyTrustLinker;
import be.fedict.trust.linker.TrustLinkerResult;
import be.fedict.trust.linker.TrustLinkerResultException;
import be.fedict.trust.linker.TrustLinkerResultReason;
import be.fedict.trust.policy.DefaultAlgorithmPolicy;
import be.fedict.trust.revocation.RevocationData;
import be.fedict.trust.test.PKIBuilder;

public class PublicKeyTrustLinkerTest {

	@BeforeAll
	public static void setUp() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void testHasTrustLink() throws Exception {
		// setup
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withValidityMonths(1).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test").withValidityMonths(1).build();

		PublicKeyTrustLinker publicKeyTrustLinker = new PublicKeyTrustLinker();

		Date validationDate = new Date();

		// operate
		TrustLinkerResult result = publicKeyTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate,
				new RevocationData(), new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.UNDECIDED, result);
	}

	@Test
	public void testExpiredCertificate() throws Exception {
		// setup
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		LocalDateTime notBefore = LocalDateTime.now();
		LocalDateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withValidityMonths(1).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test").withValidityMonths(1).build();

		PublicKeyTrustLinker publicKeyTrustLinker = new PublicKeyTrustLinker();

		Date validationDate = Date.from(notAfter.plusDays(1).atZone(ZoneId.systemDefault()).toInstant());

		// operate
		TrustLinkerResultException result = Assertions.assertThrows(TrustLinkerResultException.class, () -> {
			publicKeyTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate, new RevocationData(),
					new DefaultAlgorithmPolicy());
		});
		assertEquals(TrustLinkerResultReason.INVALID_VALIDITY_INTERVAL, result.getReason());

	}

	@Test
	public void testCertificateNotYetValid() throws Exception {
		// setup
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		LocalDateTime notBefore = LocalDateTime.now();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withValidityMonths(1).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test").withValidityMonths(1).build();

		PublicKeyTrustLinker publicKeyTrustLinker = new PublicKeyTrustLinker();

		Date validationDate = Date.from(notBefore.minusDays(1).atZone(ZoneId.systemDefault()).toInstant());

		// operate
		TrustLinkerResultException result = Assertions.assertThrows(TrustLinkerResultException.class, () -> {
			publicKeyTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate, new RevocationData(),
					new DefaultAlgorithmPolicy());
		});
		assertEquals(TrustLinkerResultReason.INVALID_VALIDITY_INTERVAL, result.getReason());
	}

	@Test
	public void testNoCaFlagFailsNotOnRootCAs() throws Exception {
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withValidityMonths(1).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test").withValidityMonths(1).build();

		PublicKeyTrustLinker publicKeyTrustLinker = new PublicKeyTrustLinker();

		Date validationDate = new Date();

		TrustLinkerResult result = publicKeyTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate,
				new RevocationData(), new DefaultAlgorithmPolicy());
		assertNotNull(result);
		// we only allow this on self-signed roots
		assertEquals(TrustLinkerResult.UNDECIDED, result);
	}

	@Test
	public void testNoCaFlagFails() throws Exception {
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withValidityMonths(1).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test").withValidityMonths(1).build();

		KeyPair keyPair2 = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate2 = new PKIBuilder.CertificateBuilder(keyPair2.getPublic(), keyPair.getPrivate(),
				certificate).withSubjectName("CN=Test 2").withValidityMonths(1).build();

		PublicKeyTrustLinker publicKeyTrustLinker = new PublicKeyTrustLinker();

		Date validationDate = new Date();

		TrustLinkerResultException result = Assertions.assertThrows(TrustLinkerResultException.class, () -> {
			publicKeyTrustLinker.hasTrustLink(certificate2, certificate, validationDate, new RevocationData(),
					new DefaultAlgorithmPolicy());
		});
		assertEquals(TrustLinkerResultReason.NO_TRUST, result.getReason());
	}

	@Test
	public void testNoCaFlagFails2() throws Exception {
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withValidityMonths(1).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test").withValidityMonths(1).withBasicConstraints(false).build();

		KeyPair keyPair2 = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate2 = new PKIBuilder.CertificateBuilder(keyPair2.getPublic(), keyPair.getPrivate(),
				certificate).withSubjectName("CN=Test 2").withValidityMonths(1).build();

		PublicKeyTrustLinker publicKeyTrustLinker = new PublicKeyTrustLinker();

		Date validationDate = new Date();

		TrustLinkerResultException result = Assertions.assertThrows(TrustLinkerResultException.class, () -> {
			publicKeyTrustLinker.hasTrustLink(certificate2, certificate, validationDate, new RevocationData(),
					new DefaultAlgorithmPolicy());
		});
		assertEquals(TrustLinkerResultReason.NO_TRUST, result.getReason());
	}

	@Test
	public void testNoCaFlagFails3() throws Exception {
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withValidityMonths(1).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test").withValidityMonths(1).withBasicConstraints(false).build();

		KeyPair keyPair2 = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate2 = new PKIBuilder.CertificateBuilder(keyPair2.getPublic(), keyPair.getPrivate(),
				certificate).withSubjectName("CN=Test 2").withValidityMonths(1).withBasicConstraints(true).build();

		PublicKeyTrustLinker publicKeyTrustLinker = new PublicKeyTrustLinker();

		Date validationDate = new Date();

		TrustLinkerResultException result = Assertions.assertThrows(TrustLinkerResultException.class, () -> {
			publicKeyTrustLinker.hasTrustLink(certificate2, certificate, validationDate, new RevocationData(),
					new DefaultAlgorithmPolicy());
		});
		assertEquals(TrustLinkerResultReason.NO_TRUST, result.getReason());
	}

	@Test
	public void testChildNotAllowToBeCA() throws Exception {
		// setup
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withValidityMonths(1).withBasicConstraints(0).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test").withValidityMonths(1).withBasicConstraints(true).build();

		PublicKeyTrustLinker publicKeyTrustLinker = new PublicKeyTrustLinker();

		Date validationDate = new Date();

		// operate & verify
		TrustLinkerResultException result = Assertions.assertThrows(TrustLinkerResultException.class, () -> {
			publicKeyTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate, new RevocationData(),
					new DefaultAlgorithmPolicy());
		});
		assertEquals(TrustLinkerResultReason.NO_TRUST, result.getReason());
	}

	@Test
	public void testChildNotAllowToBeCA2() throws Exception {
		// setup
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withValidityMonths(1).withBasicConstraints(0).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test").withValidityMonths(1).withBasicConstraints(false).build();

		PublicKeyTrustLinker publicKeyTrustLinker = new PublicKeyTrustLinker();

		Date validationDate = new Date();

		// operate & verify
		TrustLinkerResultException result = Assertions.assertThrows(TrustLinkerResultException.class, () -> {
			publicKeyTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate, new RevocationData(),
					new DefaultAlgorithmPolicy());
		});
		assertEquals(TrustLinkerResultReason.NO_TRUST, result.getReason());
	}

	@Test
	public void testNoChildFails() throws Exception {
		// setup
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withValidityMonths(1).build();

		KeyPair root2keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate root2Certificate = new PKIBuilder.CertificateBuilder(root2keyPair)
				.withSubjectName("CN=TestRoot2").withValidityMonths(1).build();

		PublicKeyTrustLinker publicKeyTrustLinker = new PublicKeyTrustLinker();

		Date validationDate = new Date();

		// operate & verify
		TrustLinkerResultException result = Assertions.assertThrows(TrustLinkerResultException.class, () -> {
			publicKeyTrustLinker.hasTrustLink(root2Certificate, rootCertificate, validationDate, new RevocationData(),
					new DefaultAlgorithmPolicy());
		});
		assertEquals(TrustLinkerResultReason.NO_TRUST, result.getReason());
	}

	@Test
	public void testCACertificateNoSKID() throws Exception {
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withValidityMonths(1).withBasicConstraints(true).withAKIDPublicKey(rootKeyPair.getPublic()).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test").withValidityMonths(1).build();

		PublicKeyTrustLinker publicKeyTrustLinker = new PublicKeyTrustLinker();

		Date validationDate = new Date();

		TrustLinkerResultException result = Assertions.assertThrows(TrustLinkerResultException.class, () -> {
			publicKeyTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate, new RevocationData(),
					new DefaultAlgorithmPolicy());
		});
		assertEquals(TrustLinkerResultReason.NO_TRUST, result.getReason());
	}

	@Test
	public void testChildCACertificateNoAKIDNotSelfSigned() throws Exception {
		// setup
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withValidityMonths(1).build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test").withValidityMonths(1).withIncludeSKID()
				.withBasicConstraints(true).build();

		PublicKeyTrustLinker publicKeyTrustLinker = new PublicKeyTrustLinker();

		Date validationDate = new Date();

		// operate
		TrustLinkerResult result = publicKeyTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate,
				new RevocationData(), new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.UNDECIDED, result);
	}

	@Test
	public void testAKIDMisMatchSKID() throws Exception {
		KeyPair rootKeyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate rootCertificate = new PKIBuilder.CertificateBuilder(rootKeyPair).withSubjectName("CN=TestRoot")
				.withValidityMonths(1).withIncludeSKID().build();

		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		KeyPair akidKeyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair.getPublic(), rootKeyPair.getPrivate(),
				rootCertificate).withSubjectName("CN=Test").withValidityMonths(1)
				.withAKIDPublicKey(akidKeyPair.getPublic()).withIncludeAKID().withIncludeSKID().build();

		PublicKeyTrustLinker publicKeyTrustLinker = new PublicKeyTrustLinker();

		Date validationDate = new Date();

		TrustLinkerResultException result = Assertions.assertThrows(TrustLinkerResultException.class, () -> {
			publicKeyTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate, new RevocationData(),
					new DefaultAlgorithmPolicy());
		});
		assertEquals(TrustLinkerResultReason.NO_TRUST, result.getReason());
	}
}
