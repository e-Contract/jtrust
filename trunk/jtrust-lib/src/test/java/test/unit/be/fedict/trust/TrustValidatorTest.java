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

import java.security.KeyPair;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.easymock.EasyMock;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;

import be.fedict.trust.AlgorithmPolicy;
import be.fedict.trust.CertificateConstraint;
import be.fedict.trust.CertificateRepository;
import be.fedict.trust.DefaultAlgorithmPolicy;
import be.fedict.trust.TrustLinker;
import be.fedict.trust.TrustLinkerResult;
import be.fedict.trust.TrustLinkerResultException;
import be.fedict.trust.TrustLinkerResultReason;
import be.fedict.trust.TrustValidator;

public class TrustValidatorTest {

	@Before
	public void setUp() throws Exception {
		if (null == Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	@Test
	public void createInstance() throws Exception {
		new TrustValidator(null);
	}

	@Test
	public void emptyCertPathFails() throws Exception {
		TrustValidator trustValidator = new TrustValidator(null);

		try {
			trustValidator.isTrusted(new LinkedList<X509Certificate>());
			fail();
		} catch (TrustLinkerResultException e) {
			// expected
			assertEquals(TrustLinkerResultReason.UNSPECIFIED, e.getReason());
		}
	}

	@Test
	public void doNotTrustUnknownCertificate() throws Exception {
		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = TrustTestUtils
				.generateSelfSignedCertificate(keyPair, "CN=Test", notBefore,
						notAfter);

		CertificateRepository mockCertificateRepository = EasyMock
				.createMock(CertificateRepository.class);
		TrustValidator trustValidator = new TrustValidator(
				mockCertificateRepository);

		EasyMock.expect(mockCertificateRepository.isTrustPoint(certificate))
				.andReturn(false);

		List<X509Certificate> certificatePath = new LinkedList<X509Certificate>();
		certificatePath.add(certificate);

		try {
			trustValidator.isTrusted(certificatePath);
			fail();
		} catch (TrustLinkerResultException e) {
			// expected
			assertEquals(TrustLinkerResultReason.ROOT, e.getReason());
		}
	}

	@Test
	public void trustKnownCertificate() throws Exception {

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = TrustTestUtils
				.generateSelfSignedCertificate(keyPair, "CN=Test", notBefore,
						notAfter);

		CertificateRepository mockCertificateRepository = EasyMock
				.createMock(CertificateRepository.class);
		TrustValidator trustValidator = new TrustValidator(
				mockCertificateRepository);

		EasyMock.expect(mockCertificateRepository.isTrustPoint(certificate))
				.andReturn(true);

		List<X509Certificate> certificatePath = new LinkedList<X509Certificate>();
		certificatePath.add(certificate);

		EasyMock.replay(mockCertificateRepository);

		trustValidator.isTrusted(certificatePath);

		EasyMock.verify(mockCertificateRepository);
	}

	@Test
	public void trustKnownCertificateSHA256WithRSA() throws Exception {

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = TrustTestUtils
				.generateSelfSignedCertificate(keyPair, "CN=test", notBefore,
						notAfter, true, -1, null, null, "SHA256WithRSA");

		CertificateRepository mockCertificateRepository = EasyMock
				.createMock(CertificateRepository.class);
		TrustValidator trustValidator = new TrustValidator(
				mockCertificateRepository);

		EasyMock.expect(mockCertificateRepository.isTrustPoint(certificate))
				.andReturn(true);

		List<X509Certificate> certificatePath = new LinkedList<X509Certificate>();
		certificatePath.add(certificate);

		EasyMock.replay(mockCertificateRepository);

		trustValidator.isTrusted(certificatePath);

		EasyMock.verify(mockCertificateRepository);
	}

	@Test
	public void doNotTrustExpiredCertificate() throws Exception {

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime().minusMonths(2);
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = TrustTestUtils
				.generateSelfSignedCertificate(keyPair, "CN=Test", notBefore,
						notAfter);

		CertificateRepository mockCertificateRepository = EasyMock
				.createMock(CertificateRepository.class);
		TrustValidator trustValidator = new TrustValidator(
				mockCertificateRepository);

		EasyMock.expect(mockCertificateRepository.isTrustPoint(certificate))
				.andStubReturn(true);

		List<X509Certificate> certificatePath = new LinkedList<X509Certificate>();
		certificatePath.add(certificate);

		EasyMock.replay(mockCertificateRepository);

		try {
			trustValidator.isTrusted(certificatePath);
			fail();
		} catch (TrustLinkerResultException e) {
			// expected
			assertEquals(TrustLinkerResultReason.INVALID_VALIDITY_INTERVAL,
					e.getReason());
			EasyMock.verify(mockCertificateRepository);
		}
	}

	@Test
	public void historicalTrustExpiredCertificate() throws Exception {

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime().minusMonths(2);
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = TrustTestUtils
				.generateSelfSignedCertificate(keyPair, "CN=Test", notBefore,
						notAfter);

		CertificateRepository mockCertificateRepository = EasyMock
				.createMock(CertificateRepository.class);
		TrustValidator trustValidator = new TrustValidator(
				mockCertificateRepository);

		EasyMock.expect(mockCertificateRepository.isTrustPoint(certificate))
				.andStubReturn(true);

		List<X509Certificate> certificatePath = new LinkedList<X509Certificate>();
		certificatePath.add(certificate);

		EasyMock.replay(mockCertificateRepository);

		trustValidator.isTrusted(certificatePath, notBefore.plusWeeks(2)
				.toDate());
	}

	@Test
	public void notSelfSignedNotTrusted() throws Exception {

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

		CertificateRepository mockCertificateRepository = EasyMock
				.createMock(CertificateRepository.class);
		TrustValidator trustValidator = new TrustValidator(
				mockCertificateRepository);

		List<X509Certificate> certificatePath = new LinkedList<X509Certificate>();
		certificatePath.add(certificate);

		EasyMock.replay(mockCertificateRepository);

		try {
			trustValidator.isTrusted(certificatePath);
			fail();
		} catch (TrustLinkerResultException e) {
			// expected
			assertEquals(TrustLinkerResultReason.NO_TRUST, e.getReason());
			EasyMock.verify(mockCertificateRepository);
		}
	}

	@Test
	public void claimedSelfSignedNotTrusted() throws Exception {

		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=TestRoot", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate());

		CertificateRepository mockCertificateRepository = EasyMock
				.createMock(CertificateRepository.class);
		TrustValidator trustValidator = new TrustValidator(
				mockCertificateRepository);

		List<X509Certificate> certificatePath = new LinkedList<X509Certificate>();
		certificatePath.add(certificate);

		EasyMock.replay(mockCertificateRepository);

		try {
			trustValidator.isTrusted(certificatePath);
			fail();
		} catch (TrustLinkerResultException e) {
			// expected
			assertEquals(TrustLinkerResultReason.INVALID_SIGNATURE,
					e.getReason());
			EasyMock.verify(mockCertificateRepository);
		}
	}

	@Test
	public void noTrustLinkerFails() throws Exception {

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

		CertificateRepository mockCertificateRepository = EasyMock
				.createMock(CertificateRepository.class);
		TrustValidator trustValidator = new TrustValidator(
				mockCertificateRepository);

		List<X509Certificate> certificatePath = new LinkedList<X509Certificate>();
		certificatePath.add(certificate);
		certificatePath.add(rootCertificate);

		EasyMock.expect(mockCertificateRepository.isTrustPoint(rootCertificate))
				.andStubReturn(true);

		EasyMock.replay(mockCertificateRepository);

		try {
			trustValidator.isTrusted(certificatePath);
			fail();
		} catch (TrustLinkerResultException e) {
			// expected
			assertEquals(TrustLinkerResultReason.NO_TRUST, e.getReason());
			EasyMock.verify(mockCertificateRepository);
		}
	}

	@Test
	public void trustLink() throws Exception {

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

		CertificateRepository mockCertificateRepository = EasyMock
				.createMock(CertificateRepository.class);
		TrustValidator trustValidator = new TrustValidator(
				mockCertificateRepository);

		List<X509Certificate> certificatePath = new LinkedList<X509Certificate>();
		certificatePath.add(certificate);
		certificatePath.add(rootCertificate);

		EasyMock.expect(mockCertificateRepository.isTrustPoint(rootCertificate))
				.andReturn(true);

		Date validationDate = new Date();

		TrustLinker mockTrustLinker = EasyMock.createMock(TrustLinker.class);
		EasyMock.expect(
				mockTrustLinker.hasTrustLink(EasyMock.eq(certificate),
						EasyMock.eq(rootCertificate),
						EasyMock.eq(validationDate),
						EasyMock.eq(trustValidator.getRevocationData()),
						EasyMock.anyObject(AlgorithmPolicy.class))).andReturn(
				TrustLinkerResult.TRUSTED);
		trustValidator.addTrustLinker(mockTrustLinker);

		EasyMock.replay(mockCertificateRepository, mockTrustLinker);

		trustValidator.isTrusted(certificatePath, validationDate);

		EasyMock.verify(mockCertificateRepository, mockTrustLinker);
	}

	@Test
	public void trustLinkMD5Certificate() throws Exception {

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
				null, null, "MD5withRSA");

		CertificateRepository mockCertificateRepository = EasyMock
				.createMock(CertificateRepository.class);
		TrustValidator trustValidator = new TrustValidator(
				mockCertificateRepository);

		List<X509Certificate> certificatePath = new LinkedList<X509Certificate>();
		certificatePath.add(certificate);
		certificatePath.add(rootCertificate);

		EasyMock.expect(mockCertificateRepository.isTrustPoint(rootCertificate))
				.andReturn(true);

		Date validationDate = new Date();

		TrustLinker mockTrustLinker = EasyMock.createMock(TrustLinker.class);
		EasyMock.expect(
				mockTrustLinker.hasTrustLink(certificate, rootCertificate,
						validationDate, trustValidator.getRevocationData(),
						new DefaultAlgorithmPolicy())).andReturn(
				TrustLinkerResult.TRUSTED);
		trustValidator.addTrustLinker(mockTrustLinker);

		EasyMock.replay(mockCertificateRepository, mockTrustLinker);

		try {
			trustValidator.isTrusted(certificatePath, validationDate);
			fail();
		} catch (TrustLinkerResultException e) {
			// expected
			assertEquals(TrustLinkerResultReason.INVALID_ALGORITHM,
					e.getReason());
		}
	}

	@Test
	public void trustMD5CertificateAllowedViaAlgorithmPolicy() throws Exception {

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
				null, null, "MD5withRSA");

		CertificateRepository mockCertificateRepository = EasyMock
				.createMock(CertificateRepository.class);
		TrustValidator trustValidator = new TrustValidator(
				mockCertificateRepository);

		List<X509Certificate> certificatePath = new LinkedList<X509Certificate>();
		certificatePath.add(certificate);
		certificatePath.add(rootCertificate);

		EasyMock.expect(mockCertificateRepository.isTrustPoint(rootCertificate))
				.andReturn(true);

		Date validationDate = new Date();

		TrustLinker mockTrustLinker = EasyMock.createMock(TrustLinker.class);
		EasyMock.expect(
				mockTrustLinker.hasTrustLink(EasyMock.eq(certificate),
						EasyMock.eq(rootCertificate),
						EasyMock.eq(validationDate),
						EasyMock.eq(trustValidator.getRevocationData()),
						EasyMock.anyObject(AlgorithmPolicy.class))).andReturn(
				TrustLinkerResult.TRUSTED);
		trustValidator.addTrustLinker(mockTrustLinker);

		EasyMock.replay(mockCertificateRepository, mockTrustLinker);

		trustValidator.setAlgorithmPolicy(new AlgorithmPolicy() {
			@Override
			public void checkSignatureAlgorithm(String signatureAlgorithm)
					throws SignatureException {
				// allow all
			}
		});

		trustValidator.isTrusted(certificatePath, validationDate);
	}

	@Test
	public void trustWithCertificateConstraint() throws Exception {

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

		CertificateRepository mockCertificateRepository = EasyMock
				.createMock(CertificateRepository.class);
		TrustValidator trustValidator = new TrustValidator(
				mockCertificateRepository);

		List<X509Certificate> certificatePath = new LinkedList<X509Certificate>();
		certificatePath.add(certificate);
		certificatePath.add(rootCertificate);

		EasyMock.expect(mockCertificateRepository.isTrustPoint(rootCertificate))
				.andReturn(true);

		Date validationDate = new Date();

		TrustLinker mockTrustLinker = EasyMock.createMock(TrustLinker.class);
		EasyMock.expect(
				mockTrustLinker.hasTrustLink(EasyMock.eq(certificate),
						EasyMock.eq(rootCertificate),
						EasyMock.eq(validationDate),
						EasyMock.eq(trustValidator.getRevocationData()),
						EasyMock.anyObject(AlgorithmPolicy.class))).andReturn(
				TrustLinkerResult.TRUSTED);
		trustValidator.addTrustLinker(mockTrustLinker);

		CertificateConstraint mockCertificateConstraint = EasyMock
				.createMock(CertificateConstraint.class);
		mockCertificateConstraint.check(certificate);
		trustValidator.addCertificateConstrain(mockCertificateConstraint);

		EasyMock.replay(mockCertificateRepository, mockCertificateConstraint,
				mockTrustLinker);

		trustValidator.isTrusted(certificatePath, validationDate);

		EasyMock.verify(mockCertificateRepository, mockCertificateConstraint,
				mockTrustLinker);
	}

	@Test
	public void trustInvalidCertificateConstraint() throws Exception {
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

		CertificateRepository mockCertificateRepository = EasyMock
				.createMock(CertificateRepository.class);
		TrustValidator trustValidator = new TrustValidator(
				mockCertificateRepository);

		List<X509Certificate> certificatePath = new LinkedList<X509Certificate>();
		certificatePath.add(certificate);
		certificatePath.add(rootCertificate);

		EasyMock.expect(mockCertificateRepository.isTrustPoint(rootCertificate))
				.andReturn(true);

		Date validationDate = new Date();

		TrustLinker mockTrustLinker = EasyMock.createMock(TrustLinker.class);
		EasyMock.expect(
				mockTrustLinker.hasTrustLink(EasyMock.eq(certificate),
						EasyMock.eq(rootCertificate),
						EasyMock.eq(validationDate),
						EasyMock.eq(trustValidator.getRevocationData()),
						EasyMock.anyObject(AlgorithmPolicy.class))).andReturn(
				TrustLinkerResult.TRUSTED);
		trustValidator.addTrustLinker(mockTrustLinker);

		CertificateConstraint mockCertificateConstraint = EasyMock
				.createMock(CertificateConstraint.class);
		mockCertificateConstraint.check(certificate);
        EasyMock.expectLastCall().andThrow(new TrustLinkerResultException(TrustLinkerResultReason.CONSTRAINT_VIOLATION));
		trustValidator.addCertificateConstrain(mockCertificateConstraint);

		EasyMock.replay(mockCertificateRepository, mockCertificateConstraint,
				mockTrustLinker);

		try {
			trustValidator.isTrusted(certificatePath, validationDate);
			fail();
		} catch (TrustLinkerResultException e) {
			// expected
			assertEquals(TrustLinkerResultReason.CONSTRAINT_VIOLATION, e.getReason());
			EasyMock.verify(mockCertificateRepository,
					mockCertificateConstraint, mockTrustLinker);
		}

	}

	@Test
	public void trustLinkThreeCertificates() throws Exception {

		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter);

		KeyPair interKeyPair = TrustTestUtils.generateKeyPair();
		X509Certificate interCertificate = TrustTestUtils.generateCertificate(
				interKeyPair.getPublic(), "CN=Inter", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate());

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				interCertificate, interKeyPair.getPrivate());

		CertificateRepository mockCertificateRepository = EasyMock
				.createMock(CertificateRepository.class);
		TrustValidator trustValidator = new TrustValidator(
				mockCertificateRepository);

		List<X509Certificate> certificatePath = new LinkedList<X509Certificate>();
		certificatePath.add(certificate);
		certificatePath.add(interCertificate);
		certificatePath.add(rootCertificate);

		EasyMock.expect(mockCertificateRepository.isTrustPoint(rootCertificate))
				.andReturn(true);

		Date validationDate = new Date();

		TrustLinker mockTrustLinker = EasyMock.createMock(TrustLinker.class);
		EasyMock.expect(
				mockTrustLinker.hasTrustLink(EasyMock.eq(interCertificate),
						EasyMock.eq(rootCertificate),
						EasyMock.eq(validationDate),
						EasyMock.eq(trustValidator.getRevocationData()),
						EasyMock.anyObject(AlgorithmPolicy.class))).andReturn(
				TrustLinkerResult.TRUSTED);
		EasyMock.expect(
				mockTrustLinker.hasTrustLink(EasyMock.eq(certificate),
						EasyMock.eq(interCertificate),
						EasyMock.eq(validationDate),
						EasyMock.eq(trustValidator.getRevocationData()),
						EasyMock.anyObject(AlgorithmPolicy.class))).andReturn(
				TrustLinkerResult.TRUSTED);
		trustValidator.addTrustLinker(mockTrustLinker);

		EasyMock.replay(mockCertificateRepository, mockTrustLinker);

		trustValidator.isTrusted(certificatePath, validationDate);

		EasyMock.verify(mockCertificateRepository, mockTrustLinker);
	}

	@Test
	public void noTrustLinkFails() throws Exception {

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

		CertificateRepository mockCertificateRepository = EasyMock
				.createMock(CertificateRepository.class);
		TrustValidator trustValidator = new TrustValidator(
				mockCertificateRepository);

		List<X509Certificate> certificatePath = new LinkedList<X509Certificate>();
		certificatePath.add(certificate);
		certificatePath.add(rootCertificate);

		EasyMock.expect(mockCertificateRepository.isTrustPoint(rootCertificate))
				.andReturn(true);

		Date validationDate = new Date();

		TrustLinker mockTrustLinker = EasyMock.createMock(TrustLinker.class);
		EasyMock.expect(
				mockTrustLinker.hasTrustLink(EasyMock.eq(certificate),
						EasyMock.eq(rootCertificate),
						EasyMock.eq(validationDate),
						EasyMock.eq(trustValidator.getRevocationData()),
						EasyMock.anyObject(AlgorithmPolicy.class))).andReturn(
				TrustLinkerResult.UNDECIDED);
		trustValidator.addTrustLinker(mockTrustLinker);

		EasyMock.replay(mockCertificateRepository, mockTrustLinker);

		try {
			trustValidator.isTrusted(certificatePath, validationDate);
			fail();
		} catch (TrustLinkerResultException e) {
			// expected
			EasyMock.verify(mockCertificateRepository, mockTrustLinker);
		}
	}

	@Test
	public void oneTrustLinkerNoFails() throws Exception {

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

		CertificateRepository mockCertificateRepository = EasyMock
				.createMock(CertificateRepository.class);
		TrustValidator trustValidator = new TrustValidator(
				mockCertificateRepository);

		List<X509Certificate> certificatePath = new LinkedList<X509Certificate>();
		certificatePath.add(certificate);
		certificatePath.add(rootCertificate);

		EasyMock.expect(mockCertificateRepository.isTrustPoint(rootCertificate))
				.andReturn(true);

		Date validationDate = new Date();

		TrustLinker mockTrustLinker = EasyMock.createMock(TrustLinker.class);
		EasyMock.expect(
				mockTrustLinker.hasTrustLink(EasyMock.eq(certificate),
						EasyMock.eq(rootCertificate),
						EasyMock.eq(validationDate),
						EasyMock.eq(trustValidator.getRevocationData()),
						EasyMock.anyObject(AlgorithmPolicy.class))).andReturn(
				TrustLinkerResult.TRUSTED);
		trustValidator.addTrustLinker(mockTrustLinker);

		TrustLinker mockTrustLinker2 = EasyMock.createMock(TrustLinker.class);
		EasyMock.expect(
				mockTrustLinker2.hasTrustLink(EasyMock.eq(certificate),
						EasyMock.eq(rootCertificate),
						EasyMock.eq(validationDate),
						EasyMock.eq(trustValidator.getRevocationData()),
						EasyMock.anyObject(AlgorithmPolicy.class))).andReturn(
				TrustLinkerResult.UNDECIDED);
		trustValidator.addTrustLinker(mockTrustLinker2);

		EasyMock.replay(mockCertificateRepository, mockTrustLinker,
				mockTrustLinker2);

	    trustValidator.isTrusted(certificatePath, validationDate);
	}

	@Test
	public void unknownTrustLinkFails() throws Exception {

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

		CertificateRepository mockCertificateRepository = EasyMock
				.createMock(CertificateRepository.class);
		TrustValidator trustValidator = new TrustValidator(
				mockCertificateRepository);

		List<X509Certificate> certificatePath = new LinkedList<X509Certificate>();
		certificatePath.add(certificate);
		certificatePath.add(rootCertificate);

		EasyMock.expect(mockCertificateRepository.isTrustPoint(rootCertificate))
				.andReturn(true);

		Date validationDate = new Date();

		TrustLinker mockTrustLinker = EasyMock.createMock(TrustLinker.class);
		EasyMock.expect(
				mockTrustLinker.hasTrustLink(EasyMock.eq(certificate),
						EasyMock.eq(rootCertificate),
						EasyMock.eq(validationDate),
						EasyMock.eq(trustValidator.getRevocationData()),
						EasyMock.anyObject(AlgorithmPolicy.class))).andReturn(
				TrustLinkerResult.UNDECIDED);
		trustValidator.addTrustLinker(mockTrustLinker);

		EasyMock.replay(mockCertificateRepository, mockTrustLinker);

		try {
			trustValidator.isTrusted(certificatePath, validationDate);
			fail();
		} catch (TrustLinkerResultException e) {
			// expected
			assertEquals(TrustLinkerResultReason.NO_TRUST, e.getReason());
			EasyMock.verify(mockCertificateRepository, mockTrustLinker);
		}
	}

	@Test
	public void trustLinkerRevocationFails() throws Exception {

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

		CertificateRepository mockCertificateRepository = EasyMock
				.createMock(CertificateRepository.class);
		TrustValidator trustValidator = new TrustValidator(
				mockCertificateRepository);

		List<X509Certificate> certificatePath = new LinkedList<X509Certificate>();
		certificatePath.add(certificate);
		certificatePath.add(rootCertificate);

		EasyMock.expect(mockCertificateRepository.isTrustPoint(rootCertificate))
				.andReturn(true);

		Date validationDate = new Date();

		TrustLinker mockTrustLinker = EasyMock.createMock(TrustLinker.class);
		EasyMock.expect(
				mockTrustLinker.hasTrustLink(EasyMock.eq(certificate),
						EasyMock.eq(rootCertificate),
						EasyMock.eq(validationDate),
						EasyMock.eq(trustValidator.getRevocationData()),
						EasyMock.anyObject(AlgorithmPolicy.class))).andThrow(
                new TrustLinkerResultException(
                        TrustLinkerResultReason.INVALID_REVOCATION_STATUS,
                        "revoked"));
		trustValidator.addTrustLinker(mockTrustLinker);

		EasyMock.replay(mockCertificateRepository, mockTrustLinker);

		try {
			trustValidator.isTrusted(certificatePath, validationDate);
			fail();
		} catch (TrustLinkerResultException e) {
			// expected
			assertEquals(TrustLinkerResultReason.INVALID_REVOCATION_STATUS,
					e.getReason());
			EasyMock.verify(mockCertificateRepository, mockTrustLinker);
		}
	}
}
