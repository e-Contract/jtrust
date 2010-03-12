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

import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.easymock.EasyMock;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;

import be.fedict.trust.CertificateConstraint;
import be.fedict.trust.CertificateRepository;
import be.fedict.trust.TrustLinker;
import be.fedict.trust.TrustLinkerResult;
import be.fedict.trust.TrustValidator;

public class TrustValidatorTest {

	@Before
	public void setUp() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void createInstance() throws Exception {
		new TrustValidator(null);
	}

	@Test
	public void emptyCertPathFails() throws Exception {
		TrustValidator trustValidator = new TrustValidator(null);

		TrustLinkerResult result = trustValidator
				.isTrusted(new LinkedList<X509Certificate>());
		assertFalse(result.isValid());
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

		TrustLinkerResult result = trustValidator.isTrusted(certificatePath);
		assertFalse(result.isValid());
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

		TrustLinkerResult result = trustValidator.isTrusted(certificatePath);
		assertFalse(result.isValid());
		EasyMock.verify(mockCertificateRepository);
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

		TrustLinkerResult result = trustValidator.isTrusted(certificatePath);
		assertFalse(result.isValid());
		EasyMock.verify(mockCertificateRepository);
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

		TrustLinkerResult result = trustValidator.isTrusted(certificatePath);
		assertFalse(result.isValid());
		EasyMock.verify(mockCertificateRepository);
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

		EasyMock
				.expect(mockCertificateRepository.isTrustPoint(rootCertificate))
				.andStubReturn(true);

		EasyMock.replay(mockCertificateRepository);

		TrustLinkerResult result = trustValidator.isTrusted(certificatePath);
		assertFalse(result.isValid());
		EasyMock.verify(mockCertificateRepository);
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

		EasyMock
				.expect(mockCertificateRepository.isTrustPoint(rootCertificate))
				.andReturn(true);

		Date validationDate = new Date();

		TrustLinker mockTrustLinker = EasyMock.createMock(TrustLinker.class);
		EasyMock.expect(
				mockTrustLinker.hasTrustLink(certificate, rootCertificate,
						validationDate, trustValidator.getRevocationData()))
				.andReturn(new TrustLinkerResult(true));
		trustValidator.addTrustLinker(mockTrustLinker);

		EasyMock.replay(mockCertificateRepository, mockTrustLinker);

		trustValidator.isTrusted(certificatePath, validationDate);

		EasyMock.verify(mockCertificateRepository, mockTrustLinker);
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

		EasyMock
				.expect(mockCertificateRepository.isTrustPoint(rootCertificate))
				.andReturn(true);

		Date validationDate = new Date();

		TrustLinker mockTrustLinker = EasyMock.createMock(TrustLinker.class);
		EasyMock.expect(
				mockTrustLinker.hasTrustLink(certificate, rootCertificate,
						validationDate, trustValidator.getRevocationData()))
				.andReturn(new TrustLinkerResult(true));
		trustValidator.addTrustLinker(mockTrustLinker);

		CertificateConstraint mockCertificateConstraint = EasyMock
				.createMock(CertificateConstraint.class);
		EasyMock.expect(mockCertificateConstraint.check(certificate))
				.andReturn(true);
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

		EasyMock
				.expect(mockCertificateRepository.isTrustPoint(rootCertificate))
				.andReturn(true);

		Date validationDate = new Date();

		TrustLinker mockTrustLinker = EasyMock.createMock(TrustLinker.class);
		EasyMock.expect(
				mockTrustLinker.hasTrustLink(certificate, rootCertificate,
						validationDate, trustValidator.getRevocationData()))
				.andReturn(new TrustLinkerResult(true));
		trustValidator.addTrustLinker(mockTrustLinker);

		CertificateConstraint mockCertificateConstraint = EasyMock
				.createMock(CertificateConstraint.class);
		EasyMock.expect(mockCertificateConstraint.check(certificate))
				.andReturn(false);
		trustValidator.addCertificateConstrain(mockCertificateConstraint);

		EasyMock.replay(mockCertificateRepository, mockCertificateConstraint,
				mockTrustLinker);

		TrustLinkerResult result = trustValidator.isTrusted(certificatePath,
				validationDate);
		assertFalse(result.isValid());
		EasyMock.verify(mockCertificateRepository, mockCertificateConstraint,
				mockTrustLinker);

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

		EasyMock
				.expect(mockCertificateRepository.isTrustPoint(rootCertificate))
				.andReturn(true);

		Date validationDate = new Date();

		TrustLinker mockTrustLinker = EasyMock.createMock(TrustLinker.class);
		EasyMock.expect(
				mockTrustLinker.hasTrustLink(interCertificate, rootCertificate,
						validationDate, trustValidator.getRevocationData()))
				.andReturn(new TrustLinkerResult(true));
		EasyMock.expect(
				mockTrustLinker.hasTrustLink(certificate, interCertificate,
						validationDate, trustValidator.getRevocationData()))
				.andReturn(new TrustLinkerResult(true));
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

		EasyMock
				.expect(mockCertificateRepository.isTrustPoint(rootCertificate))
				.andReturn(true);

		Date validationDate = new Date();

		TrustLinker mockTrustLinker = EasyMock.createMock(TrustLinker.class);
		EasyMock.expect(
				mockTrustLinker.hasTrustLink(certificate, rootCertificate,
						validationDate, trustValidator.getRevocationData()))
				.andReturn(new TrustLinkerResult(false));
		trustValidator.addTrustLinker(mockTrustLinker);

		EasyMock.replay(mockCertificateRepository, mockTrustLinker);

		TrustLinkerResult result = trustValidator.isTrusted(certificatePath,
				validationDate);
		assertFalse(result.isValid());
		EasyMock.verify(mockCertificateRepository, mockTrustLinker);
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

		EasyMock
				.expect(mockCertificateRepository.isTrustPoint(rootCertificate))
				.andReturn(true);

		Date validationDate = new Date();

		TrustLinker mockTrustLinker = EasyMock.createMock(TrustLinker.class);
		EasyMock.expect(
				mockTrustLinker.hasTrustLink(certificate, rootCertificate,
						validationDate, trustValidator.getRevocationData()))
				.andReturn(new TrustLinkerResult(true));
		trustValidator.addTrustLinker(mockTrustLinker);

		TrustLinker mockTrustLinker2 = EasyMock.createMock(TrustLinker.class);
		EasyMock.expect(
				mockTrustLinker2.hasTrustLink(certificate, rootCertificate,
						validationDate, trustValidator.getRevocationData()))
				.andReturn(new TrustLinkerResult(false));
		trustValidator.addTrustLinker(mockTrustLinker2);

		EasyMock.replay(mockCertificateRepository, mockTrustLinker,
				mockTrustLinker2);

		TrustLinkerResult result = trustValidator.isTrusted(certificatePath,
				validationDate);
		assertFalse(result.isValid());
		EasyMock.verify(mockCertificateRepository, mockTrustLinker,
				mockTrustLinker2);
	}

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

		TrustLinker mockTrustLinker = EasyMock.createMock(TrustLinker.class);
		EasyMock.expect(
				mockTrustLinker.hasTrustLink(certificate, rootCertificate,
						null, trustValidator.getRevocationData())).andReturn(
				null);
		trustValidator.addTrustLinker(mockTrustLinker);

		EasyMock.replay(mockCertificateRepository, mockTrustLinker);

		TrustLinkerResult result = trustValidator.isTrusted(certificatePath);
		assertFalse(result.isValid());
		EasyMock.verify(mockCertificateRepository, mockTrustLinker);
	}
}
