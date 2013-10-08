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

import be.fedict.trust.revocation.RevocationData;
import be.fedict.trust.policy.DefaultAlgorithmPolicy;
import be.fedict.trust.*;
import be.fedict.trust.crl.CrlRepository;
import be.fedict.trust.crl.CrlTrustLinker;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.easymock.EasyMock;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;

import java.net.URI;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;

import static org.junit.Assert.*;

public class CrlTrustLinkerTest {

	@Before
	public void setUp() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void noCrlUriInCertificate() throws Exception {
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

		CrlRepository mockCrlRepository = EasyMock
				.createMock(CrlRepository.class);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);
		TrustLinkerResult result = crlTrustLinker.hasTrustLink(certificate,
				rootCertificate, null, new RevocationData(),
				new DefaultAlgorithmPolicy());

		EasyMock.verify(mockCrlRepository);
		assertEquals(TrustLinkerResult.UNDECIDED, result);
	}

	@Test
	public void invalidCrlUriInCertificate() throws Exception {
		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter, true, 0);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1, "foobar");

		CrlRepository mockCrlRepository = EasyMock
				.createMock(CrlRepository.class);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		TrustLinkerResult result = crlTrustLinker.hasTrustLink(certificate,
				rootCertificate, null, new RevocationData(),
				new DefaultAlgorithmPolicy());
        assertEquals(TrustLinkerResult.UNDECIDED, result);
	}

	@Test
	public void noEntryInCrlRepository() throws Exception {
		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter, true, 0);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1,
				"http://crl-uri");

		Date validationDate = new Date();

		CrlRepository mockCrlRepository = EasyMock
				.createMock(CrlRepository.class);
		EasyMock.expect(
				mockCrlRepository.findCrl(new URI("http://crl-uri"),
						rootCertificate, validationDate)).andReturn(null);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		TrustLinkerResult result = crlTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData(),
				new DefaultAlgorithmPolicy());

        assertEquals(TrustLinkerResult.UNDECIDED, result);
		EasyMock.verify(mockCrlRepository);
	}

	@Test
	public void emptyCrlPasses() throws Exception {
		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter, true, 0, null, new KeyUsage(
								KeyUsage.cRLSign));

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1,
				"http://crl-uri");

		Date validationDate = notBefore.plusDays(1).toDate();

		CrlRepository mockCrlRepository = EasyMock
				.createMock(CrlRepository.class);
		X509CRL x509crl = TrustTestUtils.generateCrl(rootKeyPair.getPrivate(),
				rootCertificate, notBefore, notAfter);
		EasyMock.expect(
				mockCrlRepository.findCrl(new URI("http://crl-uri"),
						rootCertificate, validationDate)).andReturn(x509crl);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		TrustLinkerResult result = crlTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData(),
				new DefaultAlgorithmPolicy());

		assertEquals(TrustLinkerResult.TRUSTED, result);
		EasyMock.verify(mockCrlRepository);
	}

	@Test
	public void crlMissingKeyUsage() throws Exception {
		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter, true, 0);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1,
				"https://crl-uri");

		Date validationDate = notBefore.plusDays(1).toDate();

		CrlRepository mockCrlRepository = EasyMock
				.createMock(CrlRepository.class);
		X509CRL x509crl = TrustTestUtils.generateCrl(rootKeyPair.getPrivate(),
				rootCertificate, notBefore, notAfter);
		EasyMock.expect(
				mockCrlRepository.findCrl(new URI("https://crl-uri"),
						rootCertificate, validationDate)).andReturn(x509crl);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		TrustLinkerResult result = crlTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData(),
				new DefaultAlgorithmPolicy());

        assertEquals(TrustLinkerResult.TRUSTED, result);
		EasyMock.verify(mockCrlRepository);
	}

	@Test
	public void crlMissingCRLSignKeyUsage() throws Exception {
		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter, true, 0, null, new KeyUsage(
								KeyUsage.dataEncipherment));

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1,
				"https://crl-uri");

		Date validationDate = notBefore.plusDays(1).toDate();

		CrlRepository mockCrlRepository = EasyMock
				.createMock(CrlRepository.class);
		X509CRL x509crl = TrustTestUtils.generateCrl(rootKeyPair.getPrivate(),
				rootCertificate, notBefore, notAfter);
		EasyMock.expect(
				mockCrlRepository.findCrl(new URI("https://crl-uri"),
						rootCertificate, validationDate)).andReturn(x509crl);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		TrustLinkerResult result = crlTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData(),
				new DefaultAlgorithmPolicy());

        assertEquals(TrustLinkerResult.UNDECIDED, result);
		EasyMock.verify(mockCrlRepository);
	}

	@Test
	public void oldCrl() throws Exception {
		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter, true, 0);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1,
				"http://crl-uri");

		Date validationDate = notBefore.plusDays(1).toDate();

		CrlRepository mockCrlRepository = EasyMock
				.createMock(CrlRepository.class);
		X509CRL x509crl = TrustTestUtils.generateCrl(rootKeyPair.getPrivate(),
				rootCertificate, notBefore.minusMonths(2),
				notAfter.minusMonths(2));
		EasyMock.expect(
				mockCrlRepository.findCrl(new URI("http://crl-uri"),
						rootCertificate, validationDate)).andReturn(x509crl);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		TrustLinkerResult result = crlTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData(),
				new DefaultAlgorithmPolicy());

        assertEquals(TrustLinkerResult.UNDECIDED, result);
		EasyMock.verify(mockCrlRepository);
	}

	@Test
	public void crlNotIssuedByRoot() throws Exception {
		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter, true, 0);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1,
				"http://crl-uri");

		Date validationDate = notBefore.plusDays(1).toDate();

		CrlRepository mockCrlRepository = EasyMock
				.createMock(CrlRepository.class);
		X509CRL x509crl = TrustTestUtils.generateCrl(rootKeyPair.getPrivate(),
				certificate, notBefore, notAfter);
		EasyMock.expect(
				mockCrlRepository.findCrl(new URI("http://crl-uri"),
						rootCertificate, validationDate)).andReturn(x509crl);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		TrustLinkerResult result = crlTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData(),
				new DefaultAlgorithmPolicy());

        assertEquals(TrustLinkerResult.UNDECIDED, result);
		EasyMock.verify(mockCrlRepository);
	}

	@Test
	public void crlNotSignedByRoot() throws Exception {
		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter, true, 0);

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1,
				"http://crl-uri");

		Date validationDate = notBefore.plusDays(1).toDate();

		CrlRepository mockCrlRepository = EasyMock
				.createMock(CrlRepository.class);
		X509CRL x509crl = TrustTestUtils.generateCrl(keyPair.getPrivate(),
				rootCertificate, notBefore, notAfter);
		EasyMock.expect(
				mockCrlRepository.findCrl(new URI("http://crl-uri"),
						rootCertificate, validationDate)).andReturn(x509crl);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		TrustLinkerResult result = crlTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData(),
				new DefaultAlgorithmPolicy());

        assertEquals(TrustLinkerResult.UNDECIDED, result);
		EasyMock.verify(mockCrlRepository);
	}

	@Test
	public void tooFreshCrl() throws Exception {
		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter, true, 0);

		Date validationDate = notBefore.plusDays(1).toDate();

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1,
				"https://crl-uri");

		CrlRepository mockCrlRepository = EasyMock
				.createMock(CrlRepository.class);
		X509CRL x509crl = TrustTestUtils.generateCrl(rootKeyPair.getPrivate(),
				rootCertificate, notBefore.plusMonths(2),
				notAfter.plusMonths(2));
		EasyMock.expect(
				mockCrlRepository.findCrl(new URI("https://crl-uri"),
						rootCertificate, validationDate)).andReturn(x509crl);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		TrustLinkerResult result = crlTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData(),
				new DefaultAlgorithmPolicy());

        assertEquals(TrustLinkerResult.UNDECIDED, result);
		EasyMock.verify(mockCrlRepository);
	}

	@Test
	public void revokedCertificate() throws Exception {
		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter, true, 0, null, new KeyUsage(
								KeyUsage.cRLSign));

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1,
				"http://crl-uri");

		Date validationDate = notBefore.plusDays(1).toDate();

		CrlRepository mockCrlRepository = EasyMock
				.createMock(CrlRepository.class);
		X509CRL x509crl = TrustTestUtils.generateCrl(rootKeyPair.getPrivate(),
				rootCertificate, notBefore, notAfter,
				certificate.getSerialNumber());
		EasyMock.expect(
				mockCrlRepository.findCrl(new URI("http://crl-uri"),
						rootCertificate, validationDate)).andReturn(x509crl);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		try {
            crlTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData(),
				new DefaultAlgorithmPolicy());
            fail();
        }
        catch (TrustLinkerResultException e) {
            assertEquals(TrustLinkerResultReason.INVALID_REVOCATION_STATUS, e.getReason());
        }

		EasyMock.verify(mockCrlRepository);
	}

	@Test
	public void crlMD5Signature() throws Exception {
		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter, true, 0, null, new KeyUsage(
								KeyUsage.cRLSign));

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1,
				"https://crl-uri");

		Date validationDate = notBefore.plusDays(1).toDate();

		CrlRepository mockCrlRepository = EasyMock
				.createMock(CrlRepository.class);
		X509CRL x509crl = TrustTestUtils.generateCrl(rootKeyPair.getPrivate(),
				rootCertificate, notBefore, notAfter, "MD5withRSA",
				certificate.getSerialNumber());
		EasyMock.expect(
				mockCrlRepository.findCrl(new URI("https://crl-uri"),
						rootCertificate, validationDate)).andReturn(x509crl);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		try {
            crlTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData(),
				new DefaultAlgorithmPolicy());
            fail();
        } catch (TrustLinkerResultException e) {
            assertEquals(TrustLinkerResultReason.INVALID_ALGORITHM, e.getReason());
        }

		EasyMock.verify(mockCrlRepository);
	}

	@Test
	public void futureRevokedCertificate() throws Exception {
		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter, true, 0, null, new KeyUsage(
								KeyUsage.cRLSign));

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate(), false, -1,
				"http://crl-uri");

		Date validationDate = notBefore.plusDays(1).toDate();

		CrlRepository mockCrlRepository = EasyMock
				.createMock(CrlRepository.class);
		X509CRL x509crl = TrustTestUtils.generateCrl(rootKeyPair.getPrivate(),
				rootCertificate, notBefore, notAfter, Collections
						.singletonList(new TrustTestUtils.RevokedCertificate(
								certificate.getSerialNumber(), notBefore
										.plusDays(2))));
		EasyMock.expect(
				mockCrlRepository.findCrl(new URI("http://crl-uri"),
						rootCertificate, validationDate)).andReturn(x509crl);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		TrustLinkerResult result = crlTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData(),
				new DefaultAlgorithmPolicy());

		assertEquals(TrustLinkerResult.TRUSTED, result);
		EasyMock.verify(mockCrlRepository);
	}
}
