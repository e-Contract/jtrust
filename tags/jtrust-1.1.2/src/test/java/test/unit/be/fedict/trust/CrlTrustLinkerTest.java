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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.net.URI;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.easymock.EasyMock;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;

import test.unit.be.fedict.trust.TrustTestUtils.RevokedCertificate;
import be.fedict.trust.RevocationData;
import be.fedict.trust.TrustLinkerResult;
import be.fedict.trust.TrustLinkerResultReason;
import be.fedict.trust.crl.CrlRepository;
import be.fedict.trust.crl.CrlTrustLinker;

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
				rootCertificate, null, new RevocationData());

		EasyMock.verify(mockCrlRepository);
		assertNull(result);
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
				rootCertificate, rootKeyPair.getPrivate(), false, -1, ":");

		CrlRepository mockCrlRepository = EasyMock
				.createMock(CrlRepository.class);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		try {
			crlTrustLinker.hasTrustLink(certificate, rootCertificate, null,
					new RevocationData());
			fail();
		} catch (InvalidParameterException e) {
			// expected
			EasyMock.verify(mockCrlRepository);
		}
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
		X509Certificate certificate = TrustTestUtils
				.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
						notAfter, rootCertificate, rootKeyPair.getPrivate(),
						false, -1, "crl-uri");

		Date validationDate = new Date();

		CrlRepository mockCrlRepository = EasyMock
				.createMock(CrlRepository.class);
		EasyMock.expect(
				mockCrlRepository.findCrl(new URI("crl-uri"), rootCertificate,
						validationDate)).andReturn(null);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		TrustLinkerResult result = crlTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData());

		assertNull(result);
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
		X509Certificate certificate = TrustTestUtils
				.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
						notAfter, rootCertificate, rootKeyPair.getPrivate(),
						false, -1, "crl-uri");

		Date validationDate = notBefore.plusDays(1).toDate();

		CrlRepository mockCrlRepository = EasyMock
				.createMock(CrlRepository.class);
		X509CRL x509crl = TrustTestUtils.generateCrl(rootKeyPair.getPrivate(),
				rootCertificate, notBefore, notAfter);
		EasyMock.expect(
				mockCrlRepository.findCrl(new URI("crl-uri"), rootCertificate,
						validationDate)).andReturn(x509crl);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		TrustLinkerResult result = crlTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData());

		assertNotNull(result);
		assertTrue(result.isValid());
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
		X509Certificate certificate = TrustTestUtils
				.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
						notAfter, rootCertificate, rootKeyPair.getPrivate(),
						false, -1, "crl-uri");

		Date validationDate = notBefore.plusDays(1).toDate();

		CrlRepository mockCrlRepository = EasyMock
				.createMock(CrlRepository.class);
		X509CRL x509crl = TrustTestUtils.generateCrl(rootKeyPair.getPrivate(),
				rootCertificate, notBefore, notAfter);
		EasyMock.expect(
				mockCrlRepository.findCrl(new URI("crl-uri"), rootCertificate,
						validationDate)).andReturn(x509crl);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		TrustLinkerResult result = crlTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData());

		assertNull(result);
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
		X509Certificate certificate = TrustTestUtils
				.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
						notAfter, rootCertificate, rootKeyPair.getPrivate(),
						false, -1, "crl-uri");

		Date validationDate = notBefore.plusDays(1).toDate();

		CrlRepository mockCrlRepository = EasyMock
				.createMock(CrlRepository.class);
		X509CRL x509crl = TrustTestUtils.generateCrl(rootKeyPair.getPrivate(),
				rootCertificate, notBefore, notAfter);
		EasyMock.expect(
				mockCrlRepository.findCrl(new URI("crl-uri"), rootCertificate,
						validationDate)).andReturn(x509crl);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		TrustLinkerResult result = crlTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData());

		assertNull(result);
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
		X509Certificate certificate = TrustTestUtils
				.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
						notAfter, rootCertificate, rootKeyPair.getPrivate(),
						false, -1, "crl-uri");

		Date validationDate = notBefore.plusDays(1).toDate();

		CrlRepository mockCrlRepository = EasyMock
				.createMock(CrlRepository.class);
		X509CRL x509crl = TrustTestUtils.generateCrl(rootKeyPair.getPrivate(),
				rootCertificate, notBefore.minusMonths(2),
				notAfter.minusMonths(2));
		EasyMock.expect(
				mockCrlRepository.findCrl(new URI("crl-uri"), rootCertificate,
						validationDate)).andReturn(x509crl);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		TrustLinkerResult result = crlTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData());

		assertNull(result);
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
		X509Certificate certificate = TrustTestUtils
				.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
						notAfter, rootCertificate, rootKeyPair.getPrivate(),
						false, -1, "crl-uri");

		Date validationDate = notBefore.plusDays(1).toDate();

		CrlRepository mockCrlRepository = EasyMock
				.createMock(CrlRepository.class);
		X509CRL x509crl = TrustTestUtils.generateCrl(rootKeyPair.getPrivate(),
				certificate, notBefore, notAfter);
		EasyMock.expect(
				mockCrlRepository.findCrl(new URI("crl-uri"), rootCertificate,
						validationDate)).andReturn(x509crl);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		TrustLinkerResult result = crlTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData());

		assertNull(result);
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
		X509Certificate certificate = TrustTestUtils
				.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
						notAfter, rootCertificate, rootKeyPair.getPrivate(),
						false, -1, "crl-uri");

		Date validationDate = notBefore.plusDays(1).toDate();

		CrlRepository mockCrlRepository = EasyMock
				.createMock(CrlRepository.class);
		X509CRL x509crl = TrustTestUtils.generateCrl(keyPair.getPrivate(),
				rootCertificate, notBefore, notAfter);
		EasyMock.expect(
				mockCrlRepository.findCrl(new URI("crl-uri"), rootCertificate,
						validationDate)).andReturn(x509crl);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		TrustLinkerResult result = crlTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData());

		assertNull(result);
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
		X509Certificate certificate = TrustTestUtils
				.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
						notAfter, rootCertificate, rootKeyPair.getPrivate(),
						false, -1, "crl-uri");

		CrlRepository mockCrlRepository = EasyMock
				.createMock(CrlRepository.class);
		X509CRL x509crl = TrustTestUtils.generateCrl(rootKeyPair.getPrivate(),
				rootCertificate, notBefore.plusMonths(2),
				notAfter.plusMonths(2));
		EasyMock.expect(
				mockCrlRepository.findCrl(new URI("crl-uri"), rootCertificate,
						validationDate)).andReturn(x509crl);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		TrustLinkerResult result = crlTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData());

		assertNull(result);
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
		X509Certificate certificate = TrustTestUtils
				.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
						notAfter, rootCertificate, rootKeyPair.getPrivate(),
						false, -1, "crl-uri");

		Date validationDate = notBefore.plusDays(1).toDate();

		CrlRepository mockCrlRepository = EasyMock
				.createMock(CrlRepository.class);
		X509CRL x509crl = TrustTestUtils.generateCrl(rootKeyPair.getPrivate(),
				rootCertificate, notBefore, notAfter,
				certificate.getSerialNumber());
		EasyMock.expect(
				mockCrlRepository.findCrl(new URI("crl-uri"), rootCertificate,
						validationDate)).andReturn(x509crl);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		TrustLinkerResult result = crlTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData());

		assertNotNull(result);
		assertFalse(result.isValid());
		EasyMock.verify(mockCrlRepository);
	}

	@Test
	public void deltaCrls() throws Exception {

		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter, true, 0, null, new KeyUsage(
								KeyUsage.cRLSign));

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils
				.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
						notAfter, rootCertificate, rootKeyPair.getPrivate(),
						false, -1, "crl-uri");

		Date validationDate = notBefore.plusDays(1).toDate();

		CrlRepository mockCrlRepository = EasyMock
				.createMock(CrlRepository.class);
		List<String> deltaCrlUris = new LinkedList<String>();
		deltaCrlUris.add("delta-crl-uri-1");
		deltaCrlUris.add("delta-crl-uri-2");
		X509CRL x509crl = TrustTestUtils.generateCrl(rootKeyPair.getPrivate(),
				rootCertificate, notBefore, notAfter, deltaCrlUris,
				new LinkedList<RevokedCertificate>());
		X509CRL deltaX509crl0 = TrustTestUtils.generateCrl(
				rootKeyPair.getPrivate(), rootCertificate, notBefore, notAfter,
				null, true, new LinkedList<RevokedCertificate>());
		X509CRL deltaX509crl1 = TrustTestUtils.generateCrl(rootKeyPair
				.getPrivate(), rootCertificate, notBefore, notAfter, null,
				true, Collections.singletonList(new RevokedCertificate(
						certificate.getSerialNumber(), notBefore)));

		EasyMock.expect(
				mockCrlRepository.findCrl(new URI("crl-uri"), rootCertificate,
						validationDate)).andReturn(x509crl);
		EasyMock.expect(
				mockCrlRepository.findCrl(new URI(deltaCrlUris.get(0)),
						rootCertificate, validationDate)).andReturn(
				deltaX509crl0);
		EasyMock.expect(
				mockCrlRepository.findCrl(new URI(deltaCrlUris.get(1)),
						rootCertificate, validationDate)).andReturn(
				deltaX509crl1);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		TrustLinkerResult result = crlTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData());

		assertNotNull(result);
		assertFalse(result.isValid());
		EasyMock.verify(mockCrlRepository);
	}

	@Test
	public void deltaCrlEmptyDeltaRevokedInBase() throws Exception {

		KeyPair rootKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = TrustTestUtils
				.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
						notBefore, notAfter, true, 0, null, new KeyUsage(
								KeyUsage.cRLSign));

		KeyPair keyPair = TrustTestUtils.generateKeyPair();
		X509Certificate certificate = TrustTestUtils
				.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
						notAfter, rootCertificate, rootKeyPair.getPrivate(),
						false, -1, "crl-uri");

		Date validationDate = notBefore.plusDays(1).toDate();

		CrlRepository mockCrlRepository = EasyMock
				.createMock(CrlRepository.class);
		List<String> deltaCrlUris = new LinkedList<String>();
		deltaCrlUris.add("delta-crl-uri-1");
		X509CRL x509crl = TrustTestUtils.generateCrl(rootKeyPair.getPrivate(),
				rootCertificate, notBefore, notAfter, deltaCrlUris, Collections
						.singletonList(new RevokedCertificate(certificate
								.getSerialNumber(), notBefore)));
		X509CRL deltaX509crl1 = TrustTestUtils.generateCrl(
				rootKeyPair.getPrivate(), rootCertificate, notBefore, notAfter,
				null, true, new LinkedList<RevokedCertificate>());

		EasyMock.expect(
				mockCrlRepository.findCrl(new URI("crl-uri"), rootCertificate,
						validationDate)).andReturn(x509crl);
		EasyMock.expect(
				mockCrlRepository.findCrl(new URI(deltaCrlUris.get(0)),
						rootCertificate, validationDate)).andReturn(
				deltaX509crl1);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		TrustLinkerResult result = crlTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData());

		assertNotNull(result);
		assertFalse(result.isValid());
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
		X509Certificate certificate = TrustTestUtils
				.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
						notAfter, rootCertificate, rootKeyPair.getPrivate(),
						false, -1, "crl-uri");

		Date validationDate = notBefore.plusDays(1).toDate();

		CrlRepository mockCrlRepository = EasyMock
				.createMock(CrlRepository.class);
		X509CRL x509crl = TrustTestUtils.generateCrl(rootKeyPair.getPrivate(),
				rootCertificate, notBefore, notAfter, "MD5withRSA",
				certificate.getSerialNumber());
		EasyMock.expect(
				mockCrlRepository.findCrl(new URI("crl-uri"), rootCertificate,
						validationDate)).andReturn(x509crl);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		TrustLinkerResult result = crlTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData());

		assertNotNull(result);
		assertFalse(result.isValid());
		assertEquals(TrustLinkerResultReason.INVALID_SIGNATURE,
				result.getReason());
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
		X509Certificate certificate = TrustTestUtils
				.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
						notAfter, rootCertificate, rootKeyPair.getPrivate(),
						false, -1, "crl-uri");

		Date validationDate = notBefore.plusDays(1).toDate();

		CrlRepository mockCrlRepository = EasyMock
				.createMock(CrlRepository.class);
		X509CRL x509crl = TrustTestUtils.generateCrl(rootKeyPair.getPrivate(),
				rootCertificate, notBefore, notAfter, Collections
						.singletonList(new TrustTestUtils.RevokedCertificate(
								certificate.getSerialNumber(), notBefore
										.plusDays(2))));
		EasyMock.expect(
				mockCrlRepository.findCrl(new URI("crl-uri"), rootCertificate,
						validationDate)).andReturn(x509crl);

		EasyMock.replay(mockCrlRepository);

		CrlTrustLinker crlTrustLinker = new CrlTrustLinker(mockCrlRepository);

		TrustLinkerResult result = crlTrustLinker.hasTrustLink(certificate,
				rootCertificate, validationDate, new RevocationData());

		assertNotNull(result);
		assertTrue(result.isValid());
		EasyMock.verify(mockCrlRepository);
	}
}
