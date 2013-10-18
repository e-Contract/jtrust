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

import java.net.URI;
import java.security.KeyPair;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.easymock.EasyMock;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;

import be.fedict.trust.crl.CachedCrlRepository;
import be.fedict.trust.crl.CrlRepository;

public class CachedCrlRepositoryTest {

	private X509CRL testCrl;
	private X509CRL testCrl2;
	private X509Certificate testCertificate;
	private KeyPair testKeyPair;

	@Before
	public void setup() throws Exception {

		this.testKeyPair = TrustTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		this.testCertificate = TrustTestUtils.generateCertificate(
				this.testKeyPair.getPublic(), "CN=Test", notBefore, notAfter,
				null, this.testKeyPair.getPrivate(), true, 0, null, null);
		DateTime thisUpdate = new DateTime();
		DateTime nextUpdate = thisUpdate.plusHours(1);
		this.testCrl = TrustTestUtils.generateCrl(
				this.testKeyPair.getPrivate(), this.testCertificate,
				thisUpdate, nextUpdate);
		this.testCrl2 = TrustTestUtils.generateCrl(
				this.testKeyPair.getPrivate(), this.testCertificate,
				thisUpdate, nextUpdate);
	}

	@Test
	public void emptyCache() throws Exception {
		// setup
		CrlRepository mockCrlRepository = EasyMock
				.createMock(CrlRepository.class);
		URI crlUri = new URI("urn:test:crl");
		Date validationDate = new Date();

		CachedCrlRepository testedInstance = new CachedCrlRepository(
				mockCrlRepository);

		// expectations
		EasyMock.expect(
				mockCrlRepository.findCrl(crlUri, this.testCertificate,
						validationDate)).andReturn(this.testCrl);

		// prepare
		EasyMock.replay(mockCrlRepository);

		// operate
		X509CRL resultCrl = testedInstance.findCrl(crlUri,
				this.testCertificate, validationDate);

		// verify
		EasyMock.verify(mockCrlRepository);
		assertEquals(testCrl, resultCrl);
	}

	@Test
	public void cacheBeingUsed() throws Exception {
		// setup
		CrlRepository mockCrlRepository = EasyMock
				.createMock(CrlRepository.class);
		URI crlUri = new URI("urn:test:crl");
		Date validationDate = new Date();

		CachedCrlRepository testedInstance = new CachedCrlRepository(
				mockCrlRepository);

		// expectations
		EasyMock.expect(
				mockCrlRepository.findCrl(crlUri, this.testCertificate,
						validationDate)).andReturn(this.testCrl);

		// prepare
		EasyMock.replay(mockCrlRepository);

		// operate
		X509CRL resultCrl = testedInstance.findCrl(crlUri,
				this.testCertificate, validationDate);
		X509CRL resultCrl2 = testedInstance.findCrl(crlUri,
				this.testCertificate, validationDate);

		// verify
		EasyMock.verify(mockCrlRepository);
		assertEquals(testCrl, resultCrl);
		assertEquals(testCrl, resultCrl2);
	}

	@Test
	public void cacheRefreshing() throws Exception {
		// setup
		DateTime thisUpdate = new DateTime();
		DateTime nextUpdate = thisUpdate.plusDays(7);
		DateTime nextNextUpdate = nextUpdate.plusDays(7);
		this.testCrl = TrustTestUtils.generateCrl(
				this.testKeyPair.getPrivate(), this.testCertificate,
				thisUpdate, nextUpdate);
		this.testCrl2 = TrustTestUtils.generateCrl(
				this.testKeyPair.getPrivate(), this.testCertificate,
				thisUpdate, nextUpdate);
		X509CRL testCrl3 = TrustTestUtils.generateCrl(
				this.testKeyPair.getPrivate(), this.testCertificate,
				nextUpdate, nextNextUpdate);

		CrlRepository mockCrlRepository = EasyMock
				.createMock(CrlRepository.class);
		URI crlUri = new URI("urn:test:crl");
		Date validationDate = new Date();
		Date validationDate2 = new DateTime(validationDate).plusHours(2)
				.toDate();
		Date validationDate3 = new DateTime(validationDate).plusHours(4)
				.toDate();
		Date validationDate4 = nextUpdate.plusHours(1).toDate();

		CachedCrlRepository testedInstance = new CachedCrlRepository(
				mockCrlRepository);
		testedInstance.setCacheAgingHours(3);

		// verify
		assertEquals(3, testedInstance.getCacheAgingHours());

		// expectations
		EasyMock.expect(
				mockCrlRepository.findCrl(crlUri, this.testCertificate,
						validationDate)).andReturn(this.testCrl);
		EasyMock.expect(
				mockCrlRepository.findCrl(crlUri, this.testCertificate,
						validationDate3)).andReturn(this.testCrl2);
		EasyMock.expect(
				mockCrlRepository.findCrl(crlUri, this.testCertificate,
						validationDate4)).andReturn(testCrl3);

		// prepare
		EasyMock.replay(mockCrlRepository);

		// operate
		X509CRL resultCrl = testedInstance.findCrl(crlUri,
				this.testCertificate, validationDate);
		X509CRL resultCrl2 = testedInstance.findCrl(crlUri,
				this.testCertificate, validationDate2);
		X509CRL resultCrl3 = testedInstance.findCrl(crlUri,
				this.testCertificate, validationDate3);
		X509CRL resultCrl4 = testedInstance.findCrl(crlUri,
				this.testCertificate, validationDate4);

		// verify
		EasyMock.verify(mockCrlRepository);
		assertEquals(this.testCrl, resultCrl);
		assertEquals(this.testCrl, resultCrl2);
		assertEquals(this.testCrl2, resultCrl3);
		assertEquals(testCrl3, resultCrl4);
	}

	@Test
	public void cacheExpiredCacheValidationDateRefreshing() throws Exception {
		// setup
		DateTime thisUpdate = new DateTime();
		DateTime nextUpdate = thisUpdate.plusDays(7);
		this.testCrl = TrustTestUtils.generateCrl(
				this.testKeyPair.getPrivate(), this.testCertificate,
				thisUpdate, nextUpdate);

		CrlRepository mockCrlRepository = EasyMock
				.createMock(CrlRepository.class);
		URI crlUri = new URI("urn:test:crl");
		Date validationDate = new Date();
		Date expiredCacheValidationDate = new DateTime(validationDate)
				.plusHours(4).toDate();

		CachedCrlRepository testedInstance = new CachedCrlRepository(
				mockCrlRepository);

		// expectations
		EasyMock.expect(
				mockCrlRepository.findCrl(crlUri, this.testCertificate,
						expiredCacheValidationDate)).andReturn(this.testCrl)
				.times(2);

		// prepare
		EasyMock.replay(mockCrlRepository);

		// operate
		X509CRL resultCrl = testedInstance.findCrl(crlUri,
				this.testCertificate, expiredCacheValidationDate);
		X509CRL resultCrl2 = testedInstance.findCrl(crlUri,
				this.testCertificate, expiredCacheValidationDate);

		// verify
		EasyMock.verify(mockCrlRepository);
		assertEquals(this.testCrl, resultCrl);
		assertEquals(this.testCrl, resultCrl2);
	}
}
