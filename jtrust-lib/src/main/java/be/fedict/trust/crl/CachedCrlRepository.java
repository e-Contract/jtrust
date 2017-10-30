/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
 * Copyright (C) 2014-2015 e-Contract.be BVBA.
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

package be.fedict.trust.crl;

import java.lang.ref.SoftReference;
import java.net.URI;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import be.fedict.trust.common.ServerNotAvailableException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;

/**
 * A cached CRL repository implementation. This CRL repository will cache CRLs
 * in memory. This implementation is thread-safe, as far as the passed
 * {@link CrlRepository} is also thread-safe of course.
 * 
 * @author Frank Cornelis
 */
public class CachedCrlRepository implements CrlRepository {

	private static final Log LOG = LogFactory.getLog(CachedCrlRepository.class);

	public static final int DEFAULT_CACHE_AGING_HOURS = 3;

	private final Map<URI, SoftReference<CacheEntry>> crlCache;

	private final CrlRepository crlRepository;

	private int cacheAgingHours;

	private static class CacheEntry {

		private final DateTime timestamp;
		private final X509CRL crl;

		public CacheEntry(X509CRL crl) {
			this.timestamp = new DateTime();
			this.crl = crl;
		}

		public DateTime getTimestamp() {
			return this.timestamp;
		}

		public X509CRL getCRL() {
			return this.crl;
		}
	}

	/**
	 * Main constructor.
	 * 
	 * @param crlRepository
	 *            the delegated CRL repository.
	 */
	public CachedCrlRepository(CrlRepository crlRepository) {
		this.crlRepository = crlRepository;
		this.crlCache = Collections
				.synchronizedMap(new HashMap<URI, SoftReference<CacheEntry>>());
		this.cacheAgingHours = DEFAULT_CACHE_AGING_HOURS;
	}

	@Override
	public X509CRL findCrl(URI crlUri, X509Certificate issuerCertificate, Date validationDate) throws ServerNotAvailableException {
		SoftReference<CacheEntry> cacheEntryRef = this.crlCache.get(crlUri);
		if (null == cacheEntryRef) {
			LOG.debug("no cache entry ref found: " + crlUri);
			return refreshCrl(crlUri, issuerCertificate, validationDate);
		}
		CacheEntry cacheEntry = cacheEntryRef.get();
		if (null == cacheEntry) {
			LOG.debug("cache entry garbage collected: " + crlUri);
			return refreshCrl(crlUri, issuerCertificate, validationDate);
		}
		X509CRL crl = cacheEntry.getCRL();
		if (validationDate.after(crl.getNextUpdate())) {
			LOG.debug("CRL no longer valid: " + crlUri);
			LOG.debug("validation date: " + validationDate);
			LOG.debug("CRL next update: " + crl.getNextUpdate());
			return refreshCrl(crlUri, issuerCertificate, validationDate);
		}
		/*
		 * The Belgian PKI the nextUpdate CRL extension indicates 7 days. The
		 * actual CRL refresh rate is every 3 hours. So it's a bit dangerous to
		 * only base the CRL cache refresh strategy on the nextUpdate field as
		 * indicated by the CRL.
		 */
		DateTime cacheMaturityDateTime = cacheEntry.getTimestamp().plusHours(
				this.cacheAgingHours);
		if (validationDate.after(cacheMaturityDateTime.toDate())) {
			LOG.debug("refreshing the CRL cache: " + crlUri);
			return refreshCrl(crlUri, issuerCertificate, validationDate);
		}
		LOG.debug("using cached CRL: " + crlUri);
		return crl;
	}

	private X509CRL refreshCrl(URI crlUri, X509Certificate issuerCertificate, Date validationDate) throws ServerNotAvailableException {
		X509CRL crl = this.crlRepository.findCrl(crlUri, issuerCertificate, validationDate);
		if (null == crl) {
			// we don't want to cache CRL retrieval errors
			this.crlCache.remove(crlUri);
			return null;
		}
		this.crlCache.put(crlUri, new SoftReference<>(new CacheEntry(crl)));
		return crl;
	}

	/**
	 * Gives back the CRL cache aging period in hours.
	 */
	public int getCacheAgingHours() {
		return this.cacheAgingHours;
	}

	/**
	 * Sets the CRL cache aging period in hours.
	 * 
	 * @param cacheAgingHours
	 *            the CRL cache aging period in hours.
	 */
	public void setCacheAgingHours(int cacheAgingHours) {
		this.cacheAgingHours = cacheAgingHours;
	}
}