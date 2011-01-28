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

package be.fedict.trust.crl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;

import java.lang.ref.SoftReference;
import java.net.URI;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * A cached CRL repository implementation. This CRL repository will cache CRLs
 * in memory.
 * 
 * @author Frank Cornelis
 */
public class CachedCrlRepository implements CrlRepository {

	private static final Log LOG = LogFactory.getLog(CachedCrlRepository.class);

	public static final int DEFAULT_CACHE_AGING_HOURS = 3;

	private final Map<URI, SoftReference<X509CRL>> crlCache;

	private final CrlRepository crlRepository;

	private int cacheAgingHours;

	/**
	 * Main constructor.
	 * 
	 * @param crlRepository
	 *            the delegated CRL repository.
	 */
	public CachedCrlRepository(CrlRepository crlRepository) {
		this.crlRepository = crlRepository;
		this.crlCache = Collections
				.synchronizedMap(new HashMap<URI, SoftReference<X509CRL>>());
		this.cacheAgingHours = DEFAULT_CACHE_AGING_HOURS;
	}

	public X509CRL findCrl(URI crlUri, X509Certificate issuerCertificate,
			Date validationDate) {

		SoftReference<X509CRL> crlRef = this.crlCache.get(crlUri);
		if (null == crlRef) {
			LOG.debug("no CRL entry found: " + crlUri);
			return refreshCrl(crlUri, issuerCertificate, validationDate);
		}
		X509CRL crl = crlRef.get();
		if (null == crl) {
			LOG.debug("CRL garbage collected: " + crlUri);
			return refreshCrl(crlUri, issuerCertificate, validationDate);
		}
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
		Date thisUpdate = crl.getThisUpdate();
		DateTime cacheMaturityDateTime = new DateTime(thisUpdate)
				.plusHours(this.cacheAgingHours);
		if (validationDate.after(cacheMaturityDateTime.toDate())) {
			LOG.debug("refreshing the CRL cache: " + crlUri);
			return refreshCrl(crlUri, issuerCertificate, validationDate);
		}
		LOG.debug("using cached CRL: " + crlUri);
		return crl;
	}

	private X509CRL refreshCrl(URI crlUri, X509Certificate issuerCertificate,
			Date validationDate) {
		X509CRL crl = this.crlRepository.findCrl(crlUri, issuerCertificate,
				validationDate);
		this.crlCache.put(crlUri, new SoftReference<X509CRL>(crl));
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