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

package be.fedict.trust;

import java.net.URI;
import java.security.cert.X509CRL;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * A cached CRL repository implementation. This CRL repository will cache CRLs
 * in memory in case the nextUpdate is not yet reached.
 * 
 * @author fcorneli
 * 
 */
public class CachedCrlRepository implements CrlRepository {

	private static final Log LOG = LogFactory.getLog(CachedCrlRepository.class);

	private final Map<URI, X509CRL> crlCache;

	private final CrlRepository crlRepository;

	/**
	 * Main constructor.
	 * 
	 * @param crlRepository
	 *            the delegated CRL repository.
	 */
	public CachedCrlRepository(CrlRepository crlRepository) {
		this.crlRepository = crlRepository;
		this.crlCache = new HashMap<URI, X509CRL>();
	}

	public X509CRL findCrl(URI crlUri, Date validationDate) {
		X509CRL crl = this.crlCache.get(crlUri);
		if (null == crl) {
			return refreshCrl(crlUri, validationDate);
		}
		if (validationDate.after(crl.getNextUpdate())) {
			return refreshCrl(crlUri, validationDate);
		}
		LOG.debug("using cached CRL: " + crlUri);
		return crl;
	}

	private X509CRL refreshCrl(URI crlUri, Date validationDate) {
		X509CRL crl = this.crlRepository.findCrl(crlUri, validationDate);
		this.crlCache.put(crlUri, crl);
		return crl;
	}
}