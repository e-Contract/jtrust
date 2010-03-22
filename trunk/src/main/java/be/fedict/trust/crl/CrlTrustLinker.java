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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidParameterException;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extensions;

import be.fedict.trust.CRLRevocationData;
import be.fedict.trust.RevocationData;
import be.fedict.trust.TrustLinker;
import be.fedict.trust.TrustLinkerResult;
import be.fedict.trust.TrustLinkerResultReason;

/**
 * Trust linker implementation based on CRL revocation information.
 * 
 * @author Frank Cornelis
 * 
 */
public class CrlTrustLinker implements TrustLinker {

	private static final Log LOG = LogFactory.getLog(CrlTrustLinker.class);

	private final CrlRepository crlRepository;

	/**
	 * Main constructor.
	 * 
	 * @param crlRepository
	 *            the CRL repository used by this CRL trust linker.
	 */
	public CrlTrustLinker(CrlRepository crlRepository) {
		this.crlRepository = crlRepository;
	}

	public TrustLinkerResult hasTrustLink(X509Certificate childCertificate,
			X509Certificate certificate, Date validationDate,
			RevocationData revocationData) {
		URI crlUri = getCrlUri(childCertificate);
		if (null == crlUri) {
			LOG.debug("no CRL uri in certificate");
			return null;
		}
		LOG.debug("CRL URI: " + crlUri);
		X509CRL x509crl = this.crlRepository.findCrl(crlUri, certificate,
				validationDate);
		if (null == x509crl) {
			return null;
		}
		boolean crlIntegrityResult = checkCrlIntegrity(x509crl, certificate,
				validationDate);
		if (false == crlIntegrityResult) {
			return null;
		}

		// fill up revocation data if not null with this valid CRL
		if (null != revocationData) {
			try {
				revocationData.getCrlRevocationData().add(
						new CRLRevocationData(x509crl.getEncoded()));
			} catch (CRLException e) {
				LOG.error("CRLException: " + e.getMessage(), e);
				throw new RuntimeException("CRLException : " + e.getMessage(),
						e);
			}
		}

		X509CRLEntry crlEntry = x509crl.getRevokedCertificate(childCertificate
				.getSerialNumber());
		if (null == crlEntry) {
			LOG.debug("CRL OK for: "
					+ childCertificate.getSubjectX500Principal());
			return new TrustLinkerResult(true);
		}
		if (crlEntry.getRevocationDate().after(validationDate)) {
			LOG.debug("CRL OK for: "
					+ childCertificate.getSubjectX500Principal() + " at "
					+ validationDate);
			return new TrustLinkerResult(true);
		}
		// TODO: delta CRL
		return new TrustLinkerResult(false,
				TrustLinkerResultReason.INVALID_REVOCATION_STATUS,
				"certificate revoked by CRL=" + crlEntry.getSerialNumber());
	}

	public static boolean checkCrlIntegrity(X509CRL x509crl,
			X509Certificate issuerCertificate, Date validationDate) {
		if (false == x509crl.getIssuerX500Principal().equals(
				issuerCertificate.getSubjectX500Principal())) {
			return false;
		}
		try {
			x509crl.verify(issuerCertificate.getPublicKey());
		} catch (Exception e) {
			return false;
		}
		Date thisUpdate = x509crl.getThisUpdate();
		LOG.debug("validation date: " + validationDate);
		LOG.debug("CRL this update: " + thisUpdate);
		if (thisUpdate.after(validationDate)) {
			LOG.warn("CRL too young");
			return false;
		}
		LOG.debug("CRL next update: " + x509crl.getNextUpdate());
		if (validationDate.after(x509crl.getNextUpdate())) {
			LOG.debug("CRL too old");
			return false;
		}
		return true;
	}

	public static URI getCrlUri(X509Certificate certificate) {
		byte[] crlDistributionPointsValue = certificate
				.getExtensionValue(X509Extensions.CRLDistributionPoints.getId());
		if (null == crlDistributionPointsValue) {
			return null;
		}
		ASN1Sequence seq;
		try {
			DEROctetString oct;
			oct = (DEROctetString) (new ASN1InputStream(
					new ByteArrayInputStream(crlDistributionPointsValue))
					.readObject());
			seq = (ASN1Sequence) new ASN1InputStream(oct.getOctets())
					.readObject();
		} catch (IOException e) {
			throw new RuntimeException("IO error: " + e.getMessage(), e);
		}
		CRLDistPoint distPoint = CRLDistPoint.getInstance(seq);
		DistributionPoint[] distributionPoints = distPoint
				.getDistributionPoints();
		for (DistributionPoint distributionPoint : distributionPoints) {
			DistributionPointName distributionPointName = distributionPoint
					.getDistributionPoint();
			if (DistributionPointName.FULL_NAME != distributionPointName
					.getType()) {
				continue;
			}
			GeneralNames generalNames = (GeneralNames) distributionPointName
					.getName();
			GeneralName[] names = generalNames.getNames();
			for (GeneralName name : names) {
				if (name.getTagNo() != GeneralName.uniformResourceIdentifier) {
					LOG.debug("not a uniform resource identifier");
					continue;
				}
				DERIA5String derStr = DERIA5String.getInstance(name
						.getDERObject());
				String str = derStr.getString();
				URI uri = toURI(str);
				return uri;
			}
		}
		return null;
	}

	private static URI toURI(String str) {
		try {
			URI uri = new URI(str);
			return uri;
		} catch (URISyntaxException e) {
			throw new InvalidParameterException("CRL URI syntax error: "
					+ e.getMessage());
		}
	}
}
