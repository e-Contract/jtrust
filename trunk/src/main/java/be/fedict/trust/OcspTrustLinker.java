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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidParameterException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.SingleResp;

public class OcspTrustLinker implements TrustLinker {

	private static final Log LOG = LogFactory.getLog(OcspTrustLinker.class);

	private final OcspRepository ocspRepository;

	/**
	 * Default OCSP freshness interval.
	 */
	public static final long DEFAULT_FRESHNESS_INTERVAL = 1000 * 10;

	private long freshnessInterval = DEFAULT_FRESHNESS_INTERVAL;

	public OcspTrustLinker(OcspRepository ocspRepository) {
		this.ocspRepository = ocspRepository;
	}

	public void setFreshnessInterval(long freshnessInterval) {
		this.freshnessInterval = freshnessInterval;
	}

	public Boolean hasTrustLink(X509Certificate childCertificate,
			X509Certificate certificate, Date validationDate) {
		URI ocspUri = getOcspUri(childCertificate);
		if (null == ocspUri) {
			return null;
		}
		LOG.debug("OCSP URI: " + ocspUri);

		OCSPResp ocspResp = this.ocspRepository.findOcspResponse(ocspUri,
				childCertificate, certificate);
		if (null == ocspResp) {
			LOG.debug("OCSP response not found");
			return null;
		}

		int ocspRespStatus = ocspResp.getStatus();
		if (OCSPResponseStatus.SUCCESSFUL != ocspRespStatus) {
			LOG.debug("OCSP response status: " + ocspRespStatus);
			return null;
		}

		Object responseObject;
		try {
			responseObject = ocspResp.getResponseObject();
		} catch (OCSPException e) {
			LOG.debug("OCSP exception: " + e.getMessage(), e);
			return null;
		}
		BasicOCSPResp basicOCSPResp = (BasicOCSPResp) responseObject;

		try {
			X509Certificate[] responseCertificates = basicOCSPResp
					.getCerts(BouncyCastleProvider.PROVIDER_NAME);
			if (0 == responseCertificates.length) {
				/*
				 * This means that the OCSP response has been signed by the
				 * issuing CA itself.
				 */
				boolean verificationResult = basicOCSPResp.verify(certificate
						.getPublicKey(), BouncyCastleProvider.PROVIDER_NAME);
				if (false == verificationResult) {
					LOG.debug("OCSP response signature invalid");
					return null;
				}
			} else {
				/*
				 * We're dealing with a dedicated authorized OCSP Responder
				 * certificate.
				 */
				X509Certificate ocspResponderCertificate = responseCertificates[0];
				boolean verificationResult = basicOCSPResp.verify(
						ocspResponderCertificate.getPublicKey(),
						BouncyCastleProvider.PROVIDER_NAME);
				if (false == verificationResult) {
					LOG.debug("OCSP Responser response signature invalid");
					return null;
				}
				X509Certificate issuingCaCertificate = responseCertificates[1];
				if (false == certificate.equals(issuingCaCertificate)) {
					LOG.debug("OCSP responder certificate not issued by CA");
					return null;
				}
				PublicKeyTrustLinker publicKeyTrustLinker = new PublicKeyTrustLinker();
				Boolean trusted = publicKeyTrustLinker.hasTrustLink(
						ocspResponderCertificate, issuingCaCertificate,
						validationDate);
				if (null != trusted) {
					if (false == trusted) {
						LOG.debug("OCSP responder not trusted");
						return null;
					}
				}
				if (null == ocspResponderCertificate
						.getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck
								.getId())) {
					LOG
							.debug("OCSP Responder certificate should have id-pkix-ocsp-nocheck");
					return null;
				}
				List<String> extendedKeyUsage;
				try {
					extendedKeyUsage = ocspResponderCertificate
							.getExtendedKeyUsage();
				} catch (CertificateParsingException e) {
					LOG.debug(
							"OCSP Responder parsing error: " + e.getMessage(),
							e);
					return null;
				}
				if (null == extendedKeyUsage) {
					LOG
							.debug("OCSP Responder certificate has no extended key usage extension");
					return null;
				}
				if (false == extendedKeyUsage
						.contains(KeyPurposeId.id_kp_OCSPSigning.getId())) {
					LOG
							.debug("OCSP Responder certificate should have a OCSPSigning extended key usage");
					return null;
				}
			}
		} catch (NoSuchProviderException e) {
			LOG.debug("JCA provider exception: " + e.getMessage(), e);
			return null;
		} catch (OCSPException e) {
			LOG.debug("OCSP exception: " + e.getMessage(), e);
			return null;
		}

		CertificateID certificateId;
		try {
			certificateId = new CertificateID(CertificateID.HASH_SHA1,
					certificate, childCertificate.getSerialNumber());
		} catch (OCSPException e) {
			LOG.debug("OCSP exception: " + e.getMessage(), e);
			return null;
		}

		SingleResp[] singleResps = basicOCSPResp.getResponses();
		for (SingleResp singleResp : singleResps) {
			CertificateID responseCertificateId = singleResp.getCertID();
			if (false == certificateId.equals(responseCertificateId)) {
				continue;
			}
			Date thisUpdate = singleResp.getThisUpdate();
			long dt = Math.abs(thisUpdate.getTime() - validationDate.getTime());
			if (dt > this.freshnessInterval) {
				LOG.debug("freshness interval exceeded: " + dt
						+ " milliseconds");
				continue;
			}
			if (null == singleResp.getCertStatus()) {
				LOG.debug("OCSP OK for: "
						+ childCertificate.getSubjectX500Principal());
				return true;
			} else {
				return false;
			}
		}

		LOG.debug("no matching OCSP response entry");
		return null;
	}

	public URI getOcspUri(X509Certificate certificate) {
		URI ocspURI = getAccessLocation(certificate,
				X509ObjectIdentifiers.ocspAccessMethod);
		return ocspURI;
	}

	private URI getAccessLocation(X509Certificate certificate,
			DERObjectIdentifier accessMethod) {
		byte[] authInfoAccessExtensionValue = certificate
				.getExtensionValue(X509Extensions.AuthorityInfoAccess.getId());
		if (null == authInfoAccessExtensionValue) {
			return null;
		}
		AuthorityInformationAccess authorityInformationAccess;
		try {
			DEROctetString oct = (DEROctetString) (new ASN1InputStream(
					new ByteArrayInputStream(authInfoAccessExtensionValue))
					.readObject());
			authorityInformationAccess = new AuthorityInformationAccess(
					(ASN1Sequence) new ASN1InputStream(oct.getOctets())
							.readObject());
		} catch (IOException e) {
			throw new RuntimeException("IO error: " + e.getMessage(), e);
		}
		AccessDescription[] accessDescriptions = authorityInformationAccess
				.getAccessDescriptions();
		for (AccessDescription accessDescription : accessDescriptions) {
			LOG.debug("access method: " + accessDescription.getAccessMethod());
			boolean correctAccessMethod = accessDescription.getAccessMethod()
					.equals(accessMethod);
			if (!correctAccessMethod) {
				continue;
			}
			GeneralName gn = accessDescription.getAccessLocation();
			if (gn.getTagNo() != GeneralName.uniformResourceIdentifier) {
				LOG.debug("not a uniform resource identifier");
				continue;
			}
			DERIA5String str = DERIA5String.getInstance(gn.getDERObject());
			String accessLocation = str.getString();
			LOG.debug("access location: " + accessLocation);
			URI uri = toURI(accessLocation);
			LOG.debug("access location URI: " + uri);
			return uri;
		}
		return null;
	}

	private URI toURI(String str) {
		try {
			URI uri = new URI(str);
			return uri;
		} catch (URISyntaxException e) {
			throw new InvalidParameterException("URI syntax error: "
					+ e.getMessage());
		}
	}

}
