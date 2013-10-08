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

package be.fedict.trust.ocsp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import be.fedict.trust.AlgorithmPolicy;
import be.fedict.trust.OCSPRevocationData;
import be.fedict.trust.PublicKeyTrustLinker;
import be.fedict.trust.RevocationData;
import be.fedict.trust.TrustLinker;
import be.fedict.trust.TrustLinkerResult;
import be.fedict.trust.TrustLinkerResultException;
import be.fedict.trust.TrustLinkerResultReason;

/**
 * Trust linker based on OCSP revocation information.
 * 
 * @author Frank Cornelis
 * 
 */
public class OcspTrustLinker implements TrustLinker {

	private static final Log LOG = LogFactory.getLog(OcspTrustLinker.class);

	private final OcspRepository ocspRepository;

	/**
	 * Default OCSP freshness interval. Apparently 10 seconds it too low for NTP
	 * synchronized servers.
	 */
	public static final long DEFAULT_FRESHNESS_INTERVAL = 1000 * 60 * 5;

	private long freshnessInterval = DEFAULT_FRESHNESS_INTERVAL;

	/**
	 * Main constructor.
	 * 
	 * @param ocspRepository
	 *            the OCSP repository component used by this OCSP trust linker.
	 */
	public OcspTrustLinker(OcspRepository ocspRepository) {
		this.ocspRepository = ocspRepository;
	}

	/**
	 * Sets the OCSP response freshness interval in milliseconds. This interval
	 * is used to determine whether an OCSP response can be considered fresh
	 * enough to use as basis for linking trust between child certificate and
	 * parent certificate.
	 * 
	 * @param freshnessInterval
	 */
	public void setFreshnessInterval(long freshnessInterval) {
		this.freshnessInterval = freshnessInterval;
	}

	public TrustLinkerResult hasTrustLink(X509Certificate childCertificate,
			X509Certificate certificate, Date validationDate,
			RevocationData revocationData, AlgorithmPolicy algorithmPolicy)
			throws TrustLinkerResultException, Exception {
		URI ocspUri = getOcspUri(childCertificate);
		if (null == ocspUri) {
			return TrustLinkerResult.UNDECIDED;
		}
		LOG.debug("OCSP URI: " + ocspUri);

		OCSPResp ocspResp = this.ocspRepository.findOcspResponse(ocspUri,
				childCertificate, certificate);
		if (null == ocspResp) {
			LOG.debug("OCSP response not found");
			return TrustLinkerResult.UNDECIDED;
		}

		int ocspRespStatus = ocspResp.getStatus();
		if (OCSPResponseStatus.SUCCESSFUL != ocspRespStatus) {
			LOG.debug("OCSP response status: " + ocspRespStatus);
			return TrustLinkerResult.UNDECIDED;
		}

		Object responseObject = ocspResp.getResponseObject();
		BasicOCSPResp basicOCSPResp = (BasicOCSPResp) responseObject;

		X509CertificateHolder[] responseCertificates = basicOCSPResp.getCerts();
		for (X509CertificateHolder responseCertificate : responseCertificates) {
			LOG.debug("OCSP response cert: " + responseCertificate.getSubject());
			LOG.debug("OCSP response cert issuer: "
					+ responseCertificate.getIssuer());
		}

		algorithmPolicy.checkSignatureAlgorithm(basicOCSPResp
				.getSignatureAlgOID().getId());

		if (0 == responseCertificates.length) {
			/*
			 * This means that the OCSP response has been signed by the issuing
			 * CA itself.
			 */
			ContentVerifierProvider contentVerifierProvider = new JcaContentVerifierProviderBuilder()
					.setProvider(BouncyCastleProvider.PROVIDER_NAME).build(
							certificate.getPublicKey());
			boolean verificationResult = basicOCSPResp
					.isSignatureValid(contentVerifierProvider);
			if (false == verificationResult) {
				LOG.debug("OCSP response signature invalid");
				return TrustLinkerResult.UNDECIDED;
			}
		} else {
			/*
			 * We're dealing with a dedicated authorized OCSP Responder
			 * certificate, or of course with a CA that issues the OCSP
			 * Responses itself.
			 */

			X509CertificateHolder ocspResponderCertificate = responseCertificates[0];
			ContentVerifierProvider contentVerifierProvider = new JcaContentVerifierProviderBuilder()
					.setProvider(BouncyCastleProvider.PROVIDER_NAME).build(
							ocspResponderCertificate);

			boolean verificationResult = basicOCSPResp
					.isSignatureValid(contentVerifierProvider);
			if (false == verificationResult) {
				LOG.debug("OCSP Responser response signature invalid");
				return TrustLinkerResult.UNDECIDED;
			}
			if (false == Arrays.equals(certificate.getEncoded(),
					ocspResponderCertificate.getEncoded())) {
				// check certificate signature algorithm
				algorithmPolicy
						.checkSignatureAlgorithm(ocspResponderCertificate
								.getSignatureAlgorithm().getAlgorithm().getId());

				X509Certificate issuingCaCertificate;
				if (responseCertificates.length < 2) {
					// so the OCSP certificate chain only contains a single
					// entry
					LOG.debug("OCSP responder complete certificate chain missing");
					/*
					 * Here we assume that the OCSP Responder is directly signed
					 * by the CA.
					 */
					issuingCaCertificate = certificate;
				} else {
					CertificateFactory certificateFactory = CertificateFactory
							.getInstance("X.509");
					issuingCaCertificate = (X509Certificate) certificateFactory
							.generateCertificate(new ByteArrayInputStream(
									responseCertificates[1].getEncoded()));
					/*
					 * Is next check really required?
					 */
					if (false == certificate.equals(issuingCaCertificate)) {
						LOG.debug("OCSP responder certificate not issued by CA");
						return TrustLinkerResult.UNDECIDED;
					}
				}
				// check certificate signature
				algorithmPolicy.checkSignatureAlgorithm(issuingCaCertificate
						.getSigAlgOID());

				PublicKeyTrustLinker publicKeyTrustLinker = new PublicKeyTrustLinker();
				CertificateFactory certificateFactory = CertificateFactory
						.getInstance("X.509");
				X509Certificate x509OcspResponderCertificate = (X509Certificate) certificateFactory
						.generateCertificate(new ByteArrayInputStream(
								ocspResponderCertificate.getEncoded()));
				LOG.debug("OCSP Responder public key fingerprint: "
						+ DigestUtils.sha1Hex(x509OcspResponderCertificate
								.getPublicKey().getEncoded()));
				publicKeyTrustLinker.hasTrustLink(x509OcspResponderCertificate,
						issuingCaCertificate, validationDate, revocationData,
						algorithmPolicy);
				if (null == x509OcspResponderCertificate
						.getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck
								.getId())) {
					LOG.debug("OCSP Responder certificate should have id-pkix-ocsp-nocheck");
					/*
					 * TODO: perform CRL validation on the OCSP Responder
					 * certificate. On the other hand, do we really want to
					 * check the checker?
					 */
					return TrustLinkerResult.UNDECIDED;
				}
				List<String> extendedKeyUsage = x509OcspResponderCertificate
						.getExtendedKeyUsage();
				if (null == extendedKeyUsage) {
					LOG.debug("OCSP Responder certificate has no extended key usage extension");
					return TrustLinkerResult.UNDECIDED;
				}
				if (false == extendedKeyUsage
						.contains(KeyPurposeId.id_kp_OCSPSigning.getId())) {
					LOG.debug("OCSP Responder certificate should have a OCSPSigning extended key usage");
					return TrustLinkerResult.UNDECIDED;
				}
			} else {
				LOG.debug("OCSP Responder certificate equals the CA certificate");
				// and the CA certificate is already trusted at this point
			}
		}

		DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder()
				.setProvider(BouncyCastleProvider.PROVIDER_NAME).build();
		CertificateID certificateId = new CertificateID(
				digCalcProv.get(CertificateID.HASH_SHA1),
				new JcaX509CertificateHolder(certificate),
				childCertificate.getSerialNumber());

		SingleResp[] singleResps = basicOCSPResp.getResponses();
		for (SingleResp singleResp : singleResps) {
			CertificateID responseCertificateId = singleResp.getCertID();
			if (false == certificateId.equals(responseCertificateId)) {
				continue;
			}
			Date thisUpdate = singleResp.getThisUpdate();
			LOG.debug("OCSP thisUpdate: " + thisUpdate);
			LOG.debug("OCSP nextUpdate: " + singleResp.getNextUpdate());
			long dt = Math.abs(thisUpdate.getTime() - validationDate.getTime());
			if (dt > this.freshnessInterval) {
				LOG.warn("freshness interval exceeded: " + dt + " milliseconds");
				continue;
			}
			if (null == singleResp.getCertStatus()) {
				LOG.debug("OCSP OK for: "
						+ childCertificate.getSubjectX500Principal());
				addRevocationData(revocationData, ocspResp, ocspUri);
				return TrustLinkerResult.TRUSTED;
			} else {
				LOG.debug("OCSP certificate status: "
						+ singleResp.getCertStatus().getClass().getName());
				if (singleResp.getCertStatus() instanceof RevokedStatus) {
					LOG.debug("OCSP status revoked");
				}
				addRevocationData(revocationData, ocspResp, ocspUri);
				throw new TrustLinkerResultException(
						TrustLinkerResultReason.INVALID_REVOCATION_STATUS,
						"certificate revoked by OCSP");
			}
		}

		LOG.debug("no matching OCSP response entry");
		return TrustLinkerResult.UNDECIDED;
	}

	private void addRevocationData(RevocationData revocationData,
			OCSPResp ocspResp, URI uri) throws IOException {
		if (null == revocationData) {
			return;
		}
		OCSPRevocationData ocspRevocationData = new OCSPRevocationData(
				ocspResp.getEncoded(), uri.toString());
		revocationData.getOcspRevocationData().add(ocspRevocationData);
	}

	private URI getOcspUri(X509Certificate certificate) throws IOException,
			URISyntaxException {
		URI ocspURI = getAccessLocation(certificate,
				X509ObjectIdentifiers.ocspAccessMethod);
		return ocspURI;
	}

	private URI getAccessLocation(X509Certificate certificate,
			DERObjectIdentifier accessMethod) throws IOException,
			URISyntaxException {
		byte[] authInfoAccessExtensionValue = certificate
				.getExtensionValue(X509Extension.authorityInfoAccess.getId());
		if (null == authInfoAccessExtensionValue) {
			return null;
		}
		AuthorityInformationAccess authorityInformationAccess;
		DEROctetString oct = (DEROctetString) (new ASN1InputStream(
				new ByteArrayInputStream(authInfoAccessExtensionValue))
				.readObject());
		authorityInformationAccess = AuthorityInformationAccess
				.getInstance(new ASN1InputStream(oct.getOctets()).readObject());
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
			DERIA5String str = DERIA5String.getInstance(gn.getName());
			String accessLocation = str.getString();
			LOG.debug("access location: " + accessLocation);
			URI uri = toURI(accessLocation);
			LOG.debug("access location URI: " + uri);
			return uri;
		}
		return null;
	}

	private URI toURI(String str) throws URISyntaxException {
		URI uri = new URI(str);
		return uri;
	}
}
