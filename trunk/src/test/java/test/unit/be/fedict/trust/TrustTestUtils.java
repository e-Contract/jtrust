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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.BasicOCSPRespGenerator;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.CertificateStatus;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.OCSPRespGenerator;
import org.bouncycastle.ocsp.Req;
import org.bouncycastle.ocsp.RevokedStatus;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenGenerator;
import org.bouncycastle.x509.AttributeCertificateHolder;
import org.bouncycastle.x509.AttributeCertificateIssuer;
import org.bouncycastle.x509.X509Attribute;
import org.bouncycastle.x509.X509V2AttributeCertificate;
import org.bouncycastle.x509.X509V2AttributeCertificateGenerator;
import org.bouncycastle.x509.X509V2CRLGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.joda.time.DateTime;

public class TrustTestUtils {

	public static X509Certificate generateCertificate(
			PublicKey subjectPublicKey, String subjectDn, DateTime notBefore,
			DateTime notAfter, X509Certificate issuerCertificate,
			PrivateKey issuerPrivateKey) throws IOException,
			InvalidKeyException, IllegalStateException,
			NoSuchAlgorithmException, SignatureException, CertificateException {
		return generateCertificate(subjectPublicKey, subjectDn, notBefore,
				notAfter, issuerCertificate, issuerPrivateKey, true);
	}

	public static X509Certificate generateCertificate(
			PublicKey subjectPublicKey, String subjectDn, DateTime notBefore,
			DateTime notAfter, X509Certificate issuerCertificate,
			PrivateKey issuerPrivateKey, boolean caFlag) throws IOException,
			InvalidKeyException, IllegalStateException,
			NoSuchAlgorithmException, SignatureException, CertificateException {
		return generateCertificate(subjectPublicKey, subjectDn, notBefore,
				notAfter, issuerCertificate, issuerPrivateKey, caFlag, -1);
	}

	public static X509Certificate generateCertificate(
			PublicKey subjectPublicKey, String subjectDn, DateTime notBefore,
			DateTime notAfter, X509Certificate issuerCertificate,
			PrivateKey issuerPrivateKey, boolean caFlag, int pathLength)
			throws IOException, InvalidKeyException, IllegalStateException,
			NoSuchAlgorithmException, SignatureException, CertificateException {
		return generateCertificate(subjectPublicKey, subjectDn, notBefore,
				notAfter, issuerCertificate, issuerPrivateKey, caFlag,
				pathLength, null);
	}

	public static X509Certificate generateCertificate(
			PublicKey subjectPublicKey, String subjectDn, DateTime notBefore,
			DateTime notAfter, X509Certificate issuerCertificate,
			PrivateKey issuerPrivateKey, boolean caFlag, int pathLength,
			String crlUri) throws IOException, InvalidKeyException,
			IllegalStateException, NoSuchAlgorithmException,
			SignatureException, CertificateException {
		return generateCertificate(subjectPublicKey, subjectDn, notBefore,
				notAfter, issuerCertificate, issuerPrivateKey, caFlag,
				pathLength, crlUri, null);
	}

	public static X509Certificate generateCertificate(
			PublicKey subjectPublicKey, String subjectDn, DateTime notBefore,
			DateTime notAfter, X509Certificate issuerCertificate,
			PrivateKey issuerPrivateKey, boolean caFlag, int pathLength,
			String crlUri, String ocspUri) throws IOException,
			InvalidKeyException, IllegalStateException,
			NoSuchAlgorithmException, SignatureException, CertificateException {
		X509Certificate certificate = generateCertificate(subjectPublicKey,
				subjectDn, notBefore, notAfter, issuerCertificate,
				issuerPrivateKey, caFlag, pathLength, crlUri, ocspUri, null,
				"SHA1withRSA");
		return certificate;
	}

	public static X509Certificate generateCertificate(
			PublicKey subjectPublicKey, String subjectDn, DateTime notBefore,
			DateTime notAfter, X509Certificate issuerCertificate,
			PrivateKey issuerPrivateKey, boolean caFlag, int pathLength,
			String crlUri, String ocspUri, KeyUsage keyUsage,
			String signatureAlgorithm) throws IOException, InvalidKeyException,
			IllegalStateException, NoSuchAlgorithmException,
			SignatureException, CertificateException {

		return generateCertificate(subjectPublicKey, subjectDn, notBefore,
				notAfter, issuerCertificate, issuerPrivateKey, caFlag,
				pathLength, crlUri, ocspUri, keyUsage, signatureAlgorithm,
				false);
	}

	public static X509Certificate generateCertificate(
			PublicKey subjectPublicKey, String subjectDn, DateTime notBefore,
			DateTime notAfter, X509Certificate issuerCertificate,
			PrivateKey issuerPrivateKey, boolean caFlag, int pathLength,
			String crlUri, String ocspUri, KeyUsage keyUsage,
			String signatureAlgorithm, boolean tsa) throws IOException,
			InvalidKeyException, IllegalStateException,
			NoSuchAlgorithmException, SignatureException, CertificateException {
		X509V3CertificateGenerator certificateGenerator = new X509V3CertificateGenerator();
		certificateGenerator.reset();
		certificateGenerator.setPublicKey(subjectPublicKey);
		certificateGenerator.setSignatureAlgorithm(signatureAlgorithm);
		certificateGenerator.setNotBefore(notBefore.toDate());
		certificateGenerator.setNotAfter(notAfter.toDate());
		X509Principal issuerDN;
		if (null != issuerCertificate) {
			issuerDN = new X509Principal(issuerCertificate
					.getSubjectX500Principal().toString());
		} else {
			issuerDN = new X509Principal(subjectDn);
		}
		certificateGenerator.setIssuerDN(issuerDN);
		certificateGenerator.setSubjectDN(new X509Principal(subjectDn));
		certificateGenerator.setSerialNumber(new BigInteger(128,
				new SecureRandom()));

		certificateGenerator.addExtension(X509Extensions.SubjectKeyIdentifier,
				false, createSubjectKeyId(subjectPublicKey));
		PublicKey issuerPublicKey;
		issuerPublicKey = subjectPublicKey;
		certificateGenerator.addExtension(
				X509Extensions.AuthorityKeyIdentifier, false,
				createAuthorityKeyId(issuerPublicKey));

		if (caFlag) {
			if (-1 == pathLength) {
				certificateGenerator.addExtension(
						X509Extensions.BasicConstraints, false,
						new BasicConstraints(true));
			} else {
				certificateGenerator.addExtension(
						X509Extensions.BasicConstraints, false,
						new BasicConstraints(pathLength));
			}
		}

		if (null != crlUri) {
			GeneralName gn = new GeneralName(
					GeneralName.uniformResourceIdentifier, new DERIA5String(
							crlUri));
			GeneralNames gns = new GeneralNames(new DERSequence(gn));
			DistributionPointName dpn = new DistributionPointName(0, gns);
			DistributionPoint distp = new DistributionPoint(dpn, null, null);
			certificateGenerator.addExtension(
					X509Extensions.CRLDistributionPoints, false,
					new DERSequence(distp));
		}

		if (null != ocspUri) {
			GeneralName ocspName = new GeneralName(
					GeneralName.uniformResourceIdentifier, ocspUri);
			AuthorityInformationAccess authorityInformationAccess = new AuthorityInformationAccess(
					X509ObjectIdentifiers.ocspAccessMethod, ocspName);
			certificateGenerator.addExtension(
					X509Extensions.AuthorityInfoAccess.getId(), false,
					authorityInformationAccess);
		}

		if (null != keyUsage) {
			certificateGenerator.addExtension(X509Extensions.KeyUsage, true,
					keyUsage);
		}

		if (tsa) {
			certificateGenerator
					.addExtension(X509Extensions.ExtendedKeyUsage, true,
							new ExtendedKeyUsage(
									KeyPurposeId.id_kp_timeStamping));
		}

		X509Certificate certificate;
		certificate = certificateGenerator.generate(issuerPrivateKey);

		/*
		 * Next certificate factory trick is needed to make sure that the
		 * certificate delivered to the caller is provided by the default
		 * security provider instead of BouncyCastle. If we don't do this trick
		 * we might run into trouble when trying to use the CertPath validator.
		 */
		CertificateFactory certificateFactory = CertificateFactory
				.getInstance("X.509");
		certificate = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(certificate
						.getEncoded()));
		return certificate;
	}

	public static KeyPair generateKeyPair() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		SecureRandom random = new SecureRandom();
		keyPairGenerator.initialize(new RSAKeyGenParameterSpec(1024,
				RSAKeyGenParameterSpec.F4), random);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return keyPair;
	}

	private static SubjectKeyIdentifier createSubjectKeyId(PublicKey publicKey)
			throws IOException {
		ByteArrayInputStream bais = new ByteArrayInputStream(publicKey
				.getEncoded());
		SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(
				(ASN1Sequence) new ASN1InputStream(bais).readObject());
		return new SubjectKeyIdentifier(info);
	}

	private static AuthorityKeyIdentifier createAuthorityKeyId(
			PublicKey publicKey) throws IOException {

		ByteArrayInputStream bais = new ByteArrayInputStream(publicKey
				.getEncoded());
		SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(
				(ASN1Sequence) new ASN1InputStream(bais).readObject());

		return new AuthorityKeyIdentifier(info);
	}

	public static X509Certificate generateSelfSignedCertificate(
			KeyPair keyPair, String subjectDn, DateTime notBefore,
			DateTime notAfter, boolean caFlag, int pathLength, String crlUri)
			throws IOException, InvalidKeyException, IllegalStateException,
			NoSuchAlgorithmException, SignatureException, CertificateException {
		return generateSelfSignedCertificate(keyPair, subjectDn, notBefore,
				notAfter, caFlag, pathLength, crlUri, null);
	}

	public static X509Certificate generateSelfSignedCertificate(
			KeyPair keyPair, String subjectDn, DateTime notBefore,
			DateTime notAfter, boolean caFlag, int pathLength, String crlUri,
			KeyUsage keyUsage) throws IOException, InvalidKeyException,
			IllegalStateException, NoSuchAlgorithmException,
			SignatureException, CertificateException {
		PublicKey subjectPublicKey = keyPair.getPublic();
		PrivateKey issuerPrivateKey = keyPair.getPrivate();
		X509Certificate certificate = generateCertificate(subjectPublicKey,
				subjectDn, notBefore, notAfter, null, issuerPrivateKey, caFlag,
				pathLength, crlUri, null, keyUsage, "SHA1withRSA");
		return certificate;
	}

	public static X509Certificate generateSelfSignedCertificate(
			KeyPair keyPair, String subjectDn, DateTime notBefore,
			DateTime notAfter, boolean caFlag, int pathLength)
			throws IOException, InvalidKeyException, IllegalStateException,
			NoSuchAlgorithmException, SignatureException, CertificateException {
		return generateSelfSignedCertificate(keyPair, subjectDn, notBefore,
				notAfter, caFlag, pathLength, null);
	}

	public static X509Certificate generateSelfSignedCertificate(
			KeyPair keyPair, String subjectDn, DateTime notBefore,
			DateTime notAfter, boolean caFlag) throws IOException,
			InvalidKeyException, IllegalStateException,
			NoSuchAlgorithmException, SignatureException, CertificateException {
		return generateSelfSignedCertificate(keyPair, subjectDn, notBefore,
				notAfter, caFlag, -1);
	}

	public static X509Certificate generateSelfSignedCertificate(
			KeyPair keyPair, String subjectDn, DateTime notBefore,
			DateTime notAfter, String crlUri) throws IOException,
			InvalidKeyException, IllegalStateException,
			NoSuchAlgorithmException, SignatureException, CertificateException {
		return generateSelfSignedCertificate(keyPair, subjectDn, notBefore,
				notAfter, true, -1, crlUri);
	}

	public static X509Certificate generateSelfSignedCertificate(
			KeyPair keyPair, String subjectDn, DateTime notBefore,
			DateTime notAfter) throws IOException, InvalidKeyException,
			IllegalStateException, NoSuchAlgorithmException,
			SignatureException, CertificateException {
		return generateSelfSignedCertificate(keyPair, subjectDn, notBefore,
				notAfter, true);
	}

	public static class RevokedCertificate {
		private final BigInteger serialNumber;
		private final DateTime revocationDate;

		public RevokedCertificate(BigInteger serialNumber,
				DateTime revocationDate) {
			this.serialNumber = serialNumber;
			this.revocationDate = revocationDate;
		}
	}

	public static X509CRL generateCrl(PrivateKey issuerPrivateKey,
			X509Certificate issuerCertificate, DateTime thisUpdate,
			DateTime nextUpdate, BigInteger... revokedCertificateSerialNumbers)
			throws InvalidKeyException, CRLException, IllegalStateException,
			NoSuchAlgorithmException, SignatureException,
			CertificateParsingException {

		return generateCrl(issuerPrivateKey, issuerCertificate, thisUpdate,
				nextUpdate, "SHA1withRSA", revokedCertificateSerialNumbers);
	}

	public static X509CRL generateCrl(PrivateKey issuerPrivateKey,
			X509Certificate issuerCertificate, DateTime thisUpdate,
			DateTime nextUpdate, String signatureAlgorithm,
			BigInteger... revokedCertificateSerialNumbers)
			throws InvalidKeyException, CRLException, IllegalStateException,
			NoSuchAlgorithmException, SignatureException,
			CertificateParsingException {

		List<RevokedCertificate> revokedCertificates = new LinkedList<RevokedCertificate>();
		for (BigInteger revokedCertificateSerialNumber : revokedCertificateSerialNumbers) {
			revokedCertificates.add(new RevokedCertificate(
					revokedCertificateSerialNumber, thisUpdate));
		}
		return generateCrl(issuerPrivateKey, issuerCertificate, thisUpdate,
				nextUpdate, null, false, revokedCertificates,
				signatureAlgorithm);
	}

	public static X509CRL generateCrl(PrivateKey issuerPrivateKey,
			X509Certificate issuerCertificate, DateTime thisUpdate,
			DateTime nextUpdate, List<RevokedCertificate> revokedCertificates)
			throws InvalidKeyException, CRLException, IllegalStateException,
			NoSuchAlgorithmException, SignatureException,
			CertificateParsingException {

		return generateCrl(issuerPrivateKey, issuerCertificate, thisUpdate,
				nextUpdate, null, false, revokedCertificates, "SHA1withRSA");
	}

	public static X509CRL generateCrl(PrivateKey issuerPrivateKey,
			X509Certificate issuerCertificate, DateTime thisUpdate,
			DateTime nextUpdate, List<String> deltaCrlUris,
			List<RevokedCertificate> revokedCertificates)
			throws InvalidKeyException, CRLException, IllegalStateException,
			NoSuchAlgorithmException, SignatureException,
			CertificateParsingException {

		return generateCrl(issuerPrivateKey, issuerCertificate, thisUpdate,
				nextUpdate, deltaCrlUris, false, revokedCertificates,
				"SHA1withRSA");
	}

	public static X509CRL generateCrl(PrivateKey issuerPrivateKey,
			X509Certificate issuerCertificate, DateTime thisUpdate,
			DateTime nextUpdate, List<String> deltaCrlUris, boolean deltaCrl,
			List<RevokedCertificate> revokedCertificates)
			throws InvalidKeyException, CRLException, IllegalStateException,
			NoSuchAlgorithmException, SignatureException,
			CertificateParsingException {

		return generateCrl(issuerPrivateKey, issuerCertificate, thisUpdate,
				nextUpdate, deltaCrlUris, deltaCrl, revokedCertificates,
				"SHA1withRSA");
	}

	public static X509CRL generateCrl(PrivateKey issuerPrivateKey,
			X509Certificate issuerCertificate, DateTime thisUpdate,
			DateTime nextUpdate, List<String> deltaCrlUris, boolean deltaCrl,
			List<RevokedCertificate> revokedCertificates,
			String signatureAlgorithm) throws InvalidKeyException,
			CRLException, IllegalStateException, NoSuchAlgorithmException,
			SignatureException, CertificateParsingException {

		X509V2CRLGenerator crlGenerator = new X509V2CRLGenerator();
		crlGenerator.setThisUpdate(thisUpdate.toDate());
		crlGenerator.setNextUpdate(nextUpdate.toDate());
		crlGenerator.setSignatureAlgorithm(signatureAlgorithm);
		crlGenerator.setIssuerDN(issuerCertificate.getSubjectX500Principal());

		for (RevokedCertificate revokedCertificate : revokedCertificates) {
			crlGenerator.addCRLEntry(revokedCertificate.serialNumber,
					revokedCertificate.revocationDate.toDate(),
					CRLReason.privilegeWithdrawn);
		}

		crlGenerator.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
				new AuthorityKeyIdentifierStructure(issuerCertificate));
		crlGenerator.addExtension(X509Extensions.CRLNumber, false,
				new CRLNumber(BigInteger.ONE));

		if (null != deltaCrlUris && !deltaCrlUris.isEmpty()) {
			DistributionPoint[] deltaCrlDps = new DistributionPoint[deltaCrlUris
					.size()];
			for (int i = 0; i < deltaCrlUris.size(); i++) {
				deltaCrlDps[i] = getDistributionPoint(deltaCrlUris.get(i));
			}
			CRLDistPoint crlDistPoint = new CRLDistPoint(
					(DistributionPoint[]) deltaCrlDps);
			crlGenerator.addExtension(X509Extensions.FreshestCRL, false,
					crlDistPoint);
		}

		if (deltaCrl) {
			crlGenerator.addExtension(X509Extensions.DeltaCRLIndicator, true,
					new CRLNumber(BigInteger.ONE));
		}

		X509CRL x509Crl = crlGenerator.generate(issuerPrivateKey);
		return x509Crl;
	}

	public static DistributionPoint getDistributionPoint(String uri) {
		GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier,
				new DERIA5String(uri));
		ASN1EncodableVector vec = new ASN1EncodableVector();
		vec.add(gn);
		GeneralNames gns = new GeneralNames(new DERSequence(vec));
		DistributionPointName dpn = new DistributionPointName(0, gns);
		return new DistributionPoint(dpn, null, null);
	}

	public static OCSPResp createOcspResp(X509Certificate certificate,
			boolean revoked, X509Certificate issuerCertificate,
			X509Certificate ocspResponderCertificate,
			PrivateKey ocspResponderPrivateKey) throws Exception {
		return createOcspResp(certificate, revoked, issuerCertificate,
				ocspResponderCertificate, ocspResponderPrivateKey,
				"SHA1WITHRSA");
	}

	public static OCSPResp createOcspResp(X509Certificate certificate,
			boolean revoked, X509Certificate issuerCertificate,
			X509Certificate ocspResponderCertificate,
			PrivateKey ocspResponderPrivateKey, String signatureAlgorithm)
			throws Exception {
		// request
		OCSPReqGenerator ocspReqGenerator = new OCSPReqGenerator();
		CertificateID certId = new CertificateID(CertificateID.HASH_SHA1,
				issuerCertificate, certificate.getSerialNumber());
		ocspReqGenerator.addRequest(certId);
		OCSPReq ocspReq = ocspReqGenerator.generate();

		BasicOCSPRespGenerator basicOCSPRespGenerator = new BasicOCSPRespGenerator(
				ocspResponderCertificate.getPublicKey());

		// request processing
		Req[] requestList = ocspReq.getRequestList();
		for (Req ocspRequest : requestList) {
			CertificateID certificateID = ocspRequest.getCertID();
			CertificateStatus certificateStatus;
			if (revoked) {
				certificateStatus = new RevokedStatus(new Date(),
						CRLReason.unspecified);
			} else {
				certificateStatus = CertificateStatus.GOOD;
			}
			basicOCSPRespGenerator
					.addResponse(certificateID, certificateStatus);
		}

		// basic response generation
		BasicOCSPResp basicOCSPResp = basicOCSPRespGenerator.generate(
				signatureAlgorithm, ocspResponderPrivateKey, null, new Date(),
				BouncyCastleProvider.PROVIDER_NAME);

		// response generation
		OCSPRespGenerator ocspRespGenerator = new OCSPRespGenerator();
		OCSPResp ocspResp = ocspRespGenerator.generate(
				OCSPRespGenerator.SUCCESSFUL, basicOCSPResp);

		return ocspResp;
	}

	public static TimeStampToken createTimeStampToken(PrivateKey privateKey,
			List<X509Certificate> certificateChain) throws Exception {

		CollectionCertStoreParameters collectionCertStoreParameters = new CollectionCertStoreParameters(
				certificateChain);
		CertStore certStore = CertStore.getInstance("Collection",
				collectionCertStoreParameters);

		TimeStampRequestGenerator requestGen = new TimeStampRequestGenerator();
		requestGen.setCertReq(true);
		TimeStampRequest request = requestGen.generate(TSPAlgorithms.SHA1,
				new byte[20], BigInteger.valueOf(100));

		TimeStampTokenGenerator tstGen = new TimeStampTokenGenerator(
				privateKey, certificateChain.get(0), TSPAlgorithms.SHA1, "1.2");
		tstGen.setCertificatesAndCRLs(certStore);
		return tstGen.generate(request, BigInteger.ONE, new Date(), "BC");
	}

	public static X509V2AttributeCertificate createAttributeCertificate(
			X509Certificate holderCertificate,
			X509Certificate issuerCertificate, PrivateKey issuerPrivateKey,
			Date notBefore, Date notAfter) throws Exception {

		X509V2AttributeCertificateGenerator acGen = new X509V2AttributeCertificateGenerator();
		acGen.reset();
		acGen.setHolder(new AttributeCertificateHolder(holderCertificate));
		acGen.setIssuer(new AttributeCertificateIssuer(issuerCertificate
				.getSubjectX500Principal()));
		acGen.setSerialNumber(new BigInteger("1"));
		acGen.setNotBefore(notBefore);
		acGen.setNotAfter(notAfter);
		acGen.setSignatureAlgorithm("SHA512WithRSAEncryption");
		GeneralName roleName = new GeneralName(GeneralName.rfc822Name,
				"RoleName");
		ASN1EncodableVector roleSyntax = new ASN1EncodableVector();
		roleSyntax.add(roleName);
		X509Attribute attributes = new X509Attribute("2.5.24.72",
				new DERSequence(roleSyntax));
		acGen.addAttribute(attributes);

		return (X509V2AttributeCertificate) acGen.generate(issuerPrivateKey,
				"BC");

	}
}
