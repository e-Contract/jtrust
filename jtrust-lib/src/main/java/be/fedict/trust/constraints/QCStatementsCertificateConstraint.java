/*
 * Java Trust Project.
 * Copyright (C) 2009-2010 FedICT.
 * Copyright (C) 2014-2018 e-Contract.be BVBA.
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

package be.fedict.trust.constraints;

import java.io.ByteArrayInputStream;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.qualified.QCStatement;

import be.fedict.trust.linker.TrustLinkerResultException;
import be.fedict.trust.linker.TrustLinkerResultReason;

/**
 * QCStatements certificate constraint.
 * 
 * @author Frank Cornelis
 * 
 * @see <a href="http://www.ietf.org/rfc/rfc3039.txt">RFC 3039</a>
 * @see <a href=
 *      "http://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.01.01_60/en_31941205v020101p.pdf">
 *      ETSI EN 319 412-5 V2.1.1</a>
 */
public class QCStatementsCertificateConstraint implements CertificateConstraint {

	private static final Log LOG = LogFactory.getLog(QCStatementsCertificateConstraint.class);

	static final ASN1ObjectIdentifier id_etsi_qcs_QcType = new ASN1ObjectIdentifier("0.4.0.1862.1.6");

	static final ASN1ObjectIdentifier id_etsi_qcs_QcType_eSign = id_etsi_qcs_QcType.branch("1");
	static final ASN1ObjectIdentifier id_etsi_qcs_QcType_eSeal = id_etsi_qcs_QcType.branch("2");

	private final Boolean qcComplianceFilter;

	private final Boolean qcSSCDFilter;

	private final Boolean qcTypeSignFilter;

	private final Boolean qcTypeSealFilter;

	public QCStatementsCertificateConstraint(Boolean qcComplianceFilter) {
		this(qcComplianceFilter, null);
	}

	public QCStatementsCertificateConstraint(Boolean qcComplianceFilter, Boolean qcSSCDFilter) {
		this(qcComplianceFilter, qcSSCDFilter, null, null);
	}

	public QCStatementsCertificateConstraint(Boolean qcComplianceFilter, Boolean qcSSCDFilter, Boolean qcTypeSignFilter,
			Boolean qcTypeSealFilter) {
		this.qcComplianceFilter = qcComplianceFilter;
		this.qcSSCDFilter = qcSSCDFilter;
		this.qcTypeSignFilter = qcTypeSignFilter;
		this.qcTypeSealFilter = qcTypeSealFilter;
	}

	@Override
	public void check(X509Certificate certificate) throws TrustLinkerResultException, Exception {
		byte[] extensionValue = certificate.getExtensionValue(Extension.qCStatements.getId());
		if (null == extensionValue) {
			throw new TrustLinkerResultException(TrustLinkerResultReason.CONSTRAINT_VIOLATION,
					"missing QCStatements extension");
		}
		DEROctetString oct = (DEROctetString) (new ASN1InputStream(new ByteArrayInputStream(extensionValue))
				.readObject());
		ASN1Sequence qcStatements = (ASN1Sequence) new ASN1InputStream(oct.getOctets()).readObject();
		Enumeration<?> qcStatementEnum = qcStatements.getObjects();
		boolean qcCompliance = false;
		boolean qcSSCD = false;
		boolean eSign = false;
		boolean eSeal = false;
		while (qcStatementEnum.hasMoreElements()) {
			QCStatement qcStatement = QCStatement.getInstance(qcStatementEnum.nextElement());
			ASN1ObjectIdentifier statementId = qcStatement.getStatementId();
			LOG.debug("statement Id: " + statementId.getId());
			if (QCStatement.id_etsi_qcs_QcCompliance.equals(statementId)) {
				qcCompliance = true;
			}
			if (QCStatement.id_etsi_qcs_QcSSCD.equals(statementId)) {
				qcSSCD = true;
			}
			if (id_etsi_qcs_QcType.equals(statementId)) {
				ASN1Encodable statementInfo = qcStatement.getStatementInfo();
				ASN1Sequence qcTypeSequence = ASN1Sequence.getInstance(statementInfo);
				Enumeration<?> qcType = qcTypeSequence.getObjects();
				while (qcType.hasMoreElements()) {
					ASN1ObjectIdentifier qcTypeOID = ASN1ObjectIdentifier.getInstance(qcType.nextElement());
					LOG.debug("QcType: " + qcTypeOID);
					if (id_etsi_qcs_QcType_eSign.equals(qcTypeOID)) {
						eSign = true;
					}
					if (id_etsi_qcs_QcType_eSeal.equals(qcTypeOID)) {
						eSeal = true;
					}
				}
			}
		}

		if (null != this.qcComplianceFilter) {
			if (qcCompliance != this.qcComplianceFilter) {
				LOG.error("qcCompliance QCStatements error");
				throw new TrustLinkerResultException(TrustLinkerResultReason.CONSTRAINT_VIOLATION,
						"QCStatements not matching");
			}
		}

		if (null != this.qcSSCDFilter) {
			if (qcSSCD != this.qcSSCDFilter) {
				LOG.error("qcSSCD QCStatements error");
				throw new TrustLinkerResultException(TrustLinkerResultReason.CONSTRAINT_VIOLATION,
						"QCStatements not matching");
			}
		}

		if (null != this.qcTypeSignFilter) {
			if (eSign != this.qcTypeSignFilter) {
				LOG.error("QcType eSign error");
				throw new TrustLinkerResultException(TrustLinkerResultReason.CONSTRAINT_VIOLATION,
						"QcType eSign not matching");
			}
		}

		if (null != this.qcTypeSealFilter) {
			if (eSeal != this.qcTypeSealFilter) {
				LOG.error("QcType eSeal error");
				throw new TrustLinkerResultException(TrustLinkerResultReason.CONSTRAINT_VIOLATION,
						"QcType eSeal not matching");
			}
		}
	}
}
