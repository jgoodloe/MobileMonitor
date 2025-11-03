enum MonitorStatus { up, down, unknown }

enum MonitorType { url, dns, crl }

class MonitorItem {
  final String id;
  final String name;
  final MonitorType type;
  final MonitorStatus status;
  final DateTime? lastCheckTime;
  final String? errorMessage;
  final CertificateInfo? certificateInfo;
  final UrlErrorDetails? urlErrorDetails; // Enhanced error info for URLs
  final List<IpAddressInfo>? ipAddresses; // DNS IP addresses with ping info
  final CrlValidityInfo? crlValidityInfo; // CRL validity period

  MonitorItem({
    required this.id,
    required this.name,
    required this.type,
    required this.status,
    this.lastCheckTime,
    this.errorMessage,
    this.certificateInfo,
    this.urlErrorDetails,
    this.ipAddresses,
    this.crlValidityInfo,
  });

  MonitorItem copyWith({
    String? id,
    String? name,
    MonitorType? type,
    MonitorStatus? status,
    DateTime? lastCheckTime,
    String? errorMessage,
    CertificateInfo? certificateInfo,
    UrlErrorDetails? urlErrorDetails,
    List<IpAddressInfo>? ipAddresses,
    CrlValidityInfo? crlValidityInfo,
  }) {
    return MonitorItem(
      id: id ?? this.id,
      name: name ?? this.name,
      type: type ?? this.type,
      status: status ?? this.status,
      lastCheckTime: lastCheckTime ?? this.lastCheckTime,
      errorMessage: errorMessage ?? this.errorMessage,
      certificateInfo: certificateInfo ?? this.certificateInfo,
      urlErrorDetails: urlErrorDetails ?? this.urlErrorDetails,
      ipAddresses: ipAddresses ?? this.ipAddresses,
      crlValidityInfo: crlValidityInfo ?? this.crlValidityInfo,
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'name': name,
      'type': type.toString(),
      'status': status.toString(),
      'lastCheckTime': lastCheckTime?.toIso8601String(),
      'errorMessage': errorMessage,
      'certificateInfo': certificateInfo?.toJson(),
      'urlErrorDetails': urlErrorDetails?.toJson(),
      'ipAddresses': ipAddresses?.map((ip) => ip.toJson()).toList(),
      'crlValidityInfo': crlValidityInfo?.toJson(),
    };
  }

  factory MonitorItem.fromJson(Map<String, dynamic> json) {
    return MonitorItem(
      id: json['id'] as String,
      name: json['name'] as String,
      type: MonitorType.values.firstWhere(
        (e) => e.toString() == json['type'],
        orElse: () => MonitorType.url,
      ),
      status: MonitorStatus.values.firstWhere(
        (e) => e.toString() == json['status'],
        orElse: () => MonitorStatus.unknown,
      ),
      lastCheckTime: json['lastCheckTime'] != null
          ? DateTime.parse(json['lastCheckTime'] as String)
          : null,
      errorMessage: json['errorMessage'] as String?,
      certificateInfo: json['certificateInfo'] != null
          ? CertificateInfo.fromJson(json['certificateInfo'] as Map<String, dynamic>)
          : null,
      urlErrorDetails: json['urlErrorDetails'] != null
          ? UrlErrorDetails.fromJson(json['urlErrorDetails'] as Map<String, dynamic>)
          : null,
      ipAddresses: json['ipAddresses'] != null
          ? (json['ipAddresses'] as List)
              .map((ip) => IpAddressInfo.fromJson(ip as Map<String, dynamic>))
              .toList()
          : null,
      crlValidityInfo: json['crlValidityInfo'] != null
          ? CrlValidityInfo.fromJson(json['crlValidityInfo'] as Map<String, dynamic>)
          : null,
    );
  }
}

class CertificateInfo {
  final DateTime? validFrom;
  final DateTime? validTo;
  final String? issuer;
  final String? subject;
  final bool isExpiringSoon; // Expiring within 30 days

  CertificateInfo({
    this.validFrom,
    this.validTo,
    this.issuer,
    this.subject,
    this.isExpiringSoon = false,
  });

  Map<String, dynamic> toJson() {
    return {
      'validFrom': validFrom?.toIso8601String(),
      'validTo': validTo?.toIso8601String(),
      'issuer': issuer,
      'subject': subject,
      'isExpiringSoon': isExpiringSoon,
    };
  }

  factory CertificateInfo.fromJson(Map<String, dynamic> json) {
    return CertificateInfo(
      validFrom: json['validFrom'] != null
          ? DateTime.parse(json['validFrom'] as String)
          : null,
      validTo: json['validTo'] != null
          ? DateTime.parse(json['validTo'] as String)
          : null,
      issuer: json['issuer'] as String?,
      subject: json['subject'] as String?,
      isExpiringSoon: json['isExpiringSoon'] as bool? ?? false,
    );
  }
}

class UrlErrorDetails {
  final String? errorType; // e.g., "ConnectionTimeout", "SSLException", "HttpException"
  final int? httpStatusCode;
  final String? responseBody;
  final Duration? responseTime;
  final bool? isSslError;
  final String? sslErrorMessage;

  UrlErrorDetails({
    this.errorType,
    this.httpStatusCode,
    this.responseBody,
    this.responseTime,
    this.isSslError,
    this.sslErrorMessage,
  });

  Map<String, dynamic> toJson() {
    return {
      'errorType': errorType,
      'httpStatusCode': httpStatusCode,
      'responseBody': responseBody,
      'responseTime': responseTime?.inMilliseconds,
      'isSslError': isSslError,
      'sslErrorMessage': sslErrorMessage,
    };
  }

  factory UrlErrorDetails.fromJson(Map<String, dynamic> json) {
    return UrlErrorDetails(
      errorType: json['errorType'] as String?,
      httpStatusCode: json['httpStatusCode'] as int?,
      responseBody: json['responseBody'] as String?,
      responseTime: json['responseTime'] != null
          ? Duration(milliseconds: json['responseTime'] as int)
          : null,
      isSslError: json['isSslError'] as bool?,
      sslErrorMessage: json['sslErrorMessage'] as String?,
    );
  }
}

class IpAddressInfo {
  final String ipAddress;
  final bool isPingable;
  final Duration? pingTime;
  final String? pingError;

  IpAddressInfo({
    required this.ipAddress,
    this.isPingable = false,
    this.pingTime,
    this.pingError,
  });

  Map<String, dynamic> toJson() {
    return {
      'ipAddress': ipAddress,
      'isPingable': isPingable,
      'pingTime': pingTime?.inMilliseconds,
      'pingError': pingError,
    };
  }

  factory IpAddressInfo.fromJson(Map<String, dynamic> json) {
    return IpAddressInfo(
      ipAddress: json['ipAddress'] as String,
      isPingable: json['isPingable'] as bool? ?? false,
      pingTime: json['pingTime'] != null
          ? Duration(milliseconds: json['pingTime'] as int)
          : null,
      pingError: json['pingError'] as String?,
    );
  }
}

class CrlValidityInfo {
  final DateTime? validFrom;
  final DateTime? validTo;
  final Duration? timeUntilInvalid;
  final Duration? crlAge; // Age of CRL from ThisUpdate
  final bool isExpiringSoon;
  final int? revokedCertificateCount; // Number of revoked certificates in CRL
  final String? certificateAuthority; // CA that issued the CRL
  
  // CRL Extensions (CRL-level)
  final String? crlNumber; // OID 2.5.29.20 - CRL Number (hex string)
  final String? authorityKeyIdentifier; // OID 2.5.29.35 - Authority Key Identifier
  final String? issuingDistributionPoint; // OID 2.5.29.28 - Issuing Distribution Point
  final bool isDeltaCrl; // OID 2.5.29.46 - Delta CRL Indicator
  final int? deltaCrlBaseNumber; // Base CRL number for Delta CRL
  final List<String>? freshestCrlUrls; // OID 2.5.29.47 - Freshest CRL (Delta CRL Distribution Point)
  
  // Revoked Certificate Entry Extensions (aggregated info)
  final Map<String, int>? revocationReasonCounts; // Count of revocations by reason code
  final List<DateTime?>? invalidityDates; // Invalidity dates from revoked certificates

  CrlValidityInfo({
    this.validFrom,
    this.validTo,
    this.timeUntilInvalid,
    this.crlAge,
    this.isExpiringSoon = false,
    this.revokedCertificateCount,
    this.certificateAuthority,
    this.crlNumber,
    this.authorityKeyIdentifier,
    this.issuingDistributionPoint,
    this.isDeltaCrl = false,
    this.deltaCrlBaseNumber,
    this.freshestCrlUrls,
    this.revocationReasonCounts,
    this.invalidityDates,
  });

  Map<String, dynamic> toJson() {
    return {
      'validFrom': validFrom?.toIso8601String(),
      'validTo': validTo?.toIso8601String(),
      'timeUntilInvalid': timeUntilInvalid?.inMilliseconds,
      'isExpiringSoon': isExpiringSoon,
      'revokedCertificateCount': revokedCertificateCount,
      'certificateAuthority': certificateAuthority,
      'crlNumber': crlNumber,
      'crlAge': crlAge?.inMilliseconds,
      'authorityKeyIdentifier': authorityKeyIdentifier,
      'issuingDistributionPoint': issuingDistributionPoint,
      'isDeltaCrl': isDeltaCrl,
      'deltaCrlBaseNumber': deltaCrlBaseNumber,
      'freshestCrlUrls': freshestCrlUrls,
      'revocationReasonCounts': revocationReasonCounts,
      'invalidityDates': invalidityDates?.map((d) => d?.toIso8601String()).toList(),
    };
  }

  factory CrlValidityInfo.fromJson(Map<String, dynamic> json) {
    Map<String, int>? revocationReasonCounts;
    if (json['revocationReasonCounts'] != null) {
      revocationReasonCounts = Map<String, int>.from(
        (json['revocationReasonCounts'] as Map).map(
          (k, v) => MapEntry(k.toString(), v as int),
        ),
      );
    }
    
    List<DateTime?>? invalidityDates;
    if (json['invalidityDates'] != null) {
      invalidityDates = (json['invalidityDates'] as List)
          .map((d) => d != null ? DateTime.parse(d as String) : null)
          .toList();
    }
    
    return CrlValidityInfo(
      validFrom: json['validFrom'] != null
          ? DateTime.parse(json['validFrom'] as String)
          : null,
      validTo: json['validTo'] != null
          ? DateTime.parse(json['validTo'] as String)
          : null,
      timeUntilInvalid: json['timeUntilInvalid'] != null
          ? Duration(milliseconds: json['timeUntilInvalid'] as int)
          : null,
      isExpiringSoon: json['isExpiringSoon'] as bool? ?? false,
      revokedCertificateCount: json['revokedCertificateCount'] as int?,
      certificateAuthority: json['certificateAuthority'] as String?,
      crlNumber: json['crlNumber'] as String?,
      crlAge: json['crlAge'] != null
          ? Duration(milliseconds: json['crlAge'] as int)
          : null,
      authorityKeyIdentifier: json['authorityKeyIdentifier'] as String?,
      issuingDistributionPoint: json['issuingDistributionPoint'] as String?,
      isDeltaCrl: json['isDeltaCrl'] as bool? ?? false,
      deltaCrlBaseNumber: json['deltaCrlBaseNumber'] as int?,
      freshestCrlUrls: json['freshestCrlUrls'] != null
          ? List<String>.from(json['freshestCrlUrls'] as List)
          : null,
      revocationReasonCounts: revocationReasonCounts,
      invalidityDates: invalidityDates,
    );
  }
}

