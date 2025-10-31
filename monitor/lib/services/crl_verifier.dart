import 'dart:io';
import 'dart:typed_data';
import 'package:dio/dio.dart';
import 'package:asn1lib/asn1lib.dart';
import '../models/monitor_status.dart';

class CrlVerifier {
  final Dio _dio;

  CrlVerifier() : _dio = Dio() {
    _dio.options.connectTimeout = const Duration(seconds: 10);
    _dio.options.receiveTimeout = const Duration(seconds: 10);
    _dio.options.validateStatus = (status) => status! < 500;
  }

  Future<MonitorItem> verifyCrl(String crlUrl) async {
    final id = crlUrl;
    final name = crlUrl;

    try {
      final response = await _dio.get(
        crlUrl,
        options: Options(responseType: ResponseType.bytes),
      );

      if (response.statusCode == null || response.statusCode! >= 400) {
        return MonitorItem(
          id: id,
          name: name,
          type: MonitorType.crl,
          status: MonitorStatus.down,
          lastCheckTime: DateTime.now(),
          errorMessage: 'HTTP ${response.statusCode}',
        );
      }

      final crlBytes = response.data as List<int>;
      if (crlBytes.isEmpty) {
        return MonitorItem(
          id: id,
          name: name,
          type: MonitorType.crl,
          status: MonitorStatus.down,
          lastCheckTime: DateTime.now(),
          errorMessage: 'Empty CRL file',
        );
      }

      // CRL downloaded successfully, verify it has content
      // Parse CRL validity information if possible
      CrlValidityInfo? validityInfo;
      
      // Parse CRL to extract information
      int? revokedCount;
      String? certificateAuthority;
      
      try {
        // Parse the CRL file to extract issuer (Certificate Authority) and revoked certificates
        final crlInfo = await _parseCrl(crlBytes);
        certificateAuthority = crlInfo['issuer'] as String?;
        revokedCount = crlInfo['revokedCount'] as int?;
      } catch (e) {
        // If parsing fails, certificateAuthority and revokedCount remain null
        certificateAuthority = null;
        revokedCount = null;
      }
      
      // Helper function to check if a string is an IP address
      bool isIpAddress(String host) {
        final parts = host.split('.');
        if (parts.length != 4) return false;
        try {
          for (final part in parts) {
            final num = int.parse(part);
            if (num < 0 || num > 255) return false;
          }
          return true;
        } catch (_) {
          return false;
        }
      }
      
      // Final fallback: check hostname if CA not found and host is not an IP
      if (certificateAuthority == null || certificateAuthority.isEmpty) {
        try {
          final uri = Uri.parse(crlUrl);
          if (uri.host.isNotEmpty && !isIpAddress(uri.host)) {
            certificateAuthority = uri.host;
          }
        } catch (_) {
          // Keep as null if all extraction methods fail
        }
      }
      
      // Ensure we always try to extract from filename even if previous attempts failed
      if (certificateAuthority == null || certificateAuthority.isEmpty) {
        try {
          final uri = Uri.parse(crlUrl);
          final pathSegments = uri.pathSegments;
          for (final segment in pathSegments.reversed) {
            if (segment.toLowerCase().endsWith('.crl')) {
              final filename = segment.substring(0, segment.length - 4);
              // Replace underscores with spaces for readability
              certificateAuthority = filename.replaceAll('_', ' ');
              
              // Enhance CA name if it contains known patterns
              if (filename.contains('XTec') || filename.contains('Xtec')) {
                certificateAuthority = 'XTec Incorporated';
                if (filename.contains('WidePoint') || filename.contains('PIVI')) {
                  certificateAuthority = 'XTec Incorporated / WidePoint';
                }
              } else if (filename.contains('WidePoint')) {
                certificateAuthority = 'WidePoint';
              }
              break;
            }
          }
        } catch (_) {
          // If still null, leave it as null
        }
      }
      
      try {
        // Try to extract validity from HTTP headers
        final lastModified = response.headers.value('last-modified');
        final expires = response.headers.value('expires');
        
        DateTime? validFrom;
        DateTime? validTo;
        
        if (lastModified != null) {
          try {
            validFrom = HttpDate.parse(lastModified);
          } catch (_) {}
        }
        
        if (expires != null) {
          try {
            validTo = HttpDate.parse(expires);
          } catch (_) {}
        }
        
        // If no expiry from headers, calculate based on typical CRL validity (24-48 hours)
        // Or use a default based on download time
        if (validTo == null) {
          // Default CRL validity: 24 hours from now
          validTo = DateTime.now().add(const Duration(hours: 24));
        }
        
        if (validFrom == null) {
          validFrom = DateTime.now();
        }
        
        final now = DateTime.now();
        final timeUntilInvalid = validTo.difference(now);
        // CRL expiring soon threshold: 1 hour
        final isExpiringSoon = timeUntilInvalid.inHours <= 1 && timeUntilInvalid.inHours >= 0 && 
                               timeUntilInvalid.inMinutes >= 0;
        
        validityInfo = CrlValidityInfo(
          validFrom: validFrom,
          validTo: validTo,
          timeUntilInvalid: timeUntilInvalid.isNegative ? Duration.zero : timeUntilInvalid,
          isExpiringSoon: isExpiringSoon,
          revokedCertificateCount: revokedCount,
          certificateAuthority: certificateAuthority,
        );
      } catch (e) {
        // If parsing fails, set default validity
        final defaultTo = DateTime.now().add(const Duration(hours: 24));
        final nowDefault = DateTime.now();
        final timeUntilInvalidDefault = defaultTo.difference(nowDefault);
        // CRL expiring soon threshold: 1 hour
        final isExpiringSoonDefault = timeUntilInvalidDefault.inHours <= 1 && 
                                     timeUntilInvalidDefault.inHours >= 0;
        validityInfo = CrlValidityInfo(
          validFrom: DateTime.now(),
          validTo: defaultTo,
          timeUntilInvalid: const Duration(hours: 24),
          isExpiringSoon: isExpiringSoonDefault,
          revokedCertificateCount: revokedCount,
          certificateAuthority: certificateAuthority,
        );
      }
      
      if (crlBytes.isNotEmpty) {
        return MonitorItem(
          id: id,
          name: name,
          type: MonitorType.crl,
          status: MonitorStatus.up,
          lastCheckTime: DateTime.now(),
          crlValidityInfo: validityInfo,
        );
      } else {
        return MonitorItem(
          id: id,
          name: name,
          type: MonitorType.crl,
          status: MonitorStatus.down,
          lastCheckTime: DateTime.now(),
          errorMessage: 'Empty CRL file',
        );
      }
    } on DioException catch (e) {
      return MonitorItem(
        id: id,
        name: name,
        type: MonitorType.crl,
        status: MonitorStatus.down,
        lastCheckTime: DateTime.now(),
        errorMessage: e.message ?? 'Connection failed',
      );
    } catch (e) {
      return MonitorItem(
        id: id,
        name: name,
        type: MonitorType.crl,
        status: MonitorStatus.down,
        lastCheckTime: DateTime.now(),
        errorMessage: e.toString(),
      );
    }
  }

  /// Parses a CRL file to extract issuer information and revoked certificate count
  /// Wrapped with timeout to prevent hanging on malformed files
  Future<Map<String, dynamic>> _parseCrl(List<int> crlBytes) async {
    try {
      return await Future<Map<String, dynamic>>(() {
        return _parseCrlInternal(crlBytes);
      }).timeout(const Duration(seconds: 5), onTimeout: () {
        return <String, dynamic>{};
      });
    } catch (e) {
      return <String, dynamic>{};
    }
  }
  
  /// Internal CRL parsing logic
  Map<String, dynamic> _parseCrlInternal(List<int> crlBytes) {
    final result = <String, dynamic>{};
    
    try {
      // Limit parsing to reasonable file sizes (max 10MB)
      if (crlBytes.length > 10 * 1024 * 1024) {
        return result;
      }
      
      // Parse the CRL using ASN1 - convert List<int> to Uint8List
      final bytes = Uint8List.fromList(crlBytes);
      final asn1Parser = ASN1Parser(bytes);
      final topLevelSeq = asn1Parser.nextObject();
      
      if (topLevelSeq is! ASN1Sequence) {
        return result;
      }
      
      final seq = topLevelSeq;
      if (seq.elements.isEmpty) {
        return result;
      }
      
      // CRL structure: CertificateList ::= SEQUENCE {
      //   tbsCertList TBSCertList,
      //   signatureAlgorithm AlgorithmIdentifier,
      //   signatureValue BIT STRING
      // }
      
      // Get tbsCertList (first element)
      if (seq.elements.isNotEmpty) {
        final firstElement = seq.elements[0];
        if (firstElement is ASN1Sequence) {
          final tbsCertList = firstElement;
          
          if (tbsCertList.elements.isNotEmpty) {
            // TBSCertList structure: [version], signature, issuer, thisUpdate, nextUpdate, [revokedCertificates], [extensions]
            int elementIndex = 0;
            
            // Skip version if present (context-specific [0] - check tag value)
            // Version is optional and tagged, but we'll detect it by checking if first element is tagged [0]
            if (tbsCertList.elements.isNotEmpty) {
              final firstElem = tbsCertList.elements[elementIndex];
              // Check if this looks like a version tag (tagged object with tag 0x80 or similar)
              if (firstElem.tag == 0x80 || firstElem.tag == 0xA0) {
                elementIndex++; // Skip version
              }
            }
            
            // Skip signature algorithm (AlgorithmIdentifier)
            if (tbsCertList.elements.length > elementIndex) {
              elementIndex++; // Skip signature
            }
            
            // Extract issuer (Distinguished Name) - this is a Sequence
            if (tbsCertList.elements.length > elementIndex) {
              final issuerElement = tbsCertList.elements[elementIndex];
              if (issuerElement is ASN1Sequence) {
                result['issuer'] = _parseDistinguishedName(issuerElement);
                elementIndex++;
              }
            }
            
            // Extract thisUpdate and nextUpdate (skip them for now)
            if (tbsCertList.elements.length > elementIndex) {
              elementIndex++; // Skip thisUpdate (UTCTime or GeneralizedTime)
            }
            if (tbsCertList.elements.length > elementIndex) {
              elementIndex++; // Skip nextUpdate
            }
            
            // Extract revoked certificates (optional) - this is a Sequence of revoked certificates
            if (tbsCertList.elements.length > elementIndex) {
              final revokedCertificates = tbsCertList.elements[elementIndex];
              if (revokedCertificates is ASN1Sequence) {
                // Count revoked certificates - each revoked cert is a Sequence
                result['revokedCount'] = revokedCertificates.elements.length;
              }
            }
          }
        }
      }
    } catch (e) {
      // If ASN1 parsing fails, return empty result
      // Certificate Authority will be null, will fall back to filename extraction if needed
    }
    
    return result;
  }

  /// Parses a Distinguished Name (DN) from ASN1Sequence
  /// Added safeguards to prevent infinite loops
  String _parseDistinguishedName(ASN1Sequence dnSequence) {
    final parts = <String>[];
    
    try {
      // Limit iteration to prevent infinite loops (max 100 elements per DN)
      final maxElements = 100;
      int elementCount = 0;
      
      // DN structure: RelativeDistinguishedName is a Set of AttributeTypeAndValue
      // Each AttributeTypeAndValue is a Sequence [OID, Value]
      for (final element in dnSequence.elements) {
        if (elementCount >= maxElements) break;
        elementCount++;
        
        if (element is ASN1Set) {
          int setElementCount = 0;
          for (final setElement in element.elements) {
            if (setElementCount >= maxElements) break;
            setElementCount++;
            
            if (setElement is ASN1Sequence && setElement.elements.length >= 2) {
              final oid = setElement.elements[0];
              final value = setElement.elements[1];
              
              String oidString = '';
              if (oid is ASN1ObjectIdentifier) {
                oidString = oid.toString();
              }
              
              String valueString = '';
              if (value is ASN1PrintableString) {
                valueString = value.stringValue;
              } else if (value is ASN1UTF8String) {
                valueString = value.utf8StringValue;
              } else if (value is ASN1IA5String) {
                valueString = value.stringValue;
              } else if (value is ASN1BMPString) {
                valueString = value.stringValue;
              }
              
              // Map common OIDs to readable names
              String attrName = _oidToName(oidString);
              if (attrName.isNotEmpty && valueString.isNotEmpty) {
                parts.add('$attrName=$valueString');
              }
            }
          }
        }
      }
    } catch (e) {
      // If parsing fails, return a simple representation
    }
    
    return parts.isNotEmpty ? parts.join(', ') : '';
  }

  /// Maps OID to readable attribute name
  String _oidToName(String oid) {
    // Common X.500 attribute OIDs
    switch (oid) {
      case '2.5.4.3': // CN - Common Name
        return 'CN';
      case '2.5.4.6': // C - Country
        return 'C';
      case '2.5.4.7': // L - Locality
        return 'L';
      case '2.5.4.8': // ST - State/Province
        return 'ST';
      case '2.5.4.10': // O - Organization
        return 'O';
      case '2.5.4.11': // OU - Organizational Unit
        return 'OU';
      case '2.5.4.5': // serialNumber
        return 'serialNumber';
      default:
        return '';
    }
  }
}

