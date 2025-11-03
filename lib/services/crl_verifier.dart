import 'dart:io';
import 'package:dio/dio.dart';
import 'package:asn1lib/asn1lib.dart';
import 'package:flutter/foundation.dart';
import '../models/monitor_status.dart';

class CrlVerifier {
  late final Dio _dio;
  bool _initialized = false;

  CrlVerifier() {
    // Lazy initialization to avoid blocking constructor
    // Actual initialization happens on first use
  }

  void _ensureInitialized() {
    if (_initialized) return;
    _dio = Dio();
    // Longer timeouts for CRL checks - they can be slow under system load
    _dio.options.connectTimeout = const Duration(seconds: 15);
    _dio.options.receiveTimeout = const Duration(seconds: 15);
    _dio.options.validateStatus = (status) => status! < 500;
    _initialized = true;
  }

  Future<MonitorItem> verifyCrl(String crlUrl) async {
    _ensureInitialized(); // Initialize on first use, not in constructor
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

      // Parse CRL to extract information including extensions
      DateTime? crlThisUpdate;
      DateTime? crlNextUpdate;
      Map<String, dynamic> crlInfo = {};

      try {
        // Parse the CRL file to extract issuer (Certificate Authority), revoked certificates, and extensions
        // Use compute() to run parsing in isolate to avoid blocking UI thread
        crlInfo = await compute(_parseCrlIsolate, crlBytes);
        certificateAuthority = crlInfo['issuer'] as String?;
        revokedCount = crlInfo['revokedCount'] as int?;
        crlThisUpdate = crlInfo['thisUpdate'] != null
            ? DateTime.parse(crlInfo['thisUpdate'] as String).toUtc()
            : null;
        crlNextUpdate = crlInfo['nextUpdate'] != null
            ? DateTime.parse(crlInfo['nextUpdate'] as String).toUtc()
            : null;

        print(
          'DEBUG: crlThisUpdate from parse: ${crlInfo['thisUpdate']} -> $crlThisUpdate (isUtc: ${crlThisUpdate?.isUtc})',
        );
        print(
          'DEBUG: crlNextUpdate from parse: ${crlInfo['nextUpdate']} -> $crlNextUpdate (isUtc: ${crlNextUpdate?.isUtc})',
        );
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
                if (filename.contains('WidePoint') ||
                    filename.contains('PIVI')) {
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
        // Prefer CRL nextUpdate over HTTP headers (more accurate)
        DateTime? validFrom = crlThisUpdate;
        DateTime? validTo = crlNextUpdate;

        print('DEBUG: Initial validFrom (crlThisUpdate): $validFrom');
        print('DEBUG: Initial validTo (crlNextUpdate): $validTo');

        // Track if we have actual CRL dates (not fallbacks)
        bool hasActualThisUpdate = validFrom != null;
        bool hasActualNextUpdate = validTo != null;

        // Fallback to HTTP headers if CRL doesn't have dates
        if (!hasActualNextUpdate) {
          final expires = response.headers.value('expires');
          if (expires != null) {
            try {
              validTo = HttpDate.parse(expires);
            } catch (_) {}
          }
        }

        if (!hasActualThisUpdate) {
          final lastModified = response.headers.value('last-modified');
          if (lastModified != null) {
            try {
              validFrom = HttpDate.parse(lastModified);
              print(
                'DEBUG: Using HTTP last-modified for validFrom: $validFrom',
              );
            } catch (_) {}
          }
        } else {
          print('DEBUG: Using CRL thisUpdate for validFrom: $validFrom');
        }

        // Calculate age of CRL from ThisUpdate (X509V1CRLThisUpdate)
        final now = DateTime.now();
        Duration crlAge;

        if (hasActualThisUpdate && validFrom != null) {
          // Calculate age from ThisUpdate (X509V1CRLThisUpdate)
          crlAge = now.difference(validFrom);
        } else if (validFrom != null) {
          // Calculate age from ThisUpdate from HTTP headers
          crlAge = now.difference(validFrom);
        } else {
          // Fallback: no age if we don't have ThisUpdate
          crlAge = Duration.zero;
        }

        // Calculate time until invalid for expiring soon check
        Duration timeUntilInvalid;
        if (hasActualNextUpdate && validTo != null) {
          timeUntilInvalid = validTo.difference(now);
        } else if (validTo != null) {
          timeUntilInvalid = validTo.difference(now);
        } else if (hasActualThisUpdate && validFrom != null) {
          final calculatedNextUpdate = validFrom.add(const Duration(hours: 24));
          timeUntilInvalid = calculatedNextUpdate.difference(now);
        } else if (validFrom != null) {
          final calculatedNextUpdate = validFrom.add(const Duration(hours: 24));
          timeUntilInvalid = calculatedNextUpdate.difference(now);
        } else {
          validTo = DateTime.now().add(const Duration(hours: 24));
          validFrom = DateTime.now();
          timeUntilInvalid = const Duration(hours: 24);
        }

        // CRL expiring soon threshold: 1 hour
        final isExpiringSoon =
            timeUntilInvalid.inHours <= 1 &&
            timeUntilInvalid.inHours >= 0 &&
            timeUntilInvalid.inMinutes >= 0;

        // Extract CRL extension data
        final crlNumber = crlInfo['crlNumber'] as String?;
        final authorityKeyIdentifier =
            crlInfo['authorityKeyIdentifier'] as String?;
        final issuingDistributionPoint =
            crlInfo['issuingDistributionPoint'] as String?;
        final isDeltaCrl = crlInfo['isDeltaCrl'] as bool? ?? false;
        final deltaCrlBaseNumber = crlInfo['deltaCrlBaseNumber'] as int?;
        final freshestCrlUrls = crlInfo['freshestCrlUrls'] != null
            ? List<String>.from(crlInfo['freshestCrlUrls'] as List)
            : null;

        validityInfo = CrlValidityInfo(
          validFrom: validFrom,
          validTo: validTo,
          timeUntilInvalid: timeUntilInvalid.isNegative
              ? Duration.zero
              : timeUntilInvalid,
          crlAge: crlAge,
          isExpiringSoon: isExpiringSoon,
          revokedCertificateCount: revokedCount,
          certificateAuthority: certificateAuthority,
          crlNumber: crlNumber,
          authorityKeyIdentifier: authorityKeyIdentifier,
          issuingDistributionPoint: issuingDistributionPoint,
          isDeltaCrl: isDeltaCrl,
          deltaCrlBaseNumber: deltaCrlBaseNumber,
          freshestCrlUrls: freshestCrlUrls,
          revocationReasonCounts:
              null, // Not processing revoked cert extensions
          invalidityDates: null, // Not processing revoked cert extensions
        );
      } catch (e) {
        // If parsing fails, set default validity
        final defaultTo = DateTime.now().add(const Duration(hours: 24));
        final nowDefault = DateTime.now();
        final timeUntilInvalidDefault = defaultTo.difference(nowDefault);
        // CRL expiring soon threshold: 1 hour
        final isExpiringSoonDefault =
            timeUntilInvalidDefault.inHours <= 1 &&
            timeUntilInvalidDefault.inHours >= 0;
        validityInfo = CrlValidityInfo(
          validFrom: DateTime.now(),
          validTo: defaultTo,
          timeUntilInvalid: const Duration(hours: 24),
          crlAge: Duration.zero,
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

  /// Top-level function for isolate execution (must be static)
  /// Parses a CRL file to extract issuer information and revoked certificate count
  static Map<String, dynamic> _parseCrlIsolate(List<int> crlBytes) {
    try {
      return _parseCrlInternal(crlBytes);
    } catch (e) {
      return <String, dynamic>{};
    }
  }

  /// Internal CRL parsing logic
  static Map<String, dynamic> _parseCrlInternal(List<int> crlBytes) {
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
              } else {
                // Issuer should be a sequence, but if it's not, still skip it
                elementIndex++;
              }
            }

            // Extract thisUpdate (UTCTime or GeneralizedTime)
            // TBSCertList: [version], signature, issuer, thisUpdate, nextUpdate, [revokedCertificates], [extensions]
            // thisUpdate should have tag 23 (UTCTime) or 24 (GeneralizedTime)
            // Keep looking until we find a time field (skip any unexpected sequences)
            while (tbsCertList.elements.length > elementIndex) {
              final thisUpdateElement = tbsCertList.elements[elementIndex];
              print(
                'DEBUG: Checking element at index $elementIndex: tag ${thisUpdateElement.tag}, type: ${thisUpdateElement.runtimeType}',
              );

              // Check if this is a time field (UTCTime=23, GeneralizedTime=24)
              if (thisUpdateElement.tag == 23 || thisUpdateElement.tag == 24) {
                final thisUpdateStr = _parseTime(thisUpdateElement);
                print('DEBUG: thisUpdate parsed: $thisUpdateStr');
                if (thisUpdateStr != null) {
                  result['thisUpdate'] = thisUpdateStr;
                  elementIndex++;
                  break; // Found thisUpdate, exit loop
                }
              } else if (thisUpdateElement is ASN1Sequence) {
                // This is not a time field - might be another DN or unexpected structure
                // Skip it and continue looking
                print(
                  'DEBUG: Skipping sequence element at index $elementIndex (not a time field)',
                );
                elementIndex++;
              } else {
                // Try to parse anyway (might be encoded differently)
                final thisUpdateStr = _parseTime(thisUpdateElement);
                if (thisUpdateStr != null) {
                  result['thisUpdate'] = thisUpdateStr;
                  elementIndex++;
                  break;
                } else {
                  // Not a time field and can't parse it - skip
                  elementIndex++;
                  break; // Don't infinite loop
                }
              }
            }

            // Extract nextUpdate (UTCTime or GeneralizedTime)
            // NextUpdate is MANDATORY per X.509 - it should always be present after thisUpdate
            // Standard CRL structure: ... thisUpdate, nextUpdate, [revokedCertificates], [extensions]
            if (tbsCertList.elements.length > elementIndex) {
              final nextUpdateElement = tbsCertList.elements[elementIndex];

              // Check if this is a time field (nextUpdate) or revokedCertificates (sequence)
              // Time fields are NOT sequences, revokedCertificates IS a sequence
              if (nextUpdateElement is ASN1Sequence) {
                // This is a sequence, so it's revokedCertificates, not nextUpdate
                // NextUpdate might be missing (malformed CRL) or we've already passed it
                // Don't increment - this will be handled in revokedCertificates section
              } else {
                // Not a sequence, so this should be nextUpdate time field
                // Parse as time using multiple methods
                print(
                  'DEBUG: nextUpdate element tag: ${nextUpdateElement.tag}, type: ${nextUpdateElement.runtimeType}',
                );
                String? nextUpdateStr = _parseTime(nextUpdateElement);
                print('DEBUG: nextUpdate parsed: $nextUpdateStr');

                // If direct parsing failed, try extracting from ASN1Object properties
                if (nextUpdateStr == null) {
                  try {
                    // Get the encoded bytes and try to extract time string
                    final valueBytes =
                        (nextUpdateElement as dynamic).valueBytes;
                    if (valueBytes != null && valueBytes is List<int>) {
                      final timeBytes = Uint8List.fromList(valueBytes);
                      final timeStr = String.fromCharCodes(timeBytes);
                      nextUpdateStr = _parseTime(timeStr);
                    }
                  } catch (_) {}

                  // Try toString method as fallback
                  if (nextUpdateStr == null) {
                    try {
                      final strRep = nextUpdateElement.toString();
                      // Remove any non-time parts from string representation
                      final cleanStr = strRep.replaceAll(RegExp(r'[^\dZ]'), '');
                      if (cleanStr.length >= 11) {
                        nextUpdateStr = _parseTime(cleanStr);
                      }
                    } catch (_) {}
                  }
                }

                if (nextUpdateStr != null) {
                  result['nextUpdate'] = nextUpdateStr;
                  elementIndex++; // Only increment if we successfully parsed nextUpdate
                } else {
                  // Parsing failed - this might not be nextUpdate after all
                  // But increment anyway to avoid getting stuck
                  elementIndex++;
                }
              }
            }

            // Extract revoked certificates (optional) - this is a Sequence of revoked certificates
            // Only count, don't process extensions to avoid too much information
            if (tbsCertList.elements.length > elementIndex) {
              final revokedCertificates = tbsCertList.elements[elementIndex];
              if (revokedCertificates is ASN1Sequence) {
                // Count revoked certificates - each revoked cert is a Sequence
                result['revokedCount'] = revokedCertificates.elements.length;
              } else {
                // No revoked certificates or empty sequence
                result['revokedCount'] = 0;
              }
              elementIndex++;
            } else {
              // No revoked certificates section at all
              result['revokedCount'] = 0;
            }

            // Extract CRL extensions (optional) - this is the last element (tagged [0] IMPLICIT Extensions)
            // Extensions can be at the end if present, and may be tagged
            while (tbsCertList.elements.length > elementIndex) {
              final potentialExtension = tbsCertList.elements[elementIndex];
              // Check if this is a tagged extension [0] - extensions are tagged [0] IMPLICIT
              final tag = potentialExtension.tag;
              if (tag == 0xA0 || tag == 0x80) {
                // This is likely the extensions element (tagged [0])
                _parseCrlExtensions(potentialExtension, result);
                break;
              } else if (potentialExtension is ASN1Sequence) {
                // Could be extensions sequence or something else - try parsing it
                final testResult = <String, dynamic>{};
                _parseCrlExtensions(potentialExtension, testResult);
                // If we found any extensions, merge them
                if (testResult.isNotEmpty &&
                    (testResult.containsKey('crlNumber') ||
                        testResult.containsKey('authorityKeyIdentifier') ||
                        testResult.containsKey('issuingDistributionPoint'))) {
                  result.addAll(testResult);
                  break;
                }
              }
              elementIndex++;
              // Safety check to prevent infinite loop
              if (elementIndex > tbsCertList.elements.length) break;
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
  static String _parseDistinguishedName(ASN1Sequence dnSequence) {
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
  static String _oidToName(String oid) {
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

  /// Parses UTCTime or GeneralizedTime to ISO8601 string
  static String? _parseTime(dynamic timeElement) {
    try {
      // CRL time fields are typically ASN1UTCTime (tag 23/0x17) or ASN1GeneralizedTime (tag 24/0x18)
      String? timeString;

      // First check if it's an ASN1Object and check the tag
      if (timeElement is ASN1Object) {
        // UTCTime tag is 23 (0x17), GeneralizedTime tag is 24 (0x18)
        if (timeElement.tag == 23 || timeElement.tag == 24) {
          print('DEBUG: Found time element with tag ${timeElement.tag}');

          // Try multiple methods to extract the time string
          // Method 1: Try contentBytes (this is usually where the value is stored)
          try {
            final contentBytes = (timeElement as dynamic).contentBytes;
            if (contentBytes != null &&
                contentBytes is List<int> &&
                contentBytes.isNotEmpty) {
              timeString = String.fromCharCodes(contentBytes);
              print('DEBUG: Method 1 (contentBytes): $timeString');
            }
          } catch (e) {
            print('DEBUG: Method 1 failed: $e');
          }

          // Method 2: Try valueBytes property
          if (timeString == null || timeString.isEmpty) {
            try {
              final valueBytes = (timeElement as dynamic).valueBytes;
              if (valueBytes != null &&
                  valueBytes is List<int> &&
                  valueBytes.isNotEmpty) {
                timeString = String.fromCharCodes(valueBytes);
                print('DEBUG: Method 2 (valueBytes): $timeString');
              }
            } catch (e) {
              print('DEBUG: Method 2 failed: $e');
            }
          }

          // Method 3: Try stringValue property (some ASN1 types have this)
          if (timeString == null || timeString.isEmpty) {
            try {
              final strVal = (timeElement as dynamic).stringValue;
              if (strVal != null && strVal is String && strVal.isNotEmpty) {
                timeString = strVal;
                print('DEBUG: Method 3 (stringValue): $timeString');
              }
            } catch (e) {
              print('DEBUG: Method 3 failed: $e');
            }
          }

          // Method 4: Extract from encodedBytes (skip tag and length)
          if (timeString == null || timeString.isEmpty) {
            try {
              final encodedBytes = (timeElement as dynamic).encodedBytes;
              if (encodedBytes != null &&
                  encodedBytes is List<int> &&
                  encodedBytes.length > 2) {
                // Find the value portion by skipping tag and length
                int offset = 1; // Skip tag byte
                if (encodedBytes.length > offset) {
                  int lenByte = encodedBytes[offset];
                  if (lenByte & 0x80 == 0) {
                    // Short form - length in single byte
                    offset += 1;
                  } else {
                    // Long form - skip length bytes
                    int lenLen = lenByte & 0x7F;
                    if (lenLen > 0 && lenLen <= 4) {
                      offset += 1 + lenLen;
                    } else {
                      offset = 1; // Fallback to assuming short form
                    }
                  }
                  if (offset < encodedBytes.length) {
                    timeString = String.fromCharCodes(
                      encodedBytes.sublist(offset),
                    );
                    print('DEBUG: Method 4 (encodedBytes): $timeString');
                  }
                }
              }
            } catch (e) {
              print('DEBUG: Method 4 failed: $e');
            }
          }

          // Method 5: Try toString() and extract time pattern
          if (timeString == null || timeString.isEmpty) {
            try {
              final strRep = timeElement.toString();
              print('DEBUG: Method 5 (toString): $strRep');
              // Extract time pattern from string representation
              // Look for patterns like: 251102222449Z or 20251102222449Z
              final timeMatch = RegExp(r'(\d{11,15}Z?)').firstMatch(strRep);
              if (timeMatch != null) {
                timeString = timeMatch.group(1);
                print('DEBUG: extracted timeString from toString: $timeString');
              }
            } catch (e) {
              print('DEBUG: Method 5 failed: $e');
            }
          }

          if (timeString != null && timeString.isNotEmpty) {
            print('DEBUG: Final timeString from tag check: $timeString');
          } else {
            print('DEBUG: Failed to extract timeString from time element');
          }
        }
      }

      // Fallback to string types
      if (timeString == null || timeString.isEmpty) {
        if (timeElement is ASN1PrintableString) {
          timeString = timeElement.stringValue;
        } else if (timeElement is ASN1IA5String) {
          timeString = timeElement.stringValue;
        } else if (timeElement is ASN1UTF8String) {
          timeString = timeElement.utf8StringValue;
        } else if (timeElement is ASN1BMPString) {
          timeString = timeElement.stringValue;
        } else if (timeElement is ASN1OctetString) {
          final bytes = timeElement.octets;
          if (bytes.isNotEmpty) {
            timeString = String.fromCharCodes(bytes);
          }
        } else if (timeElement is ASN1Object) {
          // Try toString() as fallback
          try {
            final str = timeElement.toString();
            if (str.isNotEmpty && str.contains(RegExp(r'\d'))) {
              timeString = str;
            }
          } catch (_) {}
        } else if (timeElement is ASN1Sequence) {
          // Try to extract from sequence
          for (final element in timeElement.elements) {
            final result = _parseTime(element);
            if (result != null) return result;
          }
          return null;
        }
      }

      if (timeString == null || timeString.isEmpty) {
        return null;
      }

      // Clean up the time string
      // Remove any whitespace and non-time characters, but keep digits, Z, +, -, and :
      timeString = timeString.trim();
      print('DEBUG: timeString after fallback: $timeString');

      // Extract time pattern - handle formats like:
      // YYMMDDHHMMSSZ, YYMMDDHHMMZ (UTCTime)
      // YYYYMMDDHHMMSSZ, YYYYMMDDHHMMSS+/-HHMM (GeneralizedTime)
      String cleanedTime = timeString.replaceAll(RegExp(r'[^\dZ\+\-:]'), '');
      print('DEBUG: cleanedTime: $cleanedTime');

      try {
        // First, try to identify the format by length and structure
        // UTCTime: YYMMDDHHMMSSZ (13 chars) or YYMMDDHHMMZ (11 chars)
        // GeneralizedTime: YYYYMMDDHHMMSSZ (15+ chars)

        // Check for UTCTime format first (most common for dates before 2050)
        // UTCTime always starts with 2-digit year
        // Format: YYMMDDHHMMSSZ (13 chars) or YYMMDDHHMMZ (11 chars)
        if (cleanedTime.length == 13 && cleanedTime.endsWith('Z')) {
          // Strict UTCTime format with seconds: YYMMDDHHMMSSZ
          final match = RegExp(
            r'^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$',
          ).firstMatch(cleanedTime);
          if (match != null) {
            final year = int.parse(match.group(1)!);
            final month = int.parse(match.group(2)!);
            final day = int.parse(match.group(3)!);
            final hour = int.parse(match.group(4)!);
            final minute = int.parse(match.group(5)!);
            final second = int.parse(match.group(6)!);

            // Validate all values are reasonable
            if (month >= 1 &&
                month <= 12 &&
                day >= 1 &&
                day <= 31 &&
                hour < 24 &&
                minute < 60 &&
                second < 60) {
              // UTCTime years are 2-digit: 00-49 = 2000-2049, 50-99 = 1950-1999
              final fullYear = year < 50 ? 2000 + year : 1900 + year;
              final dateTime = DateTime.utc(
                fullYear,
                month,
                day,
                hour,
                minute,
                second,
              );
              print(
                'DEBUG: Parsed as UTCTime (13 chars): $dateTime (from $cleanedTime)',
              );
              return dateTime.toIso8601String();
            }
          }
        } else if (cleanedTime.length == 11 &&
            (cleanedTime.endsWith('Z') || !cleanedTime.contains('Z'))) {
          // UTCTime format without seconds: YYMMDDHHMMZ or YYMMDDHHMM
          final match = RegExp(
            r'^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z?$',
          ).firstMatch(cleanedTime);
          if (match != null) {
            final year = int.parse(match.group(1)!);
            final month = int.parse(match.group(2)!);
            final day = int.parse(match.group(3)!);
            final hour = int.parse(match.group(4)!);
            final minute = int.parse(match.group(5)!);

            // Validate all values are reasonable
            if (month >= 1 &&
                month <= 12 &&
                day >= 1 &&
                day <= 31 &&
                hour < 24 &&
                minute < 60) {
              // UTCTime years are 2-digit: 00-49 = 2000-2049, 50-99 = 1950-1999
              final fullYear = year < 50 ? 2000 + year : 1900 + year;
              final dateTime = DateTime.utc(
                fullYear,
                month,
                day,
                hour,
                minute,
                0, // seconds default to 0
              );
              print(
                'DEBUG: Parsed as UTCTime (11 chars): $dateTime (from $cleanedTime)',
              );
              return dateTime.toIso8601String();
            }
          }
        }

        // Check for GeneralizedTime format (15+ characters with 4-digit year)
        if (cleanedTime.length >= 15) {
          // GeneralizedTime format: YYYYMMDDHHMMSSZ or YYYYMMDDHHMMSS+/-HHMM
          final match = RegExp(
            r'^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})',
          ).firstMatch(cleanedTime);
          if (match != null) {
            final year = int.parse(match.group(1)!);
            final month = int.parse(match.group(2)!);
            final day = int.parse(match.group(3)!);
            final hour = int.parse(match.group(4)!);
            final minute = int.parse(match.group(5)!);
            final second = int.parse(match.group(6)!);

            // Validate year is reasonable (between 1950 and 2100)
            if (year >= 1950 &&
                year <= 2100 &&
                month >= 1 &&
                month <= 12 &&
                day >= 1 &&
                day <= 31 &&
                hour < 24 &&
                minute < 60 &&
                second < 60) {
              final dateTime = DateTime.utc(
                year,
                month,
                day,
                hour,
                minute,
                second,
              );
              print(
                'DEBUG: Parsed as GeneralizedTime: $dateTime (from $cleanedTime)',
              );
              return dateTime.toIso8601String();
            }
          }
        }

        // Last resort: try to find a valid date pattern anywhere in the string
        // Look for UTCTime pattern (11 or 13 digits) anywhere
        final utcMatch = RegExp(
          r'(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?',
        ).firstMatch(cleanedTime);
        if (utcMatch != null) {
          final year = int.parse(utcMatch.group(1)!);
          final month = int.parse(utcMatch.group(2)!);
          final day = int.parse(utcMatch.group(3)!);
          final hour = int.parse(utcMatch.group(4)!);
          final minute = int.parse(utcMatch.group(5)!);
          final second =
              utcMatch.group(6) != null && utcMatch.group(6)!.isNotEmpty
              ? int.parse(utcMatch.group(6)!)
              : 0;

          // Validate values are reasonable
          if (month >= 1 &&
              month <= 12 &&
              day >= 1 &&
              day <= 31 &&
              hour < 24 &&
              minute < 60 &&
              second < 60 &&
              year < 100) {
            final fullYear = year < 50 ? 2000 + year : 1900 + year;
            final dateTime = DateTime.utc(
              fullYear,
              month,
              day,
              hour,
              minute,
              second,
            );
            print(
              'DEBUG: Parsed as UTCTime (fallback): $dateTime (from $cleanedTime)',
            );
            return dateTime.toIso8601String();
          }
        }
      } catch (e) {
        // Log error for debugging if needed
        print('Error parsing time string "$timeString": $e');
      }
    } catch (e) {
      print('Error in _parseTime: $e');
    }
    return null;
  }

  /// Parses CRL-level extensions
  static void _parseCrlExtensions(
    dynamic extensionsElement,
    Map<String, dynamic> result,
  ) {
    try {
      // Extensions are typically in a tagged sequence [0] IMPLICIT Extensions
      ASN1Sequence? extensionsSeq;

      if (extensionsElement is ASN1Sequence) {
        extensionsSeq = extensionsElement;
      } else if (extensionsElement is ASN1Object) {
        // Tagged objects - try to access the content
        // Tagged [0] IMPLICIT Extensions means the sequence is inside
        try {
          // Try casting directly - sometimes tagged objects ARE sequences
          if (extensionsElement is ASN1Sequence) {
            extensionsSeq = extensionsElement;
          } else {
            // For tagged objects, try to access elements if available
            // Some implementations expose elements directly
            try {
              final elements = (extensionsElement as dynamic).elements;
              if (elements != null && elements is List && elements.isNotEmpty) {
                // If we can access elements directly, try the first one
                if (elements[0] is ASN1Sequence) {
                  extensionsSeq = elements[0] as ASN1Sequence;
                }
              }
            } catch (_) {}

            // Alternative: try to get the encoded content and reparse
            try {
              final encodedBytes = (extensionsElement as dynamic).encodedBytes;
              if (encodedBytes != null && encodedBytes is List<int>) {
                // Reparse the bytes as a sequence
                final parser = ASN1Parser(Uint8List.fromList(encodedBytes));
                final parsed = parser.nextObject();
                if (parsed is ASN1Sequence) {
                  extensionsSeq = parsed;
                }
              }
            } catch (_) {}
          }
        } catch (_) {}
      }

      if (extensionsSeq == null) return;

      // Extensions ::= SEQUENCE OF Extension
      // Extension ::= SEQUENCE {
      //   extnID      OBJECT IDENTIFIER,
      //   critical   BOOLEAN DEFAULT FALSE,
      //   extnValue   OCTET STRING
      // }

      for (final extension in extensionsSeq.elements) {
        if (extension is! ASN1Sequence || extension.elements.isEmpty) continue;

        final extnID = extension.elements[0];
        if (extnID is! ASN1ObjectIdentifier) continue;

        final oid = extnID.toString();
        dynamic extnValue;

        // Check if critical is present (2nd element might be boolean)
        int valueIndex = 1;
        if (extension.elements.length > 1 &&
            extension.elements[1] is ASN1Boolean) {
          valueIndex = 2; // Skip critical boolean
        }

        if (extension.elements.length > valueIndex) {
          extnValue = extension.elements[valueIndex];
        }

        switch (oid) {
          case '2.5.29.20': // CRL Number
            if (extnValue is ASN1OctetString) {
              final bytes = extnValue.octets;
              if (bytes.isNotEmpty) {
                // CRL Number is a hex string, not an integer
                final hexString = bytes
                    .map((b) => b.toRadixString(16).padLeft(2, '0'))
                    .join();
                result['crlNumber'] = hexString;
              }
            }
            break;

          case '2.5.29.35': // Authority Key Identifier
            if (extnValue is ASN1OctetString) {
              final bytes = extnValue.octets;
              if (bytes.isNotEmpty) {
                // AuthorityKeyIdentifier is a SEQUENCE, but we'll just show hex for now
                result['authorityKeyIdentifier'] = bytes
                    .map((b) => b.toRadixString(16).padLeft(2, '0'))
                    .join(':');
              }
            }
            break;

          case '2.5.29.28': // Issuing Distribution Point
            if (extnValue is ASN1OctetString) {
              // DistributionPointName is complex, but we can try to extract URIs
              try {
                final bytes = extnValue.octets;
                if (bytes.isNotEmpty) {
                  final parser = ASN1Parser(Uint8List.fromList(bytes));
                  final distPointSeq = parser.nextObject();
                  if (distPointSeq is ASN1Sequence) {
                    // Try to extract distributionPointName
                    result['issuingDistributionPoint'] =
                        'Present'; // Simplified for now
                  }
                }
              } catch (_) {}
            }
            break;

          case '2.5.29.46': // Delta CRL Indicator
            if (extnValue is ASN1OctetString) {
              final bytes = extnValue.octets;
              if (bytes.isNotEmpty) {
                result['isDeltaCrl'] = true;
                // Decode base CRL number
                int baseNumber = 0;
                for (final byte in bytes) {
                  baseNumber = (baseNumber << 8) | byte;
                }
                result['deltaCrlBaseNumber'] = baseNumber;
              }
            }
            break;

          case '2.5.29.47': // Freshest CRL (Delta CRL Distribution Point)
            if (extnValue is ASN1OctetString) {
              try {
                final bytes = extnValue.octets;
                if (bytes.isNotEmpty) {
                  final parser = ASN1Parser(Uint8List.fromList(bytes));
                  final distPoints = parser.nextObject();
                  final urls = <String>[];
                  // Extract URIs from DistributionPoint sequence
                  _extractDistributionPointUrls(distPoints, urls);
                  if (urls.isNotEmpty) {
                    result['freshestCrlUrls'] = urls;
                  }
                }
              } catch (_) {}
            }
            break;

          // Vendor-specific OIDs (X.509 extensions)
          case '2.16.840.1.113741.2.1.2.1.4': // X509V1CRLThisUpdate
            // Note: ThisUpdate should come from standard CRL structure, not extensions
            // But parse this in case it's provided as additional info
            if (extnValue is ASN1OctetString) {
              final dateStr = _parseTime(extnValue);
              if (dateStr != null && result['thisUpdate'] == null) {
                // Only use if we don't already have thisUpdate from standard location
                result['thisUpdate'] = dateStr;
              }
            }
            break;

          case '2.16.840.1.113741.2.1.2.1.5': // X509V1CRLNextUpdate
            // Note: NextUpdate should come from standard CRL structure location
            // Vendor-specific extension may contain different data format
            // Skip this - use standard structure parsing instead
            break;

          case '2.16.840.1.113741.2.1.2.1.6': // X509V1CRLNumberOfRevokedCertEntries
            if (extnValue is ASN1OctetString) {
              final bytes = extnValue.octets;
              if (bytes.isNotEmpty) {
                // Decode as integer (big-endian)
                int number = 0;
                for (final byte in bytes) {
                  number = (number << 8) | byte;
                }
                result['revokedCount'] =
                    number; // Override with vendor-specific value
              }
            }
            break;
        }
      }
    } catch (_) {
      // Silently fail if extension parsing fails
    }
  }

  /// Extracts URIs from DistributionPoint structure
  static void _extractDistributionPointUrls(
    dynamic distPoint,
    List<String> urls,
  ) {
    try {
      if (distPoint is ASN1Sequence) {
        for (final element in distPoint.elements) {
          // Check for tagged objects by tag value
          if (element is ASN1Sequence && element.tag == 0xA0) {
            // fullName - GeneralNames (tagged [0])
            _extractGeneralNames(element, urls);
          }
        }
      }
    } catch (_) {}
  }

  /// Extracts URIs from GeneralNames
  static void _extractGeneralNames(dynamic generalNames, List<String> urls) {
    try {
      if (generalNames is ASN1Sequence) {
        for (final name in generalNames.elements) {
          // uniformResourceIdentifier [6] IA5String
          if (name.tag == 0x86) {
            if (name is ASN1IA5String) {
              urls.add(name.stringValue);
            } else if (name is ASN1OctetString) {
              final bytes = name.octets;
              urls.add(String.fromCharCodes(bytes));
            } else if (name is ASN1Sequence) {
              // Try to extract from sequence
              for (final item in name.elements) {
                if (item is ASN1IA5String) {
                  urls.add(item.stringValue);
                }
              }
            }
          }
        }
      }
    } catch (_) {}
  }
}
