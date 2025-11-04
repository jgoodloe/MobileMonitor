import 'package:dio/dio.dart';
import 'package:asn1lib/asn1lib.dart';
import 'package:flutter/foundation.dart';
import '../models/monitor_status.dart';
import 'configuration_manager.dart';

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
      List<String> parsingLogsList = [];
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
      DateTime? validFrom;
      DateTime? validTo;
      String? crlNumber;

      print('DEBUG CRL: Starting CRL verification for: $crlUrl');
      print('DEBUG CRL: CRL bytes received: ${crlBytes.length} bytes');

      try {
        print('DEBUG CRL: Starting CRL parsing in isolate...');
        // Get setting for counting revoked certificates
        final configManager = ConfigurationManager();
        final countRevoked = await configManager.getCountRevokedCertificates();
        print('DEBUG CRL: Count revoked certificates setting: $countRevoked');

        // Parse the CRL file to extract issuer (Certificate Authority) and revoked certificates
        // Use compute() to run parsing in isolate to avoid blocking UI thread
        final crlInfo = await compute(_parseCrlIsolate, {
          'crlBytes': crlBytes,
          'countRevoked': countRevoked,
        });
        print(
          'DEBUG CRL: Parsing complete. Result keys: ${crlInfo.keys.toList()}',
        );
        print('DEBUG CRL: Full result map: $crlInfo');

        certificateAuthority = crlInfo['issuer'] as String?;
        revokedCount = crlInfo['revokedCount'] as int?;
        crlNumber = crlInfo['crlNumber'] as String?;
        parsingLogsList =
            (crlInfo['parsingLogs'] as List<dynamic>?)
                ?.map((e) => e.toString())
                .toList() ??
            <String>[];

        print('DEBUG CRL: Extracted issuer: $certificateAuthority');
        print('DEBUG CRL: Extracted revokedCount: $revokedCount');
        print('DEBUG CRL: Extracted crlNumber: $crlNumber');

        // Parse thisUpdate and nextUpdate as DateTime
        final thisUpdateStr = crlInfo['thisUpdate'] as String?;
        print('DEBUG CRL: Extracted thisUpdate string: $thisUpdateStr');
        if (thisUpdateStr != null) {
          try {
            validFrom = DateTime.parse(thisUpdateStr);
            print('DEBUG CRL: Parsed validFrom: $validFrom');
          } catch (e) {
            print('DEBUG CRL: Failed to parse thisUpdate: $e');
          }
        }

        final nextUpdateStr = crlInfo['nextUpdate'] as String?;
        print('DEBUG CRL: Extracted nextUpdate string: $nextUpdateStr');
        if (nextUpdateStr != null) {
          try {
            validTo = DateTime.parse(nextUpdateStr);
            print('DEBUG CRL: Parsed validTo: $validTo');
          } catch (e) {
            print('DEBUG CRL: Failed to parse nextUpdate: $e');
          }
        }
      } catch (e, stackTrace) {
        print('DEBUG CRL: Exception during CRL parsing: $e');
        print('DEBUG CRL: Stack trace: $stackTrace');
        // If parsing fails, all fields remain null
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
      print(
        'DEBUG CRL: Before fallbacks - certificateAuthority: $certificateAuthority',
      );
      if (certificateAuthority == null || certificateAuthority.isEmpty) {
        try {
          final uri = Uri.parse(crlUrl);
          if (uri.host.isNotEmpty && !isIpAddress(uri.host)) {
            certificateAuthority = uri.host;
            print(
              'DEBUG CRL: Fallback 1 - Using hostname: $certificateAuthority',
            );
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
              print(
                'DEBUG CRL: Fallback 2 - Using filename: $certificateAuthority',
              );

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
        } catch (e) {
          print('DEBUG CRL: Exception in filename fallback: $e');
          // If still null, leave it as null
        }
      }

      print('DEBUG CRL: Final certificateAuthority: $certificateAuthority');

      // Create CrlValidityInfo with parsed data
      if (validFrom != null ||
          validTo != null ||
          certificateAuthority != null ||
          revokedCount != null ||
          crlNumber != null) {
        // Calculate time until invalid
        Duration? timeUntilInvalid;
        bool isExpiringSoon = false;

        if (validTo != null) {
          final now = DateTime.now();
          timeUntilInvalid = validTo.difference(now);
          // CRL expiring soon threshold: 1 hour
          isExpiringSoon =
              timeUntilInvalid.inHours <= 1 &&
              timeUntilInvalid.inHours >= 0 &&
              timeUntilInvalid.inMinutes >= 0;
        }

        print('DEBUG CRL: Creating CrlValidityInfo:');
        print('DEBUG CRL:   validFrom: $validFrom');
        print('DEBUG CRL:   validTo: $validTo');
        print('DEBUG CRL:   certificateAuthority: $certificateAuthority');
        print('DEBUG CRL:   revokedCount: $revokedCount');
        print('DEBUG CRL:   crlNumber: $crlNumber');
        print('DEBUG CRL:   timeUntilInvalid: $timeUntilInvalid');
        print('DEBUG CRL:   isExpiringSoon: $isExpiringSoon');

        validityInfo = CrlValidityInfo(
          validFrom: validFrom,
          validTo: validTo,
          timeUntilInvalid:
              (timeUntilInvalid != null && timeUntilInvalid.isNegative)
              ? Duration.zero
              : timeUntilInvalid,
          isExpiringSoon: isExpiringSoon,
          revokedCertificateCount: revokedCount,
          certificateAuthority: certificateAuthority,
          crlNumber: crlNumber,
          parsingLogs: parsingLogsList,
        );
        print('DEBUG CRL: CrlValidityInfo created successfully');
      } else {
        print(
          'DEBUG CRL: No validity info fields populated, CrlValidityInfo will be null',
        );
      }

      /* try {
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
        // Default CRL validity: 24 hours from now
        validTo ??= DateTime.now().add(const Duration(hours: 24));
        
        validFrom ??= DateTime.now();
        
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
      } */

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
  static Map<String, dynamic> _parseCrlIsolate(Map<String, dynamic> params) {
    final logs = <String>[];
    try {
      final crlBytes = params['crlBytes'] as List<int>;
      final countRevoked = params['countRevoked'] as bool? ?? true;
      final result = _parseCrlInternal(
        crlBytes,
        countRevoked: countRevoked,
        logs: logs,
      );
      result['parsingLogs'] = logs;
      return result;
    } catch (e) {
      logs.add('Error parsing CRL: $e');
      return {'parsingLogs': logs};
    }
  }

  /// Internal CRL parsing logic
  static Map<String, dynamic> _parseCrlInternal(
    List<int> crlBytes, {
    bool countRevoked = true,
    List<String>? logs,
  }) {
    final result = <String, dynamic>{};
    final parsingLogs = logs ?? <String>[];
    print(
      'DEBUG CRL PARSE: Starting _parseCrlInternal with ${crlBytes.length} bytes',
    );
    parsingLogs.add('Parsing CRL binary data (${crlBytes.length} bytes)');

    try {
      // Limit parsing to reasonable file sizes (max 10MB)
      if (crlBytes.length > 10 * 1024 * 1024) {
        print('DEBUG CRL PARSE: File too large, skipping');
        return result;
      }

      // Parse the CRL using ASN1 - convert List<int> to Uint8List
      final bytes = Uint8List.fromList(crlBytes);
      final asn1Parser = ASN1Parser(bytes);
      final topLevelSeq = asn1Parser.nextObject();
      print(
        'DEBUG CRL PARSE: Parsed top level sequence type: ${topLevelSeq.runtimeType}',
      );

      if (topLevelSeq is! ASN1Sequence) {
        print(
          'DEBUG CRL PARSE: Top level is not ASN1Sequence, returning empty',
        );
        return result;
      }

      final seq = topLevelSeq;
      if (seq.elements.isEmpty) {
        print('DEBUG CRL PARSE: Top level sequence is empty, returning empty');
        return result;
      }
      print(
        'DEBUG CRL PARSE: Top level sequence has ${seq.elements.length} elements',
      );

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

            // Skip signature algorithm (AlgorithmIdentifier) - it's a Sequence [OID, Parameters]
            if (tbsCertList.elements.length > elementIndex) {
              final sigAlgElement = tbsCertList.elements[elementIndex];
              print(
                'DEBUG CRL PARSE: Signature algorithm element type: ${sigAlgElement.runtimeType}, tag: ${sigAlgElement.tag}',
              );
              elementIndex++; // Skip signature
            }

            // Extract issuer (Distinguished Name) - this is a Sequence
            print(
              'DEBUG CRL PARSE: tbsCertList has ${tbsCertList.elements.length} elements, elementIndex: $elementIndex',
            );

            if (tbsCertList.elements.length > elementIndex) {
              final issuerElement = tbsCertList.elements[elementIndex];
              print(
                'DEBUG CRL PARSE: Issuer element at index $elementIndex, type: ${issuerElement.runtimeType}, tag: ${issuerElement.tag}',
              );
              print(
                'DEBUG CRL PARSE: Issuer element toString: ${issuerElement.toString()}',
              );

              // The issuer DN is a Name type, which is a SEQUENCE OF RelativeDistinguishedName
              // RelativeDistinguishedName is a SET OF AttributeTypeAndValue
              if (issuerElement is ASN1Sequence) {
                // Check if this sequence contains Sets (which would indicate it's the DN)
                final hasSets = issuerElement.elements.any((e) => e is ASN1Set);
                print(
                  'DEBUG CRL PARSE: Issuer sequence has ${issuerElement.elements.length} elements, contains Sets: $hasSets',
                );

                if (hasSets || issuerElement.elements.length > 2) {
                  // This looks like a DN structure
                  print('DEBUG CRL PARSE: Parsing Distinguished Name...');
                  final issuerDn = _parseDistinguishedName(issuerElement);
                  print('DEBUG CRL PARSE: Parsed issuer DN: $issuerDn');
                  if (issuerDn.isNotEmpty) {
                    result['issuer'] = issuerDn;
                    parsingLogs.add('Parsed issuer DN: $issuerDn');
                  }
                  elementIndex++;
                } else {
                  print(
                    'DEBUG CRL PARSE: Issuer sequence doesn\'t look like a DN, might be signature algorithm, skipping...',
                  );
                  elementIndex++; // Skip and try next element
                }
              } else {
                print(
                  'DEBUG CRL PARSE: Issuer element is not ASN1Sequence, type: ${issuerElement.runtimeType}',
                );
                // Still increment to avoid getting stuck
                elementIndex++;
              }
            } else {
              print(
                'DEBUG CRL PARSE: No issuer element found (elementIndex $elementIndex >= ${tbsCertList.elements.length})',
              );
            }

            // Extract thisUpdate (UTCTime or GeneralizedTime)
            if (tbsCertList.elements.length > elementIndex) {
              final thisUpdateElement = tbsCertList.elements[elementIndex];
              print(
                'DEBUG CRL PARSE: thisUpdate element at index $elementIndex, type: ${thisUpdateElement.runtimeType}',
              );
              print(
                'DEBUG CRL PARSE: thisUpdate element toString: ${thisUpdateElement.toString()}',
              );

              // Check if this might actually be the issuer DN (if we didn't find it earlier)
              bool processedIssuerAtThisPosition = false;
              if (thisUpdateElement is ASN1Sequence &&
                  result['issuer'] == null) {
                final hasSets = thisUpdateElement.elements.any(
                  (e) => e is ASN1Set,
                );
                if (hasSets) {
                  print(
                    'DEBUG CRL PARSE: thisUpdate position contains DN structure, parsing as issuer...',
                  );
                  final issuerDn = _parseDistinguishedName(thisUpdateElement);
                  if (issuerDn.isNotEmpty) {
                    result['issuer'] = issuerDn;
                    parsingLogs.add('Parsed issuer DN: $issuerDn');
                    print(
                      'DEBUG CRL PARSE: Found issuer DN at thisUpdate position: $issuerDn',
                    );
                    elementIndex++;
                    processedIssuerAtThisPosition = true;
                    // Continue to next element for actual thisUpdate
                    if (tbsCertList.elements.length > elementIndex) {
                      final actualThisUpdate =
                          tbsCertList.elements[elementIndex];
                      print(
                        'DEBUG CRL PARSE: Actual thisUpdate at index $elementIndex, type: ${actualThisUpdate.runtimeType}',
                      );
                      final thisUpdateStr = _parseTime(actualThisUpdate);
                      if (thisUpdateStr != null) {
                        print(
                          'DEBUG CRL PARSE: Parsed thisUpdate: $thisUpdateStr',
                        );
                        result['thisUpdate'] = thisUpdateStr;
                        parsingLogs.add('Parsed thisUpdate: $thisUpdateStr');
                      }
                      elementIndex++;
                    }
                  }
                }
              }

              if (!processedIssuerAtThisPosition) {
                final thisUpdateStr = _parseTime(thisUpdateElement);
                if (thisUpdateStr != null) {
                  print('DEBUG CRL PARSE: Parsed thisUpdate: $thisUpdateStr');
                  result['thisUpdate'] = thisUpdateStr;
                  parsingLogs.add('Parsed thisUpdate: $thisUpdateStr');
                } else {
                  print('DEBUG CRL PARSE: Failed to parse thisUpdate');
                }
                elementIndex++;
              }
            }

            // Extract nextUpdate (UTCTime or GeneralizedTime)
            if (tbsCertList.elements.length > elementIndex) {
              final nextUpdateElement = tbsCertList.elements[elementIndex];
              print(
                'DEBUG CRL PARSE: nextUpdate element type: ${nextUpdateElement.runtimeType}',
              );
              final nextUpdateStr = _parseTime(nextUpdateElement);
              if (nextUpdateStr != null) {
                print('DEBUG CRL PARSE: Parsed nextUpdate: $nextUpdateStr');
                result['nextUpdate'] = nextUpdateStr;
                parsingLogs.add('Parsed nextUpdate: $nextUpdateStr');
              } else {
                print('DEBUG CRL PARSE: Failed to parse nextUpdate');
              }
              elementIndex++;
            }

            // Extract revoked certificates (optional) - this is a Sequence of revoked certificates
            if (tbsCertList.elements.length > elementIndex) {
              final revokedCertificates = tbsCertList.elements[elementIndex];
              print(
                'DEBUG CRL PARSE: Revoked certificates element type: ${revokedCertificates.runtimeType}',
              );
              if (revokedCertificates is ASN1Sequence) {
                if (countRevoked) {
                  // Count revoked certificates - each revoked cert is a Sequence
                  final revokedCount = revokedCertificates.elements.length;
                  result['revokedCount'] = revokedCount;
                  parsingLogs.add(
                    'Found $revokedCount revoked certificates in CRL',
                  );
                  print(
                    'DEBUG CRL PARSE: Found ${revokedCertificates.elements.length} revoked certificates',
                  );
                } else {
                  parsingLogs.add(
                    'Skipping revoked certificate count (disabled in settings)',
                  );
                  print(
                    'DEBUG CRL PARSE: Skipping revoked certificate count (disabled in settings)',
                  );
                }
                elementIndex++;
              }
            }

            // Extract extensions (optional) - context-specific [0] EXPLICIT Extensions
            // Check remaining elements for tagged extension (tag 0)
            for (
              int extIdx = elementIndex;
              extIdx < tbsCertList.elements.length;
              extIdx++
            ) {
              final potentialExtElement = tbsCertList.elements[extIdx];
              print(
                'DEBUG CRL PARSE: Checking element $extIdx for extensions, type: ${potentialExtElement.runtimeType}, tag: ${potentialExtElement.tag}',
              );

              // Extensions are tagged as [0] EXPLICIT, which means they may be wrapped
              // Check if this is a tagged element with tag 0 (context-specific)
              // Tag 0xA0 = context-specific [0] constructed, tag 0x80 = context-specific [0] primitive
              ASN1Sequence? extensionsSequence;

              // Check for context-specific tag [0] (0xA0 for constructed, 0x80 for primitive)
              final isTaggedZero =
                  (potentialExtElement.tag & 0xE0) == 0xA0 ||
                  (potentialExtElement.tag & 0xE0) == 0x80 ||
                  potentialExtElement.tag == 0xA0 ||
                  potentialExtElement.tag == 0x80 ||
                  potentialExtElement.tag == 0;

              if (isTaggedZero) {
                // This is a context-specific tag [0], which wraps the Extensions sequence
                print(
                  'DEBUG CRL PARSE: Found tagged element with tag ${potentialExtElement.tag} (hex: 0x${potentialExtElement.tag.toRadixString(16)}), extracting inner sequence...',
                );

                // For EXPLICIT tagging, the tag wraps the SEQUENCE
                // The asn1lib should decode it, so check if it's already a sequence
                if (potentialExtElement is ASN1Sequence) {
                  extensionsSequence = potentialExtElement;
                  print(
                    'DEBUG CRL PARSE: Tagged element is already ASN1Sequence',
                  );
                } else {
                  // Try to extract the inner sequence from the tagged wrapper
                  // For EXPLICIT [0], structure is: [0] { length, SEQUENCE { ... } }
                  // We need to parse the encoded bytes to get the inner SEQUENCE
                  try {
                    final octets = potentialExtElement.encodedBytes;
                    print(
                      'DEBUG CRL PARSE: Tagged element encoded bytes length: ${octets.length}',
                    );
                    if (octets.isNotEmpty) {
                      // Parse from the bytes, skipping the outer tag wrapper
                      int offset = 0;

                      // Check for tag 0xA0 (context-specific [0] constructed)
                      if (offset < octets.length && octets[offset] == 0xA0) {
                        offset++; // Skip tag byte
                        print(
                          'DEBUG CRL PARSE: Skipped tag byte, offset now: $offset',
                        );

                        // Parse DER length encoding
                        if (offset < octets.length) {
                          int lenByte = octets[offset];
                          if (lenByte & 0x80 == 0) {
                            // Short form: single byte length
                            offset += 1;
                            print(
                              'DEBUG CRL PARSE: Short form length: $lenByte, offset now: $offset',
                            );
                          } else {
                            // Long form: multi-byte length
                            int lenLen = lenByte & 0x7F;
                            if (lenLen > 0 &&
                                lenLen <= 4 &&
                                offset + 1 + lenLen < octets.length) {
                              offset += 1 + lenLen;
                              print(
                                'DEBUG CRL PARSE: Long form length, lenLen: $lenLen, offset now: $offset',
                              );
                            } else {
                              print(
                                'DEBUG CRL PARSE: Invalid long form length encoding',
                              );
                              offset = octets.length; // Skip this attempt
                            }
                          }
                        }

                        // Now parse the inner SEQUENCE (content after tag and length)
                        if (offset < octets.length) {
                          final innerBytes = octets.sublist(offset);
                          print(
                            'DEBUG CRL PARSE: Attempting to parse inner sequence, bytes length: ${innerBytes.length}',
                          );
                          try {
                            final parser = ASN1Parser(
                              Uint8List.fromList(innerBytes),
                            );
                            final parsed = parser.nextObject();
                            print(
                              'DEBUG CRL PARSE: Parsed inner object type: ${parsed.runtimeType}, tag: ${parsed.tag}',
                            );
                            if (parsed is ASN1Sequence) {
                              extensionsSequence = parsed;
                              print(
                                'DEBUG CRL PARSE: Successfully parsed inner sequence from tagged wrapper bytes, sequence has ${extensionsSequence.elements.length} elements',
                              );
                            } else {
                              print(
                                'DEBUG CRL PARSE: Inner object is not ASN1Sequence: ${parsed.runtimeType}',
                              );
                            }
                          } catch (parseError) {
                            print(
                              'DEBUG CRL PARSE: Failed to parse inner bytes as ASN1: $parseError',
                            );
                          }
                        } else {
                          print(
                            'DEBUG CRL PARSE: Offset >= octets.length, cannot parse inner sequence',
                          );
                        }
                      } else {
                        print(
                          'DEBUG CRL PARSE: First byte is not 0xA0: 0x${octets.isNotEmpty ? octets[0].toRadixString(16) : "empty"}',
                        );
                        // Try parsing the entire octets as a sequence (maybe the tag was already stripped)
                        try {
                          final parser = ASN1Parser(Uint8List.fromList(octets));
                          final parsed = parser.nextObject();
                          if (parsed is ASN1Sequence) {
                            extensionsSequence = parsed;
                            print(
                              'DEBUG CRL PARSE: Parsed entire octets as sequence, has ${extensionsSequence.elements.length} elements',
                            );
                          }
                        } catch (e) {
                          print(
                            'DEBUG CRL PARSE: Failed to parse entire octets: $e',
                          );
                        }
                      }
                    }
                  } catch (e, stackTrace) {
                    print(
                      'DEBUG CRL PARSE: Exception extracting inner sequence from tagged element: $e',
                    );
                    print('DEBUG CRL PARSE: Stack trace: $stackTrace');
                  }
                }
              } else if (potentialExtElement is ASN1Sequence &&
                  extIdx == tbsCertList.elements.length - 1) {
                // Last element might be extensions without explicit tagging (some CRLs)
                print(
                  'DEBUG CRL PARSE: Checking if last element is untagged extensions sequence...',
                );
                extensionsSequence = potentialExtElement;
              }

              if (extensionsSequence != null) {
                print(
                  'DEBUG CRL PARSE: Found extensions sequence, parsing CRL extensions...',
                );
                final keysBefore = result.keys.toList();
                _parseCrlExtensions(
                  extensionsSequence,
                  result,
                  logs: parsingLogs,
                );
                final keysAfter = result.keys.toList();
                print(
                  'DEBUG CRL PARSE: Extensions parsing complete. Keys before: $keysBefore, keys after: $keysAfter',
                );
                // If we successfully extracted at least one extension, we're done
                if (keysAfter.length > keysBefore.length ||
                    result.containsKey('crlNumber')) {
                  print(
                    'DEBUG CRL PARSE: Successfully extracted extensions, stopping search',
                  );
                  break; // Found extensions, no need to check further
                } else {
                  print(
                    'DEBUG CRL PARSE: No extensions extracted from this sequence, continuing search...',
                  );
                }
              }
            }

            // Fallback: if we haven't found extensions yet, try parsing the last sequence element
            // as extensions (some CRLs may have untagged extensions)
            if (!result.containsKey('crlNumber') &&
                tbsCertList.elements.isNotEmpty) {
              final lastElement =
                  tbsCertList.elements[tbsCertList.elements.length - 1];
              if (lastElement is ASN1Sequence &&
                  lastElement.elements.isNotEmpty) {
                print(
                  'DEBUG CRL PARSE: Fallback: Trying to parse last element as extensions sequence...',
                );
                // Check if it looks like an Extensions sequence (contains sequences with OIDs)
                bool looksLikeExtensions = false;
                for (final elem in lastElement.elements) {
                  if (elem is ASN1Sequence && elem.elements.isNotEmpty) {
                    if (elem.elements[0] is ASN1ObjectIdentifier) {
                      looksLikeExtensions = true;
                      break;
                    }
                  }
                }
                if (looksLikeExtensions) {
                  print(
                    'DEBUG CRL PARSE: Last element looks like extensions, parsing...',
                  );
                  _parseCrlExtensions(lastElement, result, logs: parsingLogs);
                  print(
                    'DEBUG CRL PARSE: Fallback parsing complete. Result keys: ${result.keys.toList()}',
                  );
                }
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
  /// DN structure: Name = SEQUENCE OF RelativeDistinguishedName
  /// RelativeDistinguishedName = SET OF AttributeTypeAndValue
  /// AttributeTypeAndValue = SEQUENCE { type OBJECT IDENTIFIER, value ANY }
  static String _parseDistinguishedName(ASN1Sequence dnSequence) {
    final parts = <String>[];
    print(
      'DEBUG CRL PARSE DN: Starting DN parsing, sequence has ${dnSequence.elements.length} elements',
    );
    print('DEBUG CRL PARSE DN: DN sequence toString: ${dnSequence.toString()}');

    try {
      // DN structure: Sequence contains Sets, each Set contains Sequences [OID, Value]
      // Process each element in the DN sequence
      for (int i = 0; i < dnSequence.elements.length; i++) {
        final element = dnSequence.elements[i];
        print(
          'DEBUG CRL PARSE DN: Processing element ${i + 1}/${dnSequence.elements.length}, type: ${element.runtimeType}',
        );

        // Each element should be a Set (RelativeDistinguishedName)
        if (element is ASN1Set) {
          print(
            'DEBUG CRL PARSE DN: Element is ASN1Set with ${element.elements.length} elements',
          );

          // Process each AttributeTypeAndValue in the Set
          for (final setElement in element.elements) {
            // AttributeTypeAndValue is a Sequence [OID, Value]
            if (setElement is ASN1Sequence && setElement.elements.length >= 2) {
              final oid = setElement.elements[0];
              final value = setElement.elements[1];

              // Skip NULL values
              if (value is ASN1Null) {
                print('DEBUG CRL PARSE DN: Skipping NULL value');
                continue;
              }

              print(
                'DEBUG CRL PARSE DN: Found AttributeTypeAndValue, OID type: ${oid.runtimeType}, Value type: ${value.runtimeType}',
              );

              // Extract OID string
              String oidString = '';
              if (oid is ASN1ObjectIdentifier) {
                // Try to get identifier property first
                try {
                  final identifier = (oid as dynamic).identifier;
                  if (identifier != null && identifier is String) {
                    oidString = identifier;
                  } else {
                    // Parse from toString format: "ObjectIdentifier(2.5.4.6)"
                    final oidStr = oid.toString();
                    final match = RegExp(
                      r'ObjectIdentifier\(([^)]+)\)',
                    ).firstMatch(oidStr);
                    if (match != null && match.group(1) != null) {
                      oidString = match.group(1)!;
                    } else {
                      oidString = oidStr;
                    }
                  }
                } catch (e) {
                  final oidStr = oid.toString();
                  final match = RegExp(
                    r'ObjectIdentifier\(([^)]+)\)',
                  ).firstMatch(oidStr);
                  if (match != null && match.group(1) != null) {
                    oidString = match.group(1)!;
                  }
                }
                print('DEBUG CRL PARSE DN: Extracted OID: $oidString');
              } else {
                print(
                  'DEBUG CRL PARSE DN: OID is not ASN1ObjectIdentifier: ${oid.runtimeType}',
                );
              }

              // Extract value string
              String valueString = '';
              if (value is ASN1PrintableString) {
                valueString = value.stringValue;
                print(
                  'DEBUG CRL PARSE DN: Value is ASN1PrintableString: $valueString',
                );
              } else if (value is ASN1UTF8String) {
                valueString = value.utf8StringValue;
                print(
                  'DEBUG CRL PARSE DN: Value is ASN1UTF8String: $valueString',
                );
              } else if (value is ASN1IA5String) {
                valueString = value.stringValue;
                print(
                  'DEBUG CRL PARSE DN: Value is ASN1IA5String: $valueString',
                );
              } else if (value is ASN1BMPString) {
                valueString = value.stringValue;
                print(
                  'DEBUG CRL PARSE DN: Value is ASN1BMPString: $valueString',
                );
              } else {
                print(
                  'DEBUG CRL PARSE DN: Value type not recognized: ${value.runtimeType}, toString: ${value.toString()}',
                );
                // Try to get string representation as fallback
                try {
                  final strValue = (value as dynamic).stringValue;
                  if (strValue != null && strValue is String) {
                    valueString = strValue;
                    print(
                      'DEBUG CRL PARSE DN: Got value from stringValue property: $valueString',
                    );
                  }
                } catch (_) {}
              }

              // Map OID to readable attribute name
              String attrName = _oidToName(oidString);
              print(
                'DEBUG CRL PARSE DN: Mapped OID $oidString to attribute name: $attrName',
              );

              if (attrName.isNotEmpty && valueString.isNotEmpty) {
                final attrPair = '$attrName=$valueString';
                parts.add(attrPair);
                print('DEBUG CRL PARSE DN: Added attribute pair: $attrPair');
              } else {
                print(
                  'DEBUG CRL PARSE DN: Skipping attribute pair (attrName: $attrName, valueString: $valueString)',
                );
              }
            } else {
              print(
                'DEBUG CRL PARSE DN: Set element is not a valid AttributeTypeAndValue sequence (type: ${setElement.runtimeType}, length: ${setElement is ASN1Sequence ? setElement.elements.length : 'N/A'})',
              );
            }
          }
        } else {
          print(
            'DEBUG CRL PARSE DN: Element is not ASN1Set: ${element.runtimeType}, toString: ${element.toString()}',
          );
        }
      }
      print(
        'DEBUG CRL PARSE DN: DN parsing complete, found ${parts.length} attribute pairs',
      );
    } catch (e, stackTrace) {
      print('DEBUG CRL PARSE DN: Exception parsing DN: $e');
      print('DEBUG CRL PARSE DN: Stack trace: $stackTrace');
      // If parsing fails, return a simple representation
    }

    final result = parts.isNotEmpty ? parts.join(', ') : '';
    print('DEBUG CRL PARSE DN: Final DN result: $result');
    return result;
  }

  /// Parses time from ASN1 UTCTime or GeneralizedTime
  static String? _parseTime(ASN1Object timeObj) {
    try {
      print(
        'DEBUG CRL PARSE TIME: Parsing time object type: ${timeObj.runtimeType}',
      );
      print(
        'DEBUG CRL PARSE TIME: Time object toString: ${timeObj.toString()}',
      );

      String timeString = '';

      // Try to extract DateTime directly from ASN1UtcTime
      if (timeObj is ASN1UtcTime) {
        try {
          // ASN1UtcTime should have a dateTimeValue property
          final dateTimeValue = (timeObj as dynamic).dateTimeValue;
          if (dateTimeValue != null && dateTimeValue is DateTime) {
            final result = dateTimeValue.toIso8601String();
            print(
              'DEBUG CRL PARSE TIME: Extracted DateTime from dateTimeValue: $result',
            );
            return result;
          }
        } catch (e) {
          print('DEBUG CRL PARSE TIME: Exception getting dateTimeValue: $e');
        }

        // Try to parse from stringValue (UTCTime format: YYMMDDHHMMSSZ or YYMMDDHHMMZ)
        try {
          final stringValue = (timeObj as dynamic).stringValue;
          if (stringValue != null && stringValue is String) {
            print('DEBUG CRL PARSE TIME: Got stringValue: $stringValue');
            // Will parse below in the common parsing section
            timeString = stringValue;
          }
        } catch (e) {
          print('DEBUG CRL PARSE TIME: Exception getting stringValue: $e');
        }

        // Try to extract from toString format: "UtcTime(2025-11-04 14:29:02.000Z)"
        try {
          final timeStr = timeObj.toString();
          final match = RegExp(r'UtcTime\(([^)]+)\)').firstMatch(timeStr);
          if (match != null && match.group(1) != null) {
            final dateTimeStr = match.group(1)!.trim();
            print(
              'DEBUG CRL PARSE TIME: Extracted from toString: $dateTimeStr',
            );
            // Try to parse as ISO8601
            try {
              final dt = DateTime.parse(dateTimeStr);
              final result = dt.toIso8601String();
              print('DEBUG CRL PARSE TIME: Parsed DateTime: $result');
              return result;
            } catch (e) {
              print(
                'DEBUG CRL PARSE TIME: Failed to parse extracted string: $e',
              );
            }
          }
        } catch (e) {
          print('DEBUG CRL PARSE TIME: Exception parsing toString: $e');
        }
      }

      // For other time types, try similar approaches
      try {
        // Try to get timeValue property
        final timeValue = (timeObj as dynamic).timeValue;
        if (timeValue != null && timeValue is String) {
          timeString = timeValue;
          print('DEBUG CRL PARSE TIME: Got timeValue: $timeString');
        } else {
          // Try to get stringValue property
          final stringValue = (timeObj as dynamic).stringValue;
          if (stringValue != null && stringValue is String) {
            timeString = stringValue;
            print('DEBUG CRL PARSE TIME: Got stringValue: $timeString');
          } else {
            // Fallback to toString
            timeString = timeObj.toString();
            print('DEBUG CRL PARSE TIME: Using toString: $timeString');
          }
        }
      } catch (e) {
        // Fallback to toString
        timeString = timeObj.toString();
        print('DEBUG CRL PARSE TIME: Exception, using toString: $timeString');
      }

      if (timeString.isEmpty) {
        print('DEBUG CRL PARSE TIME: Time string is empty, returning null');
        return null;
      }

      // Clean up the time string - remove any non-time parts
      String cleanedTime = timeString
          .replaceAll(RegExp(r'[^\dZ+-\s:]'), '')
          .trim();
      print('DEBUG CRL PARSE TIME: Cleaned time string: $cleanedTime');

      // Try parsing UTCTime format (YYMMDDHHMMSSZ or YYMMDDHHMMZ)
      if (cleanedTime.length == 13 && cleanedTime.endsWith('Z')) {
        // YYMMDDHHMMSSZ format
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
            'DEBUG CRL PARSE TIME: Parsed as UTCTime (YYMMDDHHMMSSZ): ${dateTime.toIso8601String()}',
          );
          return dateTime.toIso8601String();
        }
      } else if (cleanedTime.length == 11 && cleanedTime.endsWith('Z')) {
        // YYMMDDHHMMZ format
        final match = RegExp(
          r'^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$',
        ).firstMatch(cleanedTime);
        if (match != null) {
          final year = int.parse(match.group(1)!);
          final month = int.parse(match.group(2)!);
          final day = int.parse(match.group(3)!);
          final hour = int.parse(match.group(4)!);
          final minute = int.parse(match.group(5)!);

          final fullYear = year < 50 ? 2000 + year : 1900 + year;
          final dateTime = DateTime.utc(fullYear, month, day, hour, minute);
          print(
            'DEBUG CRL PARSE TIME: Parsed as UTCTime (YYMMDDHHMMZ): ${dateTime.toIso8601String()}',
          );
          return dateTime.toIso8601String();
        }
      } else if (cleanedTime.length >= 15) {
        // GeneralizedTime format (YYYYMMDDHHMMSSZ)
        final match = RegExp(
          r'^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z?$',
        ).firstMatch(cleanedTime);
        if (match != null) {
          final year = int.parse(match.group(1)!);
          final month = int.parse(match.group(2)!);
          final day = int.parse(match.group(3)!);
          final hour = int.parse(match.group(4)!);
          final minute = int.parse(match.group(5)!);
          final second = int.parse(match.group(6)!);

          final dateTime = DateTime.utc(year, month, day, hour, minute, second);
          print(
            'DEBUG CRL PARSE TIME: Parsed as GeneralizedTime: ${dateTime.toIso8601String()}',
          );
          return dateTime.toIso8601String();
        }
      }
      print('DEBUG CRL PARSE TIME: Time format not recognized, returning null');
    } catch (e) {
      print('DEBUG CRL PARSE TIME: Exception parsing time: $e');
      // If parsing fails, return null
    }
    return null;
  }

  /// Parses CRL extensions to extract CRL Number and other extensions
  static void _parseCrlExtensions(
    ASN1Sequence extensionsSeq,
    Map<String, dynamic> result, {
    List<String>? logs,
  }) {
    final parsingLogs = logs ?? <String>[];
    try {
      print(
        'DEBUG CRL PARSE EXT: Parsing extensions, sequence has ${extensionsSeq.elements.length} elements',
      );
      // Extensions ::= SEQUENCE OF Extension
      // Extension ::= SEQUENCE {
      //   extnID      OBJECT IDENTIFIER,
      //   critical   BOOLEAN DEFAULT FALSE,
      //   extnValue   OCTET STRING
      // }

      for (final extension in extensionsSeq.elements) {
        if (extension is! ASN1Sequence || extension.elements.isEmpty) {
          print(
            'DEBUG CRL PARSE EXT: Skipping extension, not a sequence or empty',
          );
          continue;
        }

        final extnID = extension.elements[0];
        if (extnID is! ASN1ObjectIdentifier) {
          print(
            'DEBUG CRL PARSE EXT: Extension ID is not ASN1ObjectIdentifier',
          );
          continue;
        }

        // Extract OID string
        String oid = '';
        try {
          final identifier = (extnID as dynamic).identifier;
          if (identifier != null && identifier is String) {
            oid = identifier;
          } else {
            final oidStr = extnID.toString();
            final match = RegExp(
              r'ObjectIdentifier\(([^)]+)\)',
            ).firstMatch(oidStr);
            if (match != null && match.group(1) != null) {
              oid = match.group(1)!;
            }
          }
        } catch (e) {
          print('DEBUG CRL PARSE EXT: Exception extracting OID: $e');
        }

        if (oid.isEmpty) {
          print('DEBUG CRL PARSE EXT: OID is empty, skipping extension');
          continue;
        }
        print('DEBUG CRL PARSE EXT: Processing extension with OID: $oid');

        // Get extension value (OCTET STRING)
        dynamic extnValue;
        int valueIndex = 1;

        // Check if critical is present (2nd element might be boolean)
        if (extension.elements.length > 1 &&
            extension.elements[1] is ASN1Boolean) {
          valueIndex = 2; // Skip critical boolean
        }

        if (extension.elements.length > valueIndex) {
          extnValue = extension.elements[valueIndex];
        }

        // Process known extensions
        switch (oid) {
          case '2.5.29.20': // CRL Number (RFC 5280, Section 5.2.3)
            print('DEBUG CRL PARSE EXT: Found CRL Number extension');
            // CRL Number is a non-critical extension containing an INTEGER (0..MAX)
            if (extnValue is ASN1OctetString) {
              final bytes = extnValue.octets;
              print(
                'DEBUG CRL PARSE EXT: CRL Number octet string has ${bytes.length} bytes',
              );
              if (bytes.isNotEmpty) {
                try {
                  final parser = ASN1Parser(Uint8List.fromList(bytes));
                  final integerObj = parser.nextObject();
                  if (integerObj is ASN1Integer) {
                    try {
                      // ASN1Integer doesn't have a value property, decode from encodedBytes
                      final encodedBytes = integerObj.encodedBytes;
                      if (encodedBytes.isNotEmpty) {
                        // Skip tag and length bytes to get to the integer value
                        int offset = 1; // Skip tag byte (0x02 for INTEGER)
                        if (encodedBytes.length > offset) {
                          int lenByte = encodedBytes[offset];
                          if (lenByte & 0x80 == 0) {
                            // Short form: single byte length
                            offset += 1;
                          } else {
                            // Long form: multi-byte length
                            int lenLen = lenByte & 0x7F;
                            if (lenLen > 0 &&
                                lenLen <= 4 &&
                                offset + 1 + lenLen < encodedBytes.length) {
                              offset += 1 + lenLen;
                            }
                          }
                        }

                        if (offset < encodedBytes.length) {
                          final valueBytes = encodedBytes.sublist(offset);
                          // Decode BigInt from bytes (two's complement for signed integers)
                          BigInt crlNumber = BigInt.zero;
                          for (int i = 0; i < valueBytes.length; i++) {
                            crlNumber =
                                (crlNumber << 8) | BigInt.from(valueBytes[i]);
                          }

                          // Handle two's complement for negative numbers (if MSB is set)
                          // CRL numbers should always be positive, but handle it just in case
                          if (valueBytes.isNotEmpty &&
                              (valueBytes[0] & 0x80) != 0) {
                            // Negative number in two's complement - shouldn't happen for CRL numbers
                            final mask =
                                (BigInt.one << (valueBytes.length * 8)) -
                                BigInt.one;
                            crlNumber = crlNumber - (mask + BigInt.one);
                          }

                          // Format as lowercase hex without 0x prefix, padded to even bytes
                          final hexStr = crlNumber
                              .toRadixString(16)
                              .toLowerCase();
                          // Pad to even number of hex digits (multiple of 2 for full bytes)
                          final paddedHex = hexStr.length.isOdd
                              ? '0$hexStr'
                              : hexStr;
                          result['crlNumber'] = paddedHex;
                          parsingLogs.add(
                            'Extracted CRL Number: ${result['crlNumber']}',
                          );
                          print(
                            'DEBUG CRL PARSE EXT: Extracted CRL Number from encoded bytes: ${result['crlNumber']}',
                          );
                        } else {
                          print(
                            'DEBUG CRL PARSE EXT: Offset >= encodedBytes.length, cannot extract CRL Number',
                          );
                        }
                      } else {
                        print(
                          'DEBUG CRL PARSE EXT: ASN1Integer encodedBytes is empty',
                        );
                      }
                    } catch (e) {
                      print(
                        'DEBUG CRL PARSE EXT: Exception parsing CRL Number integer: $e',
                      );
                    }
                  } else {
                    print(
                      'DEBUG CRL PARSE EXT: CRL Number value is not ASN1Integer: ${integerObj.runtimeType}',
                    );
                  }
                } catch (e) {
                  print(
                    'DEBUG CRL PARSE EXT: Exception parsing CRL Number octet string: $e',
                  );
                }
              }
            } else {
              print(
                'DEBUG CRL PARSE EXT: CRL Number extension value is not ASN1OctetString: ${extnValue.runtimeType}',
              );
            }
            break;
          default:
            print('DEBUG CRL PARSE EXT: Unknown extension OID: $oid');
        }
      }
      print('DEBUG CRL PARSE EXT: Extensions parsing complete');
    } catch (e) {
      print('DEBUG CRL PARSE EXT: Exception parsing extensions: $e');
      // If extension parsing fails, continue
    }
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
}
