import 'dart:io';
import 'package:dio/dio.dart';
import 'package:dio/io.dart';
import '../models/monitor_status.dart';

class TlsException implements Exception {
  final String message;
  TlsException(this.message);
}

class UrlMonitor {
  late final Dio _dio;

  UrlMonitor() {
    _dio = Dio();
    _dio.options.connectTimeout = const Duration(seconds: 10);
    _dio.options.receiveTimeout = const Duration(seconds: 10);
    // Allow cleartext traffic for HTTP (needed for some CRL checks)
    _dio.options.validateStatus = (status) => status! < 500;
    
    // Configure Dio to ignore certificate errors by creating a custom HttpClient
    (_dio.httpClientAdapter as IOHttpClientAdapter).createHttpClient = () {
      final client = HttpClient();
      // Ignore all certificate errors when getting URLs
      client.badCertificateCallback = (X509Certificate cert, String host, int port) {
        return true; // Accept all certificates
      };
      return client;
    };
  }

  Future<MonitorItem> checkUrl(String url) async {
    final id = url;
    final name = url;
    
    try {
      final uri = Uri.parse(url);
      final isHttps = uri.scheme == 'https';

      Response? response;
      CertificateInfo? certInfo;

      UrlErrorDetails? errorDetails;
      final stopwatch = Stopwatch()..start();
      
      try {
        response = await _dio.get(url);
        stopwatch.stop();
        
        if (isHttps) {
          certInfo = await _extractCertificateInfo(uri);
        }
      } catch (e) {
        stopwatch.stop();
        
        if (e is DioException) {
          // Even if there's an error, we might have certificate info
          if (isHttps) {
            try {
              certInfo = await _extractCertificateInfo(uri);
            } catch (_) {
              // Ignore certificate extraction errors on failed requests
            }
          }
          
          // Extract detailed error information
          String errorType = 'UnknownError';
          bool isSslError = false;
          String? sslErrorMessage;
          
          if (e.type == DioExceptionType.connectionTimeout ||
              e.type == DioExceptionType.receiveTimeout ||
              e.type == DioExceptionType.sendTimeout) {
            errorType = 'Timeout';
          } else if (e.type == DioExceptionType.connectionError) {
            errorType = 'ConnectionError';
          } else if (e.type == DioExceptionType.badResponse) {
            errorType = 'HttpError';
            errorDetails = UrlErrorDetails(
              errorType: errorType,
              httpStatusCode: e.response?.statusCode,
              responseBody: e.response?.data?.toString(),
              responseTime: stopwatch.elapsed,
            );
          } else if (e.error is TlsException || e.message?.contains('SSL') == true || 
                     e.message?.contains('TLS') == true || e.message?.contains('certificate') == true) {
            errorType = 'SSLError';
            isSslError = true;
            sslErrorMessage = e.message;
          } else {
            errorType = e.type.toString();
          }
          
          if (errorDetails == null) {
            errorDetails = UrlErrorDetails(
              errorType: errorType,
              responseTime: stopwatch.elapsed,
              isSslError: isSslError,
              sslErrorMessage: sslErrorMessage,
            );
          }
          
          return MonitorItem(
            id: id,
            name: name,
            type: MonitorType.url,
            status: MonitorStatus.down,
            lastCheckTime: DateTime.now(),
            errorMessage: e.message ?? 'Connection failed',
            certificateInfo: certInfo,
            urlErrorDetails: errorDetails,
          );
        }
        rethrow;
      }

      // At this point, response should not be null (catch block returns early)
      // Response is guaranteed to be non-null here because catch block returns early
      final statusCode = response.statusCode ?? 0;
      final status = statusCode >= 200 && statusCode < 400
          ? MonitorStatus.up
          : MonitorStatus.down;

      return MonitorItem(
        id: id,
        name: name,
        type: MonitorType.url,
        status: status,
        lastCheckTime: DateTime.now(),
        errorMessage: status == MonitorStatus.down 
            ? 'HTTP $statusCode'
            : null,
        certificateInfo: certInfo,
      );
    } catch (e) {
      return MonitorItem(
        id: id,
        name: name,
        type: MonitorType.url,
        status: MonitorStatus.down,
        lastCheckTime: DateTime.now(),
        errorMessage: e.toString(),
      );
    }
  }

  Future<CertificateInfo?> _extractCertificateInfo(Uri uri) async {
    try {
      final client = HttpClient();
      client.badCertificateCallback = (cert, host, port) => true; // Accept all for monitoring
      
      final request = await client.getUrl(uri);
      final response = await request.close();
      
      final cert = response.certificate;
      if (cert == null) return null;

      // Extract certificate information from HttpClient X509Certificate
      final now = DateTime.now();
      final validTo = cert.endValidity;
      final daysUntilExpiry = validTo.difference(now).inDays;
      final isExpiringSoon = daysUntilExpiry <= 30 && daysUntilExpiry > 0;

      return CertificateInfo(
        validFrom: cert.startValidity,
        validTo: validTo,
        issuer: cert.issuer,
        subject: cert.subject,
        isExpiringSoon: isExpiringSoon,
      );
    } catch (e) {
      // Return null if certificate extraction fails
      return null;
    }
  }
}

