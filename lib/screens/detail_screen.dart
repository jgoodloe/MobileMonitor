import 'package:flutter/material.dart';
import 'dart:io';
import 'dart:async';
import '../models/monitor_status.dart';
import '../services/ping_service.dart';

class DetailScreen extends StatefulWidget {
  final MonitorItem item;

  const DetailScreen({super.key, required this.item});

  @override
  State<DetailScreen> createState() => _DetailScreenState();
}

class _DetailScreenState extends State<DetailScreen> {
  List<IpAddressInfo>? _pingedIps;
  bool _isPinging = false;
  String? _crlHostname;

  @override
  void initState() {
    super.initState();
    // If DNS item doesn't have ping info, ping them now
    if (widget.item.type == MonitorType.dns &&
        widget.item.ipAddresses != null &&
        widget.item.ipAddresses!.any(
          (ip) => !ip.isPingable && ip.pingTime == null,
        )) {
      _pingIps();
    } else {
      _pingedIps = widget.item.ipAddresses;
    }

    // For CRL items, resolve DNS and ping server addresses
    if (widget.item.type == MonitorType.crl) {
      _resolveAndPingCrlServer();
    }
  }

  Future<void> _pingIps() async {
    if (widget.item.ipAddresses == null || widget.item.ipAddresses!.isEmpty)
      return;

    setState(() {
      _isPinging = true;
    });

    final pingService = PingService();

    // Ping all IPs in parallel for better performance
    final pingFutures = widget.item.ipAddresses!.map((ipInfo) async {
      final pingTime = await pingService.pingWithTime(ipInfo.ipAddress);
      return IpAddressInfo(
        ipAddress: ipInfo.ipAddress,
        isPingable: pingTime != null,
        pingTime: pingTime,
        pingError: pingTime == null ? 'Connection failed' : null,
      );
    });

    final pingedIps = await Future.wait(pingFutures);

    if (mounted) {
      setState(() {
        _pingedIps = pingedIps;
        _isPinging = false;
      });
    }
  }

  Future<void> _resolveAndPingCrlServer() async {
    try {
      // Extract hostname from CRL URL
      final uri = Uri.parse(widget.item.name);
      final hostname = uri.host;

      if (hostname.isEmpty) return;

      if (mounted) {
        setState(() {
          _crlHostname = hostname;
          _isPinging = true;
        });
      }

      // Perform DNS resolution with timeout
      final addresses = await InternetAddress.lookup(hostname).timeout(
        const Duration(seconds: 5),
        onTimeout: () {
          return <InternetAddress>[];
        },
      );

      if (addresses.isEmpty) {
        if (mounted) {
          setState(() {
            _pingedIps = [];
            _isPinging = false;
          });
        }
        return;
      }

      // Ping all resolved IP addresses in parallel for better performance
      final pingService = PingService();

      final pingFutures = addresses.map((address) async {
        final ip = address.address;
        final pingTime = await pingService.pingWithTime(ip);
        return IpAddressInfo(
          ipAddress: ip,
          isPingable: pingTime != null,
          pingTime: pingTime,
          pingError: pingTime == null ? 'Connection failed' : null,
        );
      });

      final pingedIps = await Future.wait(pingFutures);

      if (mounted) {
        setState(() {
          _pingedIps = pingedIps;
          _isPinging = false;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _pingedIps = [];
          _isPinging = false;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(_getTypeLabel(widget.item.type)),
        actions:
            (widget.item.type == MonitorType.dns &&
                    widget.item.ipAddresses != null) ||
                widget.item.type == MonitorType.crl
            ? [
                IconButton(
                  icon: _isPinging
                      ? const SizedBox(
                          width: 20,
                          height: 20,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Icon(Icons.refresh),
                  onPressed: _isPinging
                      ? null
                      : (widget.item.type == MonitorType.dns
                            ? _pingIps
                            : _resolveAndPingCrlServer),
                  tooltip: widget.item.type == MonitorType.dns
                      ? 'Re-ping IPs'
                      : 'Re-resolve and ping server',
                ),
              ]
            : null,
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _buildStatusCard(),
            const SizedBox(height: 16),
            _buildInfoCard(),
            if (widget.item.certificateInfo != null) ...[
              const SizedBox(height: 16),
              _buildCertificateCard(),
            ],
            if (widget.item.urlErrorDetails != null) ...[
              const SizedBox(height: 16),
              _buildUrlErrorDetailsCard(),
            ],
            if (widget.item.type == MonitorType.dns &&
                (_pingedIps != null || widget.item.ipAddresses != null)) ...[
              const SizedBox(height: 16),
              _buildDnsIpsCard(),
            ],
            if (widget.item.crlValidityInfo != null) ...[
              const SizedBox(height: 16),
              _buildCrlValidityCard(),
            ],
            if (widget.item.type == MonitorType.crl &&
                (_pingedIps != null || _isPinging)) ...[
              const SizedBox(height: 16),
              _buildCrlServerAddressesCard(),
            ],
            if (widget.item.errorMessage != null &&
                widget.item.urlErrorDetails == null) ...[
              const SizedBox(height: 16),
              _buildErrorCard(),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildStatusCard() {
    final color = widget.item.status == MonitorStatus.up
        ? Colors.green
        : widget.item.status == MonitorStatus.down
        ? Colors.red
        : Colors.grey;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          children: [
            CircleAvatar(
              radius: 32,
              backgroundColor: color,
              child: Icon(
                widget.item.status == MonitorStatus.up
                    ? Icons.check_circle
                    : widget.item.status == MonitorStatus.down
                    ? Icons.error
                    : Icons.help_outline,
                color: Colors.white,
                size: 40,
              ),
            ),
            const SizedBox(width: 16),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    widget.item.status == MonitorStatus.up
                        ? widget.item.type == MonitorType.dns
                              ? 'RESOLVED'
                              : 'UP'
                        : widget.item.status == MonitorStatus.down
                        ? 'DOWN'
                        : 'UNKNOWN',
                    style: TextStyle(
                      fontSize: 24,
                      fontWeight: FontWeight.bold,
                      color: color,
                    ),
                  ),
                  const SizedBox(height: 4),
                  Text(widget.item.name, style: const TextStyle(fontSize: 16)),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildInfoCard() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Information',
              style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
            ),
            const Divider(),
            _buildInfoRow('Type', _getTypeLabel(widget.item.type)),
            if (widget.item.lastCheckTime != null)
              _buildInfoRow(
                'Last Check',
                '${widget.item.lastCheckTime!.toLocal()}',
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildCertificateCard() {
    final cert = widget.item.certificateInfo!;
    return Card(
      color: cert.isExpiringSoon ? Colors.orange[50] : null,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Text(
                  'Certificate Information',
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                ),
                if (cert.isExpiringSoon)
                  Container(
                    margin: const EdgeInsets.only(left: 8),
                    padding: const EdgeInsets.symmetric(
                      horizontal: 8,
                      vertical: 4,
                    ),
                    decoration: BoxDecoration(
                      color: Colors.orange,
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: const Text(
                      'EXPIRING SOON',
                      style: TextStyle(
                        fontSize: 10,
                        fontWeight: FontWeight.bold,
                        color: Colors.white,
                      ),
                    ),
                  ),
              ],
            ),
            const Divider(),
            if (cert.validFrom != null)
              _buildInfoRow('Valid From', cert.validFrom!.toLocal().toString()),
            if (cert.validTo != null)
              _buildInfoRow('Valid To', cert.validTo!.toLocal().toString()),
            if (cert.issuer != null) _buildInfoRow('Issuer', cert.issuer!),
            if (cert.subject != null) _buildInfoRow('Subject', cert.subject!),
          ],
        ),
      ),
    );
  }

  Widget _buildUrlErrorDetailsCard() {
    final errorDetails = widget.item.urlErrorDetails!;
    return Card(
      color: Colors.red[50],
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Error Details',
              style: TextStyle(
                fontSize: 18,
                fontWeight: FontWeight.bold,
                color: Colors.red,
              ),
            ),
            const Divider(),
            if (errorDetails.errorType != null)
              _buildInfoRow('Error Type', errorDetails.errorType!),
            if (errorDetails.httpStatusCode != null)
              _buildInfoRow(
                'HTTP Status Code',
                errorDetails.httpStatusCode!.toString(),
              ),
            if (errorDetails.responseTime != null)
              _buildInfoRow(
                'Response Time',
                '${errorDetails.responseTime!.inMilliseconds}ms',
              ),
            if (errorDetails.isSslError == true) ...[
              _buildInfoRow('SSL/TLS Error', 'Yes'),
              if (errorDetails.sslErrorMessage != null)
                _buildInfoRow(
                  'SSL/TLS Error Message',
                  errorDetails.sslErrorMessage!,
                ),
            ],
            if (errorDetails.responseBody != null &&
                errorDetails.responseBody!.isNotEmpty)
              Padding(
                padding: const EdgeInsets.only(top: 8),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'Response Body:',
                      style: TextStyle(fontWeight: FontWeight.bold),
                    ),
                    const SizedBox(height: 4),
                    Container(
                      padding: const EdgeInsets.all(8),
                      decoration: BoxDecoration(
                        color: Colors.white,
                        borderRadius: BorderRadius.circular(4),
                        border: Border.all(color: Colors.grey[300]!),
                      ),
                      constraints: const BoxConstraints(maxHeight: 200),
                      child: SingleChildScrollView(
                        child: SelectableText(
                          errorDetails.responseBody!.length > 1000
                              ? '${errorDetails.responseBody!.substring(0, 1000)}...\n\n(Truncated)'
                              : errorDetails.responseBody!,
                          style: const TextStyle(
                            fontSize: 11,
                            fontFamily: 'monospace',
                          ),
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            if (widget.item.errorMessage != null) ...[
              const SizedBox(height: 8),
              const Divider(),
              Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: Colors.red[100],
                  borderRadius: BorderRadius.circular(4),
                ),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Icon(
                      Icons.error_outline,
                      color: Colors.red,
                      size: 20,
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: SelectableText(
                        widget.item.errorMessage!,
                        style: const TextStyle(
                          color: Colors.red,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildDnsIpsCard() {
    final ips = _pingedIps ?? widget.item.ipAddresses ?? [];

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Resolved IP Addresses',
              style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
            ),
            const Divider(),
            if (_isPinging)
              const Padding(
                padding: EdgeInsets.all(16),
                child: Center(child: CircularProgressIndicator()),
              )
            else if (ips.isEmpty)
              const Text('No IP addresses found')
            else
              ...ips.map((ipInfo) => _buildIpAddressRow(ipInfo)),
          ],
        ),
      ),
    );
  }

  Widget _buildCrlServerAddressesCard() {
    final ips = _pingedIps ?? [];

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Text(
                  'Server Addresses',
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                ),
                if (_crlHostname != null) ...[
                  const SizedBox(width: 8),
                  Text(
                    '(${_crlHostname!})',
                    style: TextStyle(fontSize: 14, color: Colors.grey[600]),
                  ),
                ],
              ],
            ),
            const Divider(),
            if (_isPinging)
              const Padding(
                padding: EdgeInsets.all(16),
                child: Center(child: CircularProgressIndicator()),
              )
            else if (ips.isEmpty)
              const Text('No IP addresses found')
            else
              ...ips.map((ipInfo) => _buildIpAddressRow(ipInfo)),
          ],
        ),
      ),
    );
  }

  Widget _buildIpAddressRow(IpAddressInfo ipInfo) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Row(
        children: [
          Icon(
            ipInfo.isPingable ? Icons.check_circle : Icons.cancel,
            color: ipInfo.isPingable ? Colors.green : Colors.red,
            size: 20,
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                SelectableText(
                  ipInfo.ipAddress,
                  style: const TextStyle(fontWeight: FontWeight.bold),
                ),
                if (ipInfo.pingTime != null)
                  Text(
                    'Ping: ${ipInfo.pingTime!.inMilliseconds}ms',
                    style: TextStyle(fontSize: 12, color: Colors.grey[600]),
                  )
                else if (ipInfo.pingError != null)
                  Text(
                    ipInfo.pingError!,
                    style: TextStyle(fontSize: 12, color: Colors.red[700]),
                  )
                else
                  const Text(
                    'Not pinged',
                    style: TextStyle(fontSize: 12, color: Colors.grey),
                  ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildCrlValidityCard() {
    final validity = widget.item.crlValidityInfo!;
    return Card(
      color: validity.isExpiringSoon ? Colors.orange[50] : null,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Text(
                  'CRL Information',
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                ),
                if (validity.isExpiringSoon)
                  Container(
                    margin: const EdgeInsets.only(left: 8),
                    padding: const EdgeInsets.symmetric(
                      horizontal: 8,
                      vertical: 4,
                    ),
                    decoration: BoxDecoration(
                      color: Colors.orange,
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: const Text(
                      'EXPIRING SOON',
                      style: TextStyle(
                        fontSize: 10,
                        fontWeight: FontWeight.bold,
                        color: Colors.white,
                      ),
                    ),
                  ),
              ],
            ),
            const Divider(),
            if (validity.validFrom != null)
              _buildInfoRow('This Update', _formatDate(validity.validFrom!)),
            if (validity.validTo != null)
              _buildInfoRow('Next Update', _formatDate(validity.validTo!)),
            if (validity.crlAge != null) ...[
              _buildInfoRow('Age of CRL', _formatDuration(validity.crlAge!)),
            ],
            if (validity.crlNumber != null)
              _buildInfoRow('CRL Number (OID 2.5.29.20)', validity.crlNumber!),
            if (validity.revokedCertificateCount != null)
              _buildInfoRow(
                '# of Revoked Certificates',
                validity.revokedCertificateCount!.toString(),
              ),
            if (validity.certificateAuthority != null)
              _buildInfoRow(
                'Certificate Authority',
                validity.certificateAuthority!,
              ),
            if (validity.authorityKeyIdentifier != null)
              _buildInfoRow(
                'Authority Key ID',
                validity.authorityKeyIdentifier!,
              ),
            if (validity.issuingDistributionPoint != null)
              _buildInfoRow(
                'Issuing Distribution Point',
                validity.issuingDistributionPoint!,
              ),
            if (validity.isDeltaCrl) ...[
              _buildInfoRow('Type', 'Delta CRL'),
              if (validity.deltaCrlBaseNumber != null)
                _buildInfoRow(
                  'Base CRL Number',
                  validity.deltaCrlBaseNumber!.toString(),
                ),
            ],
            if (validity.freshestCrlUrls != null &&
                validity.freshestCrlUrls!.isNotEmpty) ...[
              const SizedBox(height: 8),
              const Text(
                'Freshest CRL URLs:',
                style: TextStyle(fontWeight: FontWeight.bold),
              ),
              ...validity.freshestCrlUrls!.map(
                (url) => Padding(
                  padding: const EdgeInsets.only(top: 4),
                  child: SelectableText(url),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  String _formatDate(DateTime date) {
    // Format: Sunday, November 2, 2025 4:34:09 PM
    // Convert UTC date to local timezone for display
    final localDate = date.isUtc ? date.toLocal() : date;

    // DateTime.weekday: Monday=1, Tuesday=2, ..., Sunday=7
    final weekdayNames = [
      '',
      'Monday',
      'Tuesday',
      'Wednesday',
      'Thursday',
      'Friday',
      'Saturday',
      'Sunday',
    ];
    final weekday = weekdayNames[localDate.weekday];
    final month = [
      'January',
      'February',
      'March',
      'April',
      'May',
      'June',
      'July',
      'August',
      'September',
      'October',
      'November',
      'December',
    ][localDate.month - 1];
    final day = localDate.day;
    final year = localDate.year;
    final hour = localDate.hour;
    final hour12 = hour > 12 ? hour - 12 : (hour == 0 ? 12 : hour);
    final amPm = hour >= 12 ? 'PM' : 'AM';
    final minute = localDate.minute.toString().padLeft(2, '0');
    final second = localDate.second.toString().padLeft(2, '0');

    // Get timezone abbreviation for display
    final timezone = _getCurrentTimezone();

    return '$weekday, $month $day, $year $hour12:$minute:$second $amPm $timezone';
  }

  String _getCurrentTimezone() {
    final now = DateTime.now();
    // Get the timezone offset from the DateTime object
    final offset = now.timeZoneOffset;

    // Get hours and minutes from the offset Duration
    final offsetHours = offset.inHours;
    final offsetMinutes = offset.inMinutes.remainder(60).abs();

    // Format timezone offset (e.g., UTC-5, UTC+9:30)
    String offsetStr;
    if (offsetHours == 0 && offsetMinutes == 0) {
      offsetStr = 'UTC';
    } else if (offsetMinutes == 0) {
      offsetStr = offsetHours >= 0
          ? 'UTC+$offsetHours'
          : 'UTC$offsetHours'; // Negative sign already included
    } else {
      final sign = offsetHours >= 0 ? '+' : '';
      offsetStr =
          'UTC$sign${offsetHours.abs()}:${offsetMinutes.toString().padLeft(2, '0')}';
    }

    return offsetStr;
  }

  String _formatDuration(Duration duration) {
    if (duration.inDays > 0) {
      return '${duration.inDays} days, ${duration.inHours % 24} hours';
    } else if (duration.inHours > 0) {
      return '${duration.inHours} hours, ${duration.inMinutes % 60} minutes';
    } else if (duration.inMinutes > 0) {
      return '${duration.inMinutes} minutes, ${duration.inSeconds % 60} seconds';
    } else {
      return '${duration.inSeconds} seconds';
    }
  }

  Widget _buildErrorCard() {
    return Card(
      color: Colors.red[50],
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Error Details',
              style: TextStyle(
                fontSize: 18,
                fontWeight: FontWeight.bold,
                color: Colors.red,
              ),
            ),
            const Divider(),
            Text(
              widget.item.errorMessage!,
              style: const TextStyle(color: Colors.red),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildInfoRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 120,
            child: Text(
              '$label:',
              style: const TextStyle(fontWeight: FontWeight.bold),
            ),
          ),
          Expanded(child: SelectableText(value)),
        ],
      ),
    );
  }

  String _getTypeLabel(MonitorType type) {
    switch (type) {
      case MonitorType.url:
        return 'URL';
      case MonitorType.dns:
        return 'DNS Host';
      case MonitorType.crl:
        return 'CRL';
    }
  }
}
