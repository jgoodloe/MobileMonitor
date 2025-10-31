import 'package:flutter/material.dart';
import '../models/monitor_status.dart';
import '../services/url_monitor.dart';
import '../services/dns_resolver.dart';
import '../services/crl_verifier.dart';
import '../services/configuration_manager.dart';
import 'detail_screen.dart';

class MonitorScreen extends StatefulWidget {
  const MonitorScreen({super.key});

  @override
  State<MonitorScreen> createState() => _MonitorScreenState();
}

class _MonitorScreenState extends State<MonitorScreen> with SingleTickerProviderStateMixin {
  final ConfigurationManager _configManager = ConfigurationManager();
  final UrlMonitor _urlMonitor = UrlMonitor();
  final DnsResolver _dnsResolver = DnsResolver();
  final CrlVerifier _crlVerifier = CrlVerifier();

  late TabController _tabController;
  bool _isRefreshing = false;
  
  List<MonitorItem> _urlItems = [];
  List<MonitorItem> _dnsItems = [];
  List<MonitorItem> _crlItems = [];

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 3, vsync: this);
    _loadConfigurationAndCheck();
  }

  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }

  Future<void> _loadConfigurationAndCheck() async {
    await _checkAll();
  }

  Future<void> _checkAll() async {
    setState(() {
      _isRefreshing = true;
    });

    try {
      // Load configuration
      final urls = await _configManager.getUrls();
      final dnsHosts = await _configManager.getDnsHosts();
      final crlUrls = await _configManager.getCrlUrls();

      // Check URLs
      final urlResults = <MonitorItem>[];
      for (final url in urls) {
        final result = await _urlMonitor.checkUrl(url);
        urlResults.add(result);
      }

      // Check DNS hosts with ping enabled for detail view
      final dnsResults = <MonitorItem>[];
      for (final host in dnsHosts) {
        final result = await _dnsResolver.checkDnsHost(host, pingIps: true);
        dnsResults.add(result);
      }

      // Check CRLs
      final crlResults = <MonitorItem>[];
      for (final crlUrl in crlUrls) {
        final result = await _crlVerifier.verifyCrl(crlUrl);
        crlResults.add(result);
      }

      setState(() {
        _urlItems = urlResults;
        _dnsItems = dnsResults;
        _crlItems = crlResults;
        _isRefreshing = false;
      });
    } catch (e) {
      setState(() {
        _isRefreshing = false;
      });
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Error checking: $e')),
        );
      }
    }
  }

  Widget _buildMonitorItemCard(MonitorItem item) {
    final color = item.status == MonitorStatus.up
        ? Colors.green
        : item.status == MonitorStatus.down
            ? Colors.red
            : Colors.grey;

    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      child: ListTile(
        leading: CircleAvatar(
          backgroundColor: color,
          child: Icon(
            item.status == MonitorStatus.up
                ? Icons.check_circle
                : item.status == MonitorStatus.down
                    ? Icons.error
                    : Icons.help_outline,
            color: Colors.white,
          ),
        ),
        title: Text(
          item.name,
          style: const TextStyle(fontWeight: FontWeight.bold),
        ),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (item.errorMessage != null)
              Text(
                item.errorMessage!,
                style: TextStyle(color: Colors.red[700]),
              ),
            if (item.lastCheckTime != null)
              Text(
                'Last check: ${_formatTime(item.lastCheckTime!)}',
                style: TextStyle(fontSize: 12, color: Colors.grey[600]),
              ),
            if (item.certificateInfo != null) ...[
              const SizedBox(height: 4),
              if (item.certificateInfo!.validTo != null)
                Text(
                  'Cert expires: ${_formatDate(item.certificateInfo!.validTo!)}',
                  style: TextStyle(
                    fontSize: 12,
                    color: item.certificateInfo!.isExpiringSoon
                        ? Colors.orange[700]
                        : Colors.grey[600],
                  ),
                ),
              if (item.certificateInfo!.isExpiringSoon)
                Container(
                  padding: const EdgeInsets.all(4),
                  margin: const EdgeInsets.only(top: 4),
                  decoration: BoxDecoration(
                    color: Colors.orange[100],
                    borderRadius: BorderRadius.circular(4),
                  ),
                  child: const Text(
                    '⚠ Certificate expiring soon (within 30 days)',
                    style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold),
                  ),
                ),
            ],
            if (item.crlValidityInfo != null) ...[
              const SizedBox(height: 4),
              if (item.crlValidityInfo!.validTo != null)
                Text(
                  'CRL expires: ${_formatDate(item.crlValidityInfo!.validTo!)}',
                  style: TextStyle(
                    fontSize: 12,
                    color: item.crlValidityInfo!.isExpiringSoon
                        ? Colors.orange[700]
                        : Colors.grey[600],
                  ),
                ),
              if (item.crlValidityInfo!.isExpiringSoon)
                Container(
                  padding: const EdgeInsets.all(4),
                  margin: const EdgeInsets.only(top: 4),
                  decoration: BoxDecoration(
                    color: Colors.orange[100],
                    borderRadius: BorderRadius.circular(4),
                  ),
                  child: const Text(
                    '⚠ CRL expiring soon (within 1 hour)',
                    style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold),
                  ),
                ),
            ],
          ],
        ),
        trailing: const Icon(Icons.chevron_right),
        onTap: () {
          Navigator.push(
            context,
            MaterialPageRoute(
              builder: (context) => DetailScreen(item: item),
            ),
          );
        },
      ),
    );
  }

  String _formatTime(DateTime dateTime) {
    return '${dateTime.hour.toString().padLeft(2, '0')}:'
        '${dateTime.minute.toString().padLeft(2, '0')}:'
        '${dateTime.second.toString().padLeft(2, '0')}';
  }

  String _formatDate(DateTime dateTime) {
    return '${dateTime.year}-${dateTime.month.toString().padLeft(2, '0')}-'
        '${dateTime.day.toString().padLeft(2, '0')}';
  }

  Widget _buildTab(List<MonitorItem> items, String emptyMessage) {
    if (_isRefreshing && items.isEmpty) {
      return const Center(child: CircularProgressIndicator());
    }

    if (items.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.info_outline, size: 64, color: Colors.grey[400]),
            const SizedBox(height: 16),
            Text(
              emptyMessage,
              style: TextStyle(color: Colors.grey[600]),
            ),
            const SizedBox(height: 16),
            const Text(
              'Configure items in Settings',
              style: TextStyle(fontSize: 12, color: Colors.grey),
            ),
          ],
        ),
      );
    }

    return RefreshIndicator(
      onRefresh: _checkAll,
      child: ListView.builder(
        itemCount: items.length,
        itemBuilder: (context, index) {
          return _buildMonitorItemCard(items[index]);
        },
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Monitor'),
        bottom: TabBar(
          controller: _tabController,
          tabs: const [
            Tab(text: 'URLs', icon: Icon(Icons.link)),
            Tab(text: 'DNS', icon: Icon(Icons.dns)),
            Tab(text: 'CRLs', icon: Icon(Icons.security)),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: _isRefreshing ? null : _checkAll,
            tooltip: 'Refresh',
          ),
        ],
      ),
      body: _isRefreshing && _urlItems.isEmpty && _dnsItems.isEmpty && _crlItems.isEmpty
          ? const Center(child: CircularProgressIndicator())
          : TabBarView(
              controller: _tabController,
              children: [
                _buildTab(_urlItems, 'No URLs configured'),
                _buildTab(_dnsItems, 'No DNS hosts configured'),
                _buildTab(_crlItems, 'No CRL URLs configured'),
              ],
            ),
    );
  }
}

