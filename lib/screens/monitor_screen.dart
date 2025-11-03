import 'package:flutter/material.dart';
import 'dart:async';
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
    // Defer initial check until after first frame renders to prevent startup jank
    // Add small delay to let system stabilize after initial render
    WidgetsBinding.instance.addPostFrameCallback((_) {
      Future.delayed(const Duration(milliseconds: 200), () {
        _loadConfigurationAndCheck();
      });
    });
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
    if (!mounted) return;
    setState(() {
      _isRefreshing = true;
    });

    // Yield to UI thread before starting heavy work
    await Future.delayed(Duration.zero);

    try {
      // Load configuration in parallel to reduce latency
      final configResults = await Future.wait<List<String>>([
        _configManager.getUrls(),
        _configManager.getDnsHosts(),
        _configManager.getCrlUrls(),
      ]);
      final urls = configResults[0];
      final dnsHosts = configResults[1];
      final crlUrls = configResults[2];

      // Initialize lists with empty results for incremental updates
      if (mounted) {
        setState(() {
          _urlItems = urls.map((url) => _createPlaceholderItem(url, MonitorType.url)).toList();
          _dnsItems = dnsHosts.map((host) => _createPlaceholderItem(host, MonitorType.dns)).toList();
          _crlItems = crlUrls.map((url) => _createPlaceholderItem(url, MonitorType.crl)).toList();
        });
      }

      // Yield to UI thread
      await Future.delayed(Duration.zero);

      // Process checks incrementally to avoid blocking UI
      // URLs first
      for (int i = 0; i < urls.length; i++) {
        if (!mounted) return;
        try {
          final result = await _urlMonitor.checkUrl(urls[i]);
          if (mounted) {
            setState(() {
              _urlItems[i] = result;
            });
            // Yield every few items to keep UI responsive
            if (i % 2 == 0) {
              await Future.delayed(Duration.zero);
            }
          }
        } catch (e) {
          // Continue with next item on error
        }
      }

      // Yield before DNS checks
      await Future.delayed(Duration.zero);

      // DNS hosts (without ping for initial check - ping is only for detail view)
      for (int i = 0; i < dnsHosts.length; i++) {
        if (!mounted) return;
        try {
          final result = await _dnsResolver.checkDnsHost(dnsHosts[i], pingIps: false);
          if (mounted) {
            setState(() {
              _dnsItems[i] = result;
            });
            // Yield every few items to keep UI responsive
            if (i % 2 == 0) {
              await Future.delayed(Duration.zero);
            }
          }
        } catch (e) {
          // Continue with next item on error
        }
      }

      // Yield before CRL checks and let system stabilize
      await Future.delayed(const Duration(milliseconds: 100));

      // CRLs last (these can be heavy and need more time under load)
      for (int i = 0; i < crlUrls.length; i++) {
        if (!mounted) return;
        try {
          // Add retry logic for CRL checks - they may fail under system load
          MonitorItem result = await _crlVerifier.verifyCrl(crlUrls[i]);
          int retries = 2;
          
          // Retry on transient errors (timeouts, connection errors)
          while (retries > 0 && 
                 result.status == MonitorStatus.down && 
                 result.errorMessage != null &&
                 (result.errorMessage!.toLowerCase().contains('timeout') ||
                  result.errorMessage!.toLowerCase().contains('connection') ||
                  result.errorMessage!.toLowerCase().contains('failed'))) {
            retries--;
            if (retries > 0) {
              // Wait before retry to let system recover
              await Future.delayed(const Duration(milliseconds: 300));
              result = await _crlVerifier.verifyCrl(crlUrls[i]);
            }
          }
          
          if (mounted) {
            setState(() {
              _crlItems[i] = result;
            });
          }
          
          // Add delay between CRL checks to avoid overwhelming system
          // This gives the network and CPU time to recover
          if (i < crlUrls.length - 1) {
            await Future.delayed(const Duration(milliseconds: 150));
          }
        } catch (e) {
          // Continue with next item on error
        }
      }

      // Final update
      if (mounted) {
        setState(() {
          _isRefreshing = false;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _isRefreshing = false;
        });
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Error checking: $e')),
        );
      }
    }
  }

  MonitorItem _createPlaceholderItem(String name, MonitorType type) {
    return MonitorItem(
      id: name,
      name: name,
      type: type,
      status: MonitorStatus.unknown,
      lastCheckTime: null,
    );
  }

  Widget _buildMonitorItemCard(MonitorItem item) {
    final color = item.status == MonitorStatus.up
        ? Colors.green
        : item.status == MonitorStatus.down
            ? Colors.red
            : Colors.grey;

    return Card(
      key: ValueKey(item.id),
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
        isThreeLine: item.errorMessage != null || 
                     item.certificateInfo != null || 
                     item.crlValidityInfo != null,
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
            const Icon(Icons.info_outline, size: 64, color: Colors.grey),
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
        cacheExtent: 200, // Cache a bit more to reduce rebuilds
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

