import 'package:flutter/material.dart';
import '../services/configuration_manager.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> with SingleTickerProviderStateMixin {
  final ConfigurationManager _configManager = ConfigurationManager();
  late TabController _tabController;

  List<String> _urls = [];
  List<String> _dnsHosts = [];
  List<String> _crlUrls = [];

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 3, vsync: this);
    _loadConfiguration();
  }

  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }

  Future<void> _loadConfiguration() async {
    final urls = await _configManager.getUrls();
    final dnsHosts = await _configManager.getDnsHosts();
    final crlUrls = await _configManager.getCrlUrls();

    setState(() {
      _urls = List.from(urls);
      _dnsHosts = List.from(dnsHosts);
      _crlUrls = List.from(crlUrls);
    });
  }

  Future<void> _saveUrls() async {
    await _configManager.setUrls(_urls);
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('URLs saved')),
      );
    }
  }

  Future<void> _saveDnsHosts() async {
    await _configManager.setDnsHosts(_dnsHosts);
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('DNS hosts saved')),
      );
    }
  }

  Future<void> _saveCrlUrls() async {
    await _configManager.setCrlUrls(_crlUrls);
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('CRL URLs saved')),
      );
    }
  }

  Future<void> _showAddDialog(List<String> list, String type, Function(String) onAdd) async {
    final controller = TextEditingController();
    final result = await showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text('Add $type'),
        content: TextField(
          controller: controller,
          decoration: InputDecoration(
            hintText: 'Enter $type',
            labelText: type,
          ),
          autofocus: true,
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () {
              if (controller.text.trim().isNotEmpty) {
                Navigator.pop(context, controller.text.trim());
              }
            },
            child: const Text('Add'),
          ),
        ],
      ),
    );

    if (result != null && result.isNotEmpty) {
      setState(() {
        onAdd(result);
      });
      if (type == 'URL') {
        await _saveUrls();
      } else if (type == 'DNS Host') {
        await _saveDnsHosts();
      } else if (type == 'CRL URL') {
        await _saveCrlUrls();
      }
    }
  }

  Widget _buildListTab(List<String> items, String type, Function(String) onAdd, Function(int) onRemove, Future<void> Function() onSave) {
    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.all(16),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text(
                'Configure $type',
                style: const TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
              ),
              ElevatedButton.icon(
                icon: const Icon(Icons.add),
                label: Text('Add $type'),
                onPressed: () => _showAddDialog(items, type, onAdd),
              ),
            ],
          ),
        ),
        Expanded(
          child: items.isEmpty
              ? Center(
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Icon(Icons.info_outline, size: 64, color: Colors.grey[400]),
                      const SizedBox(height: 16),
                      Text(
                        'No $type items configured',
                        style: TextStyle(color: Colors.grey[600]),
                      ),
                    ],
                  ),
                )
              : ListView.builder(
                  itemCount: items.length,
                  itemBuilder: (context, index) {
                    return Card(
                      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
                      child: ListTile(
                        title: Text(items[index]),
                        trailing: IconButton(
                          icon: const Icon(Icons.delete, color: Colors.red),
                          onPressed: () async {
                            setState(() {
                              onRemove(index);
                            });
                            await onSave();
                          },
                        ),
                      ),
                    );
                  },
                ),
        ),
      ],
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Settings'),
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
            icon: const Icon(Icons.restore),
            tooltip: 'Reset to defaults',
            onPressed: () async {
              if (!mounted) return;
              final messenger = ScaffoldMessenger.of(context);
              
              final confirm = await showDialog<bool>(
                context: context,
                builder: (context) => AlertDialog(
                  title: const Text('Reset to Defaults'),
                  content: const Text(
                    'This will replace all current settings with default values. Continue?',
                  ),
                  actions: [
                    TextButton(
                      onPressed: () => Navigator.pop(context, false),
                      child: const Text('Cancel'),
                    ),
                    TextButton(
                      onPressed: () => Navigator.pop(context, true),
                      child: const Text('Reset'),
                    ),
                  ],
                ),
              );

              if (!mounted) return;
              
              if (confirm == true) {
                await _configManager.resetToDefaults();
                await _loadConfiguration();
                if (mounted) {
                  messenger.showSnackBar(
                    const SnackBar(content: Text('Settings reset to defaults')),
                  );
                }
              }
            },
          ),
        ],
      ),
      body: TabBarView(
        controller: _tabController,
        children: [
          _buildListTab(
            _urls,
            'URL',
            (url) => _urls.add(url),
            (index) => _urls.removeAt(index),
            _saveUrls,
          ),
          _buildListTab(
            _dnsHosts,
            'DNS Host',
            (host) => _dnsHosts.add(host),
            (index) => _dnsHosts.removeAt(index),
            _saveDnsHosts,
          ),
          _buildListTab(
            _crlUrls,
            'CRL URL',
            (url) => _crlUrls.add(url),
            (index) => _crlUrls.removeAt(index),
            _saveCrlUrls,
          ),
        ],
      ),
    );
  }
}

