import 'package:shared_preferences/shared_preferences.dart';

class ConfigurationManager {
  static const String _urlsKey = 'monitor_urls';
  static const String _dnsHostsKey = 'monitor_dns_hosts';
  static const String _crlUrlsKey = 'monitor_crl_urls';

  // Default values from the original app
  static const List<String> _defaultUrls = [
    'https://pivi.xcloud.authentx.com/portal/index.html',
    'https://piv.xcloud.authentx.com/portal/index.html',
  ];

  static const List<String> _defaultDnsHosts = [
    'piv.xcloud.authentx.com',
    'pivi.xcloud.authentx.com',
    'ocsp.xca.xpki.com',
    'crl.xca.xpki.com',
    'aia.xca.xpki.com',
  ];

  static const List<String> _defaultCrlUrls = [
    'http://crl.xca.xpki.com/CRLs/XTec_PIVI_CA1.crl',
    'http://66.165.167.225/CRLs/XTec_PIVI_CA1.crl',
    'http://152.186.38.46/CRLs/XTec_PIVI_CA1.crl',
  ];

  Future<List<String>> getUrls() async {
    final prefs = await SharedPreferences.getInstance();
    final urls = prefs.getStringList(_urlsKey);
    return urls ?? _defaultUrls;
  }

  Future<void> setUrls(List<String> urls) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setStringList(_urlsKey, urls);
  }

  Future<List<String>> getDnsHosts() async {
    final prefs = await SharedPreferences.getInstance();
    final hosts = prefs.getStringList(_dnsHostsKey);
    return hosts ?? _defaultDnsHosts;
  }

  Future<void> setDnsHosts(List<String> hosts) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setStringList(_dnsHostsKey, hosts);
  }

  Future<List<String>> getCrlUrls() async {
    final prefs = await SharedPreferences.getInstance();
    final urls = prefs.getStringList(_crlUrlsKey);
    return urls ?? _defaultCrlUrls;
  }

  Future<void> setCrlUrls(List<String> urls) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setStringList(_crlUrlsKey, urls);
  }

  Future<void> resetToDefaults() async {
    await setUrls(_defaultUrls);
    await setDnsHosts(_defaultDnsHosts);
    await setCrlUrls(_defaultCrlUrls);
  }
}

