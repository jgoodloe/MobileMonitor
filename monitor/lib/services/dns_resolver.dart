import 'dart:io';
import 'dart:async';
import '../models/monitor_status.dart';
import 'ping_service.dart';

class DnsResolver {
  final PingService _pingService = PingService();

  Future<MonitorItem> checkDnsHost(String hostname, {bool pingIps = false}) async {
    final id = hostname;
    final name = hostname;

    try {
      // Add timeout to DNS lookup to prevent hanging
      final addresses = await InternetAddress.lookup(hostname)
          .timeout(const Duration(seconds: 5), onTimeout: () {
        return <InternetAddress>[];
      });
      
      final status = addresses.isNotEmpty
          ? MonitorStatus.up
          : MonitorStatus.down;

      List<IpAddressInfo>? ipInfos;
      
      if (addresses.isNotEmpty && pingIps) {
        // Ping all resolved IP addresses
        ipInfos = [];
        for (final address in addresses) {
          final ip = address.address;
          final pingTime = await _pingService.pingWithTime(ip);
          ipInfos.add(IpAddressInfo(
            ipAddress: ip,
            isPingable: pingTime != null,
            pingTime: pingTime,
            pingError: pingTime == null ? 'Connection failed' : null,
          ));
        }
      } else if (addresses.isNotEmpty) {
        // Just collect IP addresses without pinging
        ipInfos = addresses.map((addr) => IpAddressInfo(
          ipAddress: addr.address,
          isPingable: false,
        )).toList();
      }

      return MonitorItem(
        id: id,
        name: name,
        type: MonitorType.dns,
        status: status,
        lastCheckTime: DateTime.now(),
        errorMessage: status == MonitorStatus.down
            ? 'No addresses found'
            : null,
        ipAddresses: ipInfos,
      );
    } on SocketException catch (e) {
      return MonitorItem(
        id: id,
        name: name,
        type: MonitorType.dns,
        status: MonitorStatus.down,
        lastCheckTime: DateTime.now(),
        errorMessage: e.message,
      );
    } catch (e) {
      return MonitorItem(
        id: id,
        name: name,
        type: MonitorType.dns,
        status: MonitorStatus.down,
        lastCheckTime: DateTime.now(),
        errorMessage: e.toString(),
      );
    }
  }
}

