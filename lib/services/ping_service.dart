import 'dart:io';
import 'dart:async';

class PingService {
  /// Attempts to ping an IP address by connecting to a common port
  /// Returns true if connection succeeds within timeout
  Future<bool> ping(String ipAddress, {Duration timeout = const Duration(seconds: 3)}) async {
    try {
      final socket = await Socket.connect(
        ipAddress,
        80, // Try HTTP port first
        timeout: timeout,
      ).timeout(timeout);
      await socket.close();
      return true;
    } catch (e) {
      // If port 80 fails, try 443 (HTTPS)
      try {
        final socket = await Socket.connect(
          ipAddress,
          443,
          timeout: timeout,
        ).timeout(timeout);
        await socket.close();
        return true;
      } catch (e2) {
        return false;
      }
    }
  }

  /// Attempts to ping and returns duration if successful
  Future<Duration?> pingWithTime(String ipAddress, {Duration timeout = const Duration(seconds: 3)}) async {
    final stopwatch = Stopwatch()..start();
    try {
      final socket = await Socket.connect(
        ipAddress,
        80,
        timeout: timeout,
      ).timeout(timeout);
      stopwatch.stop();
      await socket.close();
      return stopwatch.elapsed;
    } catch (e) {
      // Try HTTPS port
      stopwatch.reset();
      try {
        final socket = await Socket.connect(
          ipAddress,
          443,
          timeout: timeout,
        ).timeout(timeout);
        stopwatch.stop();
        await socket.close();
        return stopwatch.elapsed;
      } catch (e2) {
        return null;
      }
    }
  }
}

