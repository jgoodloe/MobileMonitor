// This is a basic Flutter widget test.
//
// To perform an interaction with a widget in your test, use the WidgetTester
// utility in the flutter_test package. For example, you can send tap and scroll
// gestures. You can also use WidgetTester to find child widgets in the widget
// tree, read text, and verify that the values of widget properties are correct.

import 'package:flutter_test/flutter_test.dart';

import 'package:monitor/main.dart';

void main() {
  testWidgets('Monitor app smoke test', (WidgetTester tester) async {
    // Build our app and trigger a frame.
    await tester.pumpWidget(const MonitorApp());

    // Verify that the app title is displayed.
    expect(find.text('System Monitor'), findsOneWidget);
    
    // Verify that key sections are present.
    expect(find.text('Battery Status'), findsOneWidget);
    expect(find.text('Network Status'), findsOneWidget);
    expect(find.text('Device Information'), findsOneWidget);
    expect(find.text('System Information'), findsOneWidget);
  });
}
