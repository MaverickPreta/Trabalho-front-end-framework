import 'dart:async';
import 'dart:convert';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

const apiBase = 'http://127.0.0.1:5000/api';

void main() => runApp(const ScannerApp());

class ScannerApp extends StatelessWidget {
  const ScannerApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Scanner VirusTotal',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(colorSchemeSeed: Colors.indigo, useMaterial3: true),
      home: const HomePage(),
    );
  }
}

class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  List<Map<String, dynamic>> downloads = [];
  // resultado por nome de arquivo: {status: scanning|queued|done|error, ...}
  final Map<String, Map<String, dynamic>> results = {};
  bool loading = false;
  String? listError;
  int minutes = 60;

  @override
  void initState() {
    super.initState();
    loadDownloads();
  }

  Future<void> loadDownloads() async {
    setState(() {
      loading = true;
      listError = null;
    });
    try {
      final r = await http.get(Uri.parse('$apiBase/downloads?minutes=$minutes'));
      if (r.statusCode != 200) throw jsonDecode(r.body)['error'] ?? 'Erro ${r.statusCode}';
      setState(() => downloads = List<Map<String, dynamic>>.from(jsonDecode(r.body)));
    } catch (e) {
      setState(() => listError = 'Não consegui falar com o backend: $e');
    } finally {
      setState(() => loading = false);
    }
  }

  Future<void> scanDownload(String name) async {
    setState(() => results[name] = {'status': 'scanning'});
    try {
      final r = await http.post(
        Uri.parse('$apiBase/scan/download'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'filename': name}),
      );
      await handleScanResponse(name, r);
    } catch (e) {
      setState(() => results[name] = {'status': 'error', 'error': '$e'});
    }
  }

  Future<void> pickAndScan() async {
    final picked = await FilePicker.platform.pickFiles(withData: true);
    if (picked == null || picked.files.single.bytes == null) return;
    final file = picked.files.single;
    setState(() => results[file.name] = {'status': 'scanning', 'uploaded': true});
    try {
      final req = http.MultipartRequest('POST', Uri.parse('$apiBase/scan/upload'))
        ..files.add(http.MultipartFile.fromBytes('file', file.bytes!, filename: file.name));
      final r = await http.Response.fromStream(await req.send());
      await handleScanResponse(file.name, r);
    } catch (e) {
      setState(() => results[file.name] = {'status': 'error', 'error': '$e'});
    }
  }

  Future<void> handleScanResponse(String name, http.Response r) async {
    final body = jsonDecode(r.body) as Map<String, dynamic>;
    if (r.statusCode != 200) {
      setState(() => results[name] = {'status': 'error', 'error': body['error'] ?? 'Erro ${r.statusCode}'});
      return;
    }
    setState(() => results[name] = body);
    if (body['status'] == 'queued') pollAnalysis(name, body['analysis_id']);
  }

  Future<void> pollAnalysis(String name, String id) async {
    for (var i = 0; i < 30; i++) {
      await Future.delayed(const Duration(seconds: 6));
      if (!mounted) return;
      try {
        final r = await http.get(Uri.parse('$apiBase/analysis/$id'));
        final body = jsonDecode(r.body) as Map<String, dynamic>;
        if (r.statusCode == 200 && body['status'] == 'done') {
          setState(() => results[name] = {...body, 'submitted': true});
          return;
        }
      } catch (_) {}
    }
    setState(() => results[name] = {'status': 'error', 'error': 'Tempo esgotado aguardando a análise.'});
  }

  String fmtSize(num b) {
    if (b < 1024) return '$b B';
    if (b < 1024 * 1024) return '${(b / 1024).toStringAsFixed(1)} KB';
    return '${(b / 1024 / 1024).toStringAsFixed(1)} MB';
  }

  @override
  Widget build(BuildContext context) {
    // resultados de upload manual que não estão na lista de downloads
    final names = downloads.map((d) => d['name'] as String).toSet();
    final extra = results.keys.where((k) => !names.contains(k)).toList();

    return Scaffold(
      appBar: AppBar(title: const Text('Scanner VirusTotal'), centerTitle: false),
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 800),
          child: ListView(
            padding: const EdgeInsets.all(16),
            children: [
              Wrap(spacing: 12, runSpacing: 8, crossAxisAlignment: WrapCrossAlignment.center, children: [
                FilledButton.icon(
                  onPressed: pickAndScan,
                  icon: const Icon(Icons.upload_file),
                  label: const Text('Escolher arquivo'),
                ),
                OutlinedButton.icon(
                  onPressed: loading ? null : loadDownloads,
                  icon: const Icon(Icons.refresh),
                  label: const Text('Atualizar downloads'),
                ),
                DropdownButton<int>(
                  value: minutes,
                  items: const [
                    DropdownMenuItem(value: 15, child: Text('Últimos 15 min')),
                    DropdownMenuItem(value: 60, child: Text('Última hora')),
                    DropdownMenuItem(value: 1440, child: Text('Últimas 24 h')),
                  ],
                  onChanged: (v) {
                    setState(() => minutes = v!);
                    loadDownloads();
                  },
                ),
              ]),
              const SizedBox(height: 16),
              Text('Downloads recentes', style: Theme.of(context).textTheme.titleMedium),
              const SizedBox(height: 8),
              if (loading) const LinearProgressIndicator(),
              if (listError != null)
                Card(
                  color: Theme.of(context).colorScheme.errorContainer,
                  child: Padding(padding: const EdgeInsets.all(12), child: Text(listError!)),
                ),
              if (!loading && listError == null && downloads.isEmpty)
                const Padding(
                  padding: EdgeInsets.all(12),
                  child: Text('Nenhum arquivo baixado nesse período.'),
                ),
              for (final d in downloads)
                FileCard(
                  name: d['name'],
                  subtitle: fmtSize(d['size']),
                  result: results[d['name']],
                  onScan: () => scanDownload(d['name']),
                ),
              if (extra.isNotEmpty) ...[
                const SizedBox(height: 16),
                Text('Arquivos enviados', style: Theme.of(context).textTheme.titleMedium),
                const SizedBox(height: 8),
                for (final n in extra) FileCard(name: n, subtitle: 'upload manual', result: results[n]),
              ],
            ],
          ),
        ),
      ),
    );
  }
}

class FileCard extends StatelessWidget {
  final String name;
  final String subtitle;
  final Map<String, dynamic>? result;
  final VoidCallback? onScan;

  const FileCard({super.key, required this.name, required this.subtitle, this.result, this.onScan});

  @override
  Widget build(BuildContext context) {
    final status = result?['status'];
    final busy = status == 'scanning' || status == 'queued';

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(children: [
            const Icon(Icons.insert_drive_file_outlined),
            const SizedBox(width: 12),
            Expanded(
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text(name, overflow: TextOverflow.ellipsis, style: const TextStyle(fontWeight: FontWeight.w600)),
                Text(subtitle, style: Theme.of(context).textTheme.bodySmall),
              ]),
            ),
            if (onScan != null)
              FilledButton.tonal(onPressed: busy ? null : onScan, child: const Text('Escanear')),
          ]),
          if (busy) ...[
            const SizedBox(height: 10),
            const LinearProgressIndicator(),
            const SizedBox(height: 4),
            Text(status == 'queued'
                ? 'Arquivo novo para o VirusTotal, aguardando análise...'
                : 'Calculando hash e consultando...'),
          ],
          if (status == 'error') ...[
            const SizedBox(height: 8),
            Text(result!['error'] ?? 'Erro', style: TextStyle(color: Theme.of(context).colorScheme.error)),
          ],
          if (status == 'done') ResultView(result: result!),
        ]),
      ),
    );
  }
}

class ResultView extends StatelessWidget {
  final Map<String, dynamic> result;
  const ResultView({super.key, required this.result});

  @override
  Widget build(BuildContext context) {
    final s = Map<String, dynamic>.from(result['stats'] ?? {});
    final malicious = (s['malicious'] ?? 0) as int;
    final suspicious = (s['suspicious'] ?? 0) as int;
    final total = s.values.whereType<int>().fold<int>(0, (a, b) => a + b);

    final (label, color, icon) = malicious > 0
        ? ('Malicioso: $malicious de $total motores detectaram', Colors.red, Icons.dangerous)
        : suspicious > 0
            ? ('Suspeito: $suspicious de $total motores', Colors.orange, Icons.warning_amber)
            : ('Limpo: nenhuma detecção em $total motores', Colors.green, Icons.verified_outlined);

    return Padding(
      padding: const EdgeInsets.only(top: 10),
      child: Container(
        padding: const EdgeInsets.all(10),
        decoration: BoxDecoration(
          color: color.withOpacity(0.1),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: color.withOpacity(0.5)),
        ),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(children: [
            Icon(icon, color: color),
            const SizedBox(width: 8),
            Expanded(child: Text(label, style: TextStyle(color: color, fontWeight: FontWeight.bold))),
          ]),
          const SizedBox(height: 6),
          Text('SHA-256: ${result['sha256']}', style: Theme.of(context).textTheme.bodySmall),
          if (result['link'] != null)
            SelectableText('Relatório: ${result['link']}', style: Theme.of(context).textTheme.bodySmall),
        ]),
      ),
    );
  }
}
