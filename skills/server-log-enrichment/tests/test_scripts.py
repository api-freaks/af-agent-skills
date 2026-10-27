"""Regression tests for the log scripts. Fixtures are inline. No network."""

import contextlib
import gzip
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
import build_dataset as bd  # noqa: E402
import extract_indicators as ei  # noqa: E402
import ip_evidence as ev  # noqa: E402

CLF = ('203.0.113.5 - - [01/Jan/2026:00:00:00 +0000] '
       '"GET / HTTP/1.1" 200 1 "-" "curl/8"')


def run_extract(text, extra=None, binary=None):
    with tempfile.TemporaryDirectory() as d:
        log = os.path.join(d, 'a.log')
        out = os.path.join(d, 'out')
        if binary is not None:
            with open(log, 'wb') as fh:
                fh.write(binary)
        else:
            if not text.endswith('\n'):
                text += '\n'
            with open(log, 'w', encoding='utf-8') as fh:
                fh.write(text)
        argv = [log, '--out', out]
        if extra:
            argv.extend(extra)
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            code = ei.main(argv)

        def rows(name):
            path = os.path.join(out, name)
            if not os.path.exists(path):
                return []
            with open(path, encoding='utf-8') as fh:
                return [json.loads(line) for line in fh if line.strip()]

        with open(os.path.join(out, 'summary.json'), encoding='utf-8') as fh:
            summary = json.load(fh)
        return code, summary, rows('ips.jsonl'), rows('hostnames.jsonl'), rows('user_agents.jsonl')


def ips_of(rows):
    return {row['ip']: row for row in rows}


class ExtractTests(unittest.TestCase):
    def test_combined_and_common(self):
        common = ('203.0.113.6 - - [01/Jan/2026:00:00:01 +0000] '
                  '"GET /only HTTP/1.0" 200 12')
        code, summary, ips, hosts, uas = run_extract(CLF + '\n' + common)
        self.assertEqual(code, 0)
        self.assertEqual(summary['lines_parsed'], 2)
        self.assertEqual(summary['formats'].get('combined'), 1)
        self.assertEqual(summary['formats'].get('common'), 1)
        self.assertIn('203.0.113.5', ips_of(ips))
        self.assertEqual(uas[0]['user_agent'], 'curl/8')

    def test_vhost(self):
        line = ('example.com:80 203.0.113.7 - - [01/Jan/2026:00:00:00 +0000] '
                '"GET / HTTP/1.1" 200 1 "-" "curl/8"')
        code, summary, ips, hosts, uas = run_extract(line)
        self.assertEqual(code, 0)
        self.assertEqual(summary['formats'].get('vhost-combined'), 1)
        self.assertIn('203.0.113.7', ips_of(ips))
        self.assertEqual(hosts[0]['host'], 'example.com')

    def test_anonymized_token_parses_without_inventing_an_address(self):
        line = ('IP277299 - - [31/Jan/2026:00:00:19 +0900] '
                '"GET /wp-login.php HTTP/1.1" 200 1 "-" "WordPress/6.9"')
        code, summary, ips, hosts, uas = run_extract(
            line + '\nlocalhost - - [31/Jan/2026:00:00:20 +0900] '
            '"GET /health HTTP/1.1" 200 1 "-" "kube-probe/1.28"')
        self.assertEqual(code, 0)
        self.assertEqual(summary['lines_parsed'], 2)
        self.assertEqual(ips, [])
        self.assertGreaterEqual(summary['malformed_values']['ip'], 2)
        self.assertIn('anonymized', ' '.join(summary['notes']))
        agents = {row['user_agent'] for row in uas}
        self.assertIn('WordPress/6.9', agents)
        self.assertIn('kube-probe/1.28', agents)

    def test_comma_separated_client_is_a_chain(self):
        line = ('10.0.0.2, 10.0.0.1, 203.0.113.9 - - '
                '[07/Dec/2016:11:05:07 +0100] "GET /ocelot HTTP/1.1" 200 571 '
                '"-" "Mozilla/5.0"')
        code, summary, ips, hosts, uas = run_extract(line)
        self.assertEqual(code, 0)
        found = ips_of(ips)
        self.assertEqual(set(found), {'10.0.0.2', '10.0.0.1', '203.0.113.9'})
        for row in found.values():
            self.assertNotIn('connecting', row['sources'])
        self.assertTrue(any('chain' in s for s in found['203.0.113.9']['sources']))

    def test_comma_list_then_connecting_address(self):
        line = ('2001:db8::1, 10.0.0.2 203.0.113.9 - - '
                '[07/Dec/2016:11:05:07 +0100] "GET /ocelot HTTP/1.1" 200 571 '
                '"-" "Mozilla/5.0"')
        code, summary, ips, hosts, uas = run_extract(line)
        self.assertEqual(code, 0)
        found = ips_of(ips)
        self.assertIn('connecting', found['203.0.113.9']['sources'])
        self.assertNotIn('connecting', found['2001:db8::1']['sources'])
        self.assertIn('chain_1', found['2001:db8::1']['sources'])

    def test_quoted_chain_keeps_the_connecting_address(self):
        line = ('"203.0.113.1, 198.51.100.2" 203.0.113.9 - - '
                '[22/Jan/2016:13:18:29 +0000] "GET /assets HTTP/1.1" 200 1 '
                '"-" "Amazon CloudFront"')
        code, summary, ips, hosts, uas = run_extract(line)
        self.assertEqual(code, 0)
        found = ips_of(ips)
        self.assertIn('connecting', found['203.0.113.9']['sources'])
        self.assertNotIn('connecting', found['203.0.113.1']['sources'])
        self.assertIn('chain_1', found['203.0.113.1']['sources'])

    def test_host_without_port_and_quoted_chain_stays_unmatched(self):
        line = ('example.com "203.0.113.1, 198.51.100.2" 203.0.113.9 - - '
                '[22/Jan/2016:13:18:29 +0000] "GET /assets HTTP/1.1" 200 1 '
                '"-" "Amazon CloudFront"')
        code, summary, ips, hosts, uas = run_extract(line, extra=['--min-parsed', '0'])
        self.assertEqual(summary['lines_parsed'], 0)
        self.assertEqual(ips, [])

    def test_traefik_bare_referer_keeps_the_user_agent(self):
        line = ('203.0.113.9 - - [28/Feb/2018:17:30:33 +0000] '
                '"GET /en/ HTTP/2.0" 200 2814 - "Mozilla/5.0 (iPhone)" '
                '13 "router" "http://10.0.0.3:8080" 2ms')
        code, summary, ips, hosts, uas = run_extract(line)
        self.assertEqual(code, 0)
        self.assertEqual(summary['formats'].get('combined'), 1)
        self.assertEqual(uas[0]['user_agent'], 'Mozilla/5.0 (iPhone)')
        self.assertGreater(summary['unmapped_trailing_field_lines'], 0)

    def test_haproxy_classic_and_extra_host(self):
        classic = ('Jul 30 09:03:52 localhost haproxy[32450]: '
                   '203.0.113.4:38862 [30/Jul/2018:09:03:52.726] incoming~ '
                   'docs/docs 0/0/1/0/2 304 168 - - ---- 6/6/0/0/0 0/0 '
                   '{docs.example.internal||} {|||} "GET /app.js HTTP/1.1"')
        extra = ('May 22 02:22:22 server1 haproxy[5089]: '
                 '-:22222 [22/May/2021:02:22:22.222] www-https~ myapp/node2 '
                 'site.domain.com 0/0/0/18/18 200 200 - - ---- 222/222/2/0/0 0/0 '
                 '"OPTIONS /api/v2/app/ HTTP/1.1"')
        code, summary, ips, hosts, uas = run_extract(classic + '\n' + extra)
        self.assertEqual(code, 0)
        self.assertEqual(summary['lines_parsed'], 2)
        self.assertEqual(summary['formats'].get('haproxy'), 2)
        self.assertIn('203.0.113.4', ips_of(ips))
        self.assertNotIn('-', ips_of(ips))

    def test_envoy_text(self):
        line = ('[2019-04-11T00:31:55.439Z] "GET /elastic HTTP/1.1" 404 NR 0 0 0 - '
                '"203.0.113.4" "curl/7.59.0" "rid" "www.elastic.co" "-"')
        code, summary, ips, hosts, uas = run_extract(line)
        self.assertEqual(code, 0)
        self.assertEqual(summary['formats'].get('envoy'), 1)
        self.assertIn('203.0.113.4', ips_of(ips))
        self.assertIn('www.elastic.co', [h['host'] for h in hosts])

    def test_envoy_message_wrapper(self):
        inner = ('ACCESS [2019-04-11T00:31:55.439Z] "GET /elastic HTTP/1.1" 404 NR 0 0 0 - '
                 '"203.0.113.4" "curl/7.59.0" "rid" "www.elastic.co" "-"')
        wrap = {'message': inner, 'stream': 'stdout',
                'time': '2019-02-12T18:37:43Z'}
        code, summary, ips, hosts, uas = run_extract(json.dumps(wrap))
        self.assertEqual(code, 0)
        self.assertEqual(summary['formats'].get('envoy'), 1)
        self.assertIn('203.0.113.4', ips_of(ips))

    def test_docker_log_wrapper_still_unwraps(self):
        inner = CLF + '\n'
        wrap = {'log': inner, 'stream': 'stdout'}
        code, summary, ips, hosts, uas = run_extract(json.dumps(wrap))
        self.assertEqual(code, 0)
        self.assertIn('203.0.113.5', ips_of(ips))

    def test_iis_plus_decoding_and_zone(self):
        text = (
            '#Fields: date time c-ip cs(User-Agent) sc-status\n'
            '2018-01-01 08:09:10 203.0.113.8 Mozilla/5.0+(Windows+NT) 200\n'
            '#Fields: c-ip sc-status\n'
            '::1%0 200\n'
        )
        code, summary, ips, hosts, uas = run_extract(text)
        self.assertEqual(code, 0)
        self.assertEqual(summary['formats'].get('w3c'), 2)
        self.assertIn('203.0.113.8', ips_of(ips))
        self.assertIn('::1', ips_of(ips))
        self.assertEqual(uas[0]['user_agent'], 'Mozilla/5.0 (Windows NT)')

    def test_fields_header_ignored_after_nginx(self):
        text = (
            CLF + '\n'
            '#Fields: c-ip cs-method cs-uri-stem sc-status\n'
            '198.51.100.9 GET /injected 200\n'
        )
        code, summary, ips, hosts, uas = run_extract(text, extra=['--min-parsed', '0'])
        found = ips_of(ips)
        self.assertIn('203.0.113.5', found)
        self.assertNotIn('198.51.100.9', found)

    def test_headerless_iis_does_not_resolve(self):
        line = '2018-01-01 08:09:10 203.0.113.8 GET / 200'
        code, summary, ips, hosts, uas = run_extract(line)
        self.assertEqual(code, ei.EXIT_FORMAT)
        self.assertEqual(summary['lines_parsed'], 0)

    def test_cloudfront_tab_and_forwarded(self):
        text = (
            '#Version: 1.0\n'
            '#Fields: date time c-ip cs-method cs-uri-stem sc-status '
            'cs(User-Agent) x-forwarded-for x-host-header\n'
            '2019-12-04\t21:02:31\t203.0.113.10\tGET\t/index.html\t200\t'
            'Mozilla/5.0%20(Windows)\t203.0.113.11, 203.0.113.12\twww.example.com\n'
        )
        code, summary, ips, hosts, uas = run_extract(text)
        self.assertEqual(code, 0)
        found = ips_of(ips)
        self.assertIn('connecting', found['203.0.113.10']['sources'])
        self.assertIn('chain_1', found['203.0.113.11']['sources'])
        self.assertEqual(uas[0]['user_agent'], 'Mozilla/5.0 (Windows)')
        self.assertIn('www.example.com', [h['host'] for h in hosts])

    def test_alb_does_not_promote_a_query_host(self):
        line = (
            'http 2018-07-02T22:23:00.186641Z app/lb/abc 203.0.113.10:2817 '
            '10.0.0.1:80 0.000 0.001 0.000 200 200 34 366 '
            '"GET http://www.example.com/shell?next=http://evil.example/x HTTP/1.1" '
            '"curl/7.46.0"'
        )
        code, summary, ips, hosts, uas = run_extract(line)
        self.assertEqual(code, 0)
        self.assertIn('203.0.113.10', ips_of(ips))
        names = [h['host'] for h in hosts]
        self.assertIn('www.example.com', names)
        self.assertNotIn('evil.example', names)

    def test_caddy_and_cloudflare_json(self):
        caddy = {
            'request': {
                'remote_ip': '203.0.113.11',
                'client_ip': '203.0.113.20',
                'host': 'example.com',
                'headers': {'User-Agent': ['curl/8']},
            },
            'status': 200,
        }
        cf = {
            'ClientIP': '203.0.113.10',
            'ClientRequestHost': 'example.com',
            'ClientRequestUserAgent': 'curl/8',
            'EdgeResponseStatus': 200,
        }
        code, summary, ips, hosts, uas = run_extract(
            json.dumps(caddy) + '\n' + json.dumps(cf))
        self.assertEqual(code, 0)
        found = ips_of(ips)
        self.assertIn('connecting', found['203.0.113.11']['sources'])
        self.assertIn('chain_1', found['203.0.113.20']['sources'])
        self.assertIn('connecting', found['203.0.113.10']['sources'])

    def test_nested_remote_ip_beats_bare_ip(self):
        obj = {'ip': '198.51.100.8', 'request': {'remote_ip': '203.0.113.50'},
               'http_user_agent': 'curl/8', 'status': 200}
        code, summary, ips, hosts, uas = run_extract(json.dumps(obj))
        self.assertEqual(code, 0)
        self.assertIn('203.0.113.50', ips_of(ips))
        self.assertNotIn('198.51.100.8', ips_of(ips))

    def test_syslog_prefix(self):
        line = ('Oct 20 10:00:00 host nginx: ' + CLF)
        code, summary, ips, hosts, uas = run_extract(line)
        self.assertEqual(code, 0)
        self.assertIn('203.0.113.5', ips_of(ips))

    def test_oauth_token_is_counted_and_not_stored(self):
        line = ('203.0.113.9 - - [01/Jan/2026:00:00:00 +0000] '
                '"GET /cb?oauth_token=ya29.SUPERSECRET&access_token=ATSECRET '
                'HTTP/1.1" 302 1 "-" "Mozilla/5.0"')
        code, summary, ips, hosts, uas = run_extract(line)
        self.assertEqual(code, 0)
        self.assertGreaterEqual(summary['sensitive_assignments'], 1)
        blob = json.dumps({'s': summary, 'ips': ips, 'hosts': hosts, 'uas': uas})
        self.assertNotIn('SUPERSECRET', blob)
        self.assertNotIn('ATSECRET', blob)

    def test_crawler_email_does_not_block_the_user_agent(self):
        line = ('203.0.113.9 - - [01/Jan/2026:00:00:00 +0000] '
                '"GET / HTTP/1.1" 200 1 "-" '
                '"Mozilla/5.0 (compatible; Ezooms/1.0; help@moz.com)"')
        code, summary, ips, hosts, uas = run_extract(line)
        self.assertEqual(code, 0)
        self.assertNotIn('contains_sensitive', uas[0])
        self.assertGreaterEqual(summary['email_shaped_values'].get('user_agent', 0), 1)
        self.assertNotIn('help@moz.com', json.dumps(summary))

    def test_credential_in_user_agent_is_flagged(self):
        line = ('203.0.113.9 - - [01/Jan/2026:00:00:00 +0000] '
                '"GET / HTTP/1.1" 200 1 "-" "Mozilla password=hunter2"')
        code, summary, ips, hosts, uas = run_extract(line)
        self.assertTrue(uas[0].get('contains_sensitive'))

    def test_bearer_redacted_in_malformed_sample_only(self):
        line = ('NOTALOG Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig '
                'cookie=sessionid=abc123def')
        code, summary, ips, hosts, uas = run_extract(line, extra=['--min-parsed', '0'])
        sample = summary['malformed_samples'][0]
        self.assertIn('Bearer [redacted]', sample)
        self.assertNotIn('eyJ', sample)
        self.assertNotIn('abc123def', sample)

    def test_cgnat_note(self):
        line = ('100.64.0.1 - - [01/Jan/2026:00:00:00 +0000] '
                '"GET / HTTP/1.1" 200 1 "-" "curl/8"')
        code, summary, ips, hosts, uas = run_extract(line)
        self.assertFalse(ips_of(ips)['100.64.0.1']['public'])
        self.assertTrue(any('carrier-grade NAT' in n for n in summary['notes']))

    def test_gzip(self):
        payload = gzip.compress((CLF + '\n').encode())
        code, summary, ips, hosts, uas = run_extract(None, binary=payload)
        self.assertEqual(code, 0)
        self.assertIn('203.0.113.5', ips_of(ips))


class DatasetTests(unittest.TestCase):
    def test_invisible_formula_prefix(self):
        with tempfile.TemporaryDirectory() as d:
            ind = os.path.join(d, 'uas.jsonl')
            out = os.path.join(d, 'uas.csv')
            rows = [
                {'user_agent': '=1+1', 'count': 1},
                {'user_agent': '\u200b=1+1', 'count': 1},
                {'user_agent': '\u200c=1+1', 'count': 1},
                {'user_agent': '\u2060=1+1', 'count': 1},
                {'user_agent': '\u00ad=1+1', 'count': 1},
                {'user_agent': 'normal', 'count': 1},
            ]
            with open(ind, 'w', encoding='utf-8') as fh:
                for row in rows:
                    fh.write(json.dumps(row) + '\n')
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                code = bd.main(['--indicators', ind, '--out', out,
                                '--local-only', '--strict'])
            self.assertEqual(code, 0)
            with open(out, encoding='utf-8') as fh:
                lines = fh.read().splitlines()[1:]
            for line in lines:
                if 'normal' in line:
                    self.assertFalse(line.startswith('"\''))
                else:
                    self.assertIn("\"'", line)


class EvidenceTests(unittest.TestCase):
    def test_query_dropped_and_long_line_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'a.log')
            out = os.path.join(d, 'ev')
            huge = 'b' * (ei.MAX_LINE + 10)
            text = (
                '203.0.113.9 - - [01/Jan/2026:00:00:00 +0000] '
                '"GET /cb?oauth_token=ya29.SUPERSECRET HTTP/1.1" 302 1 "-" "ua"\n'
                '203.0.113.9 - - [01/Jan/2026:00:00:01 +0000] "GET /' + huge +
                ' HTTP/1.1" 200 1 "-" "ua"\n'
            )
            with open(log, 'w', encoding='utf-8') as fh:
                fh.write(text)
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                code = ev.main([log, '--ip', '203.0.113.9', '--out', out,
                                '--min-parsed', '0'])
            self.assertEqual(code, 0)
            with open(os.path.join(out, 'evidence.jsonl'), encoding='utf-8') as fh:
                blob = fh.read()
            self.assertNotIn('SUPERSECRET', blob)
            self.assertNotIn('ya29', blob)
            self.assertIn('/cb', blob)
            with open(os.path.join(out, 'summary.json'), encoding='utf-8') as fh:
                summary = json.load(fh)
            self.assertGreaterEqual(summary['lines_malformed'], 1)


class SafetyTests(unittest.TestCase):
    def test_email_scan_stays_fast_on_a_long_line(self):
        import time
        blob = '@' + ('a' * 200000)
        started = time.perf_counter()
        self.assertFalse(ei.contains_email(blob))
        self.assertLess(time.perf_counter() - started, 0.5)
        line = ('203.0.113.9 - - [01/Jan/2026:00:00:00 +0000] '
                '"GET / HTTP/1.1" 200 1 "-" "bot help@moz.com" ' + blob)
        started = time.perf_counter()
        code, summary, ips, hosts, uas = run_extract(line)
        self.assertLess(time.perf_counter() - started, 1.0)
        self.assertEqual(code, 0)
        self.assertGreaterEqual(summary['email_shaped_values'].get('user_agent', 0), 1)
        self.assertNotIn('help@moz.com', json.dumps(summary))

    def test_overlong_line_is_dropped_and_the_next_line_parses(self):
        text = ('z' * (ei.MAX_LINE + 50)) + '\n' + CLF + '\n'
        code, summary, ips, hosts, uas = run_extract(text, extra=['--min-parsed', '0'])
        self.assertEqual(summary['lines_malformed'], 1)
        self.assertIn('203.0.113.5', ips_of(ips))
        self.assertTrue(summary['malformed_samples'][0].startswith('[line longer'))

    def test_stacked_prefixes_do_not_recurse_off_the_stack(self):
        prefix = 'Oct 20 10:00:00 host nginx: '
        line = (prefix * 30) + CLF
        code, summary, ips, hosts, uas = run_extract(line, extra=['--min-parsed', '0'])
        self.assertEqual(summary['lines_parsed'], 0)
        line = prefix + prefix + CLF
        code, summary, ips, hosts, uas = run_extract(line)
        self.assertEqual(code, 0)
        self.assertIn('203.0.113.5', ips_of(ips))

    def test_nested_quantifier_regex_is_refused(self):
        self.assertTrue(ei.regex_backtracks(r'(a+)+'))
        self.assertFalse(ei.regex_backtracks(r'(?:[^"\\]|\\.)*'))
        self.assertFalse(ei.regex_backtracks(
            r'^(?P<ip>[^|]+)\|(?P<ua>[^|]+)\|(?P<status>\d+)$'))
        rx, err = ei.compile_user_regex(r'(?P<ip>(?:\d+\.)+\d+)')
        self.assertIsNone(rx)
        self.assertIn('nests', err)
        rx, err = ei.compile_user_regex(
            r'^(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) (?P<ua>\S+)')
        self.assertIsNone(err)
        self.assertIsNotNone(rx)


if __name__ == '__main__':
    unittest.main()
