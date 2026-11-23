"""Tests isolés: aucun paquet réseau capturé et aucun pare-feu modifié."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

from core import admins, access_control as ac, sniffer, alerts

PROJECT = Path(__file__).resolve().parents[1]

class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.accounts = self.path / 'admins.json'
        self.logs = self.path / 'events.log'
        self.config_path = self.path / 'config.json'
        self.config_path.write_text((PROJECT/'config.example.json').read_text(),encoding='utf-8')
        patches=[patch.object(admins,'ADMINS_PATH',str(self.accounts)),
                 patch.object(alerts,'LOG_FILE',str(self.logs)),
                 patch.object(alerts,'LOG_DIR',str(self.path)),
                 patch.object(ac,'CONFIG_PATH',str(self.config_path)),
                 patch.object(sniffer,'CONFIG_PATH',str(self.config_path)),
                 patch.object(ac,'IPTABLES',None)]
        for p in patches:
            p.start();self.addCleanup(p.stop)
        alerts._recent.clear()

    def test_config_example_valid(self):
        cfg=sniffer.load_config()
        self.assertEqual(cfg['web']['host'],'127.0.0.1')
        self.assertEqual(cfg['detection']['flood_packet_threshold'],200)

    def test_no_default_admin_password(self):
        with patch.dict(os.environ, {'NETCONTROL_ADMIN_PASSWORD':''}):
            with self.assertRaises(RuntimeError):admins.ensure_bootstrap_admin()
        self.assertFalse(self.accounts.exists())

    def test_bootstrap_login_and_rejection(self):
        with patch.dict(os.environ, {'NETCONTROL_ADMIN_USER':'tester','NETCONTROL_ADMIN_PASSWORD':'some-strong-password-123'}):
            admins.ensure_bootstrap_admin()
        self.assertTrue(admins.verify('tester','some-strong-password-123'))
        self.assertFalse(admins.verify('tester','incorrect'))
        raw=self.accounts.read_text();self.assertNotIn('some-strong-password-123',raw)
        admins.ensure_bootstrap_admin()  # no reset of existing accounts
        self.assertEqual(admins.list_admins(),['tester'])

    def test_admin_management(self):
        with patch.dict(os.environ, {'NETCONTROL_ADMIN_PASSWORD':'some-strong-password-123'}):
            admins.ensure_bootstrap_admin()
        self.assertFalse(admins.add_admin('second','short')[0])
        self.assertTrue(admins.add_admin('second','another-strong-password')[0])
        self.assertFalse(admins.remove_admin('admin','admin')[0])
        self.assertTrue(admins.remove_admin('second','admin')[0])
        self.assertFalse(admins.remove_admin('admin','second')[0])

    def test_access_control_validation(self):
        self.assertFalse(ac.add_to_blacklist('hello; echo hi')[0])
        self.assertFalse(ac.add_to_whitelist('not_an_ip')[0])
        ok,msg=ac.add_to_blacklist('192.0.2.15')
        self.assertTrue(ok)
        self.assertIn('not active',msg)
        self.assertIn('192.0.2.15',ac.get_lists()[1])
        self.assertTrue(ac.remove_from_blacklist('192.0.2.15')[0])
        self.assertTrue(ac.add_to_whitelist('192.0.2.30')[0])
        self.assertTrue(ac.is_whitelisted('192.0.2.30'))


    def test_whitelisted_ip_cannot_be_blacklisted(self):
        cfg = {
            "access_control": {
                "whitelist": ["10.0.2.2"],
                "blacklist": []
            }
        }

        with patch.object(ac, "_load_config", return_value=cfg):
            with patch.object(
                ac, "_iptables_block",
                side_effect=AssertionError("iptables must not be called")
            ):
                ok, msg = ac.add_to_blacklist("10.0.2.2")

        self.assertFalse(ok)
        self.assertIn("whitelist", msg.lower())

    def test_iptables_command_assembly_mock_only(self):
        # no OS-level commands called: verifies exact argument vectors
        calls=[]
        def fake_run(args,**kw):
            calls.append(args)
            if '-C' in args:return SimpleNamespace(returncode=1)
            return SimpleNamespace(returncode=0)
        with patch.object(ac,'IPTABLES','/mock/iptables'), patch.object(ac.subprocess,'run',side_effect=fake_run):
            self.assertTrue(ac._iptables_block('192.0.2.15'))
        self.assertEqual(sum('-I' in c for c in calls),2)
        self.assertTrue(all(c[0]=='/mock/iptables' for c in calls))

    def test_flood_threshold(self):
        cfg=json.loads(self.config_path.read_text());cfg['detection']['flood_packet_threshold']=3
        m=sniffer.TrafficMonitor(cfg)
        with patch.object(sniffer,'is_whitelisted',return_value=False),patch.object(sniffer,'log_event') as log,patch.object(sniffer.time,'time',return_value=100):
            for _ in range(5):m._check_flood('192.0.2.1')
            self.assertEqual(log.call_count,1)
            self.assertEqual(log.call_args.args[0],'FLOOD')

    def test_arp_alert_with_fake_packet(self):
        class ARP:
            def __init__(self,ip,mac):self.op=2;self.psrc=ip;self.hwsrc=mac
        class Packet:
            def __init__(self,layer):self.layer=layer
            def haslayer(self,key):return True
            def __getitem__(self,key):return self.layer
        cfg=json.loads(self.config_path.read_text());m=sniffer.TrafficMonitor(cfg)
        with patch.object(sniffer,'ARP',ARP,create=True),patch.object(sniffer,'is_whitelisted',return_value=False),patch.object(sniffer,'log_event') as log:
            m._check_arp(Packet(ARP('192.0.2.5','aa:bb:cc:dd:ee:01')))
            m._check_arp(Packet(ARP('192.0.2.5','aa:bb:cc:dd:ee:02')))
            self.assertEqual(log.call_count,1)
            self.assertEqual(log.call_args.args[0],'ARP')

    def test_snapshot(self):
        m=sniffer.TrafficMonitor(json.loads(self.config_path.read_text()))
        m.total_packets=9;m.packets_per_ip['192.0.2.3']=7
        snap=m.snapshot()
        self.assertEqual(snap['total_packets'],9)
        self.assertEqual(snap['unique_ips'],1)

    def test_log_json(self):
        ev=alerts.log_event('SYSTEM','test','warning')
        self.assertEqual(json.loads(self.logs.read_text().splitlines()[0])['category'],'SYSTEM')
        self.assertEqual(alerts.event_counts()['warning'],1)

    def test_templates_csrf_for_each_form(self):
        import re
        for f in (PROJECT/'templates').glob('*.html'):
            s=f.read_text()
            for match in re.finditer(r'<form\b[^>]*method="POST"[^>]*>',s):
                snippet=s[match.end():s.find('</form>',match.end())]
                self.assertIn('name="_csrf"',snippet,str(f))
        self.assertNotIn('admin123',(PROJECT/'templates/login.html').read_text())

    def test_files_not_to_publish(self):
        ig=(PROJECT/'.gitignore').read_text()
        for name in ['config.json','admins.json','.env','logs/']:
            self.assertIn(name,ig)
        import subprocess
        result = subprocess.run(
            ["git", "ls-files", "--cached", "--", "config.json"],
            cwd=PROJECT,
            capture_output=True,
            text=True,
            check=True
        )
        self.assertEqual(result.stdout.strip(), "")

if __name__=='__main__':unittest.main()
