"""Language settings must not weaken authentication or alter operator data."""
import unittest
import test_portability as fixture
ui = fixture.ui
from i18n import html_english, translate_script

class LanguageTests(unittest.TestCase):
    def setUp(self):
        base=fixture.PortabilityTests();base.setUp()
        self.client=base.client;self.auth=base.auth

    def test_language_requires_auth_and_validates_target(self):
        self.assertEqual(ui.app.test_client().get('/manage').status_code,303)
        self.assertEqual(self.client.get('/language?lang=de',headers=self.auth).status_code,400)
        r=self.client.get('/language?lang=en&next=https://example.com',headers=self.auth)
        self.assertEqual(r.status_code,303);self.assertEqual(r.location,'/')
        self.assertIn('HttpOnly',r.headers['Set-Cookie']);self.assertIn('SameSite=Lax',r.headers['Set-Cookie'])

    def test_preference_is_per_browser_and_switches_back(self):
        french=self.client.get('/manage',headers=self.auth)
        self.assertIn('État du service',french.get_data(as_text=True))
        self.client.get('/language?lang=en',headers=self.auth)
        english=self.client.get('/manage',headers=self.auth).get_data(as_text=True)
        self.assertIn('Service status',english);self.assertIn('lang="en"',english)
        self.assertNotIn('fcp-language-select',english)
        other_client=ui.app.test_client();fixture.sign_in(other_client)
        other=other_client.get('/manage',headers=self.auth)
        self.assertEqual(other.headers['Content-Language'],'fr')
        self.client.get('/language?lang=fr',headers=self.auth)
        self.assertIn('État du service',self.client.get('/manage',headers=self.auth).get_data(as_text=True))

    def test_technical_and_editable_contents_remain_intact(self):
        original='<html lang="fr"><body><h1>Détections</h1><pre>Détections</pre><textarea>Détections</textarea><input value="Détections" placeholder="Nom du fichier"></body></html>'
        html=html_english(original)
        self.assertIn('<h1>Detections</h1>',html);self.assertIn('<pre>Détections</pre>',html)
        self.assertIn('<textarea>Détections</textarea>',html);self.assertIn('value="Détections"',html)
        self.assertIn('placeholder="File name"',html)
        script=translate_script("const id='overview';confirm('Tester puis recharger toutes les jails ?');const token='DEBANNIR';")
        self.assertIn("id='overview'",script);self.assertIn('Validate and reload all jails?',script)
        self.assertIn("token='DEBANNIR'",script)

    def test_geographic_names_follow_the_selected_language(self):
        from i18n import register_geo_label, translate
        register_geo_label('🇧🇪 Belgique · Bruxelles','🇧🇪 Belgium · Brussels')
        self.assertEqual(translate('IP bannie : 1.1.1.1 · 🇧🇪 Belgique · Bruxelles'),'IP banned: 1.1.1.1 · 🇧🇪 Belgium · Brussels')
