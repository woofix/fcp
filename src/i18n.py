# Copyright 2026 Eric TOMAS and FCP contributors
# SPDX-License-Identifier: Apache-2.0
"""Translate application-owned UI copy; leave code, logs and form values intact."""
import ast
import json
import re
import threading
from html import escape
from html.parser import HTMLParser
from pathlib import Path
from flask import request, redirect

CATALOG = json.loads(Path(__file__).with_name('en.json').read_text())
# Match once, longest first, so translated text is never translated again.
PATTERN = re.compile('|'.join(re.escape(k) for k in sorted(CATALOG, key=len, reverse=True)))
JS_STRING = re.compile(r'''(['"])((?:\\.|(?!\1)[^\\])*)\1''')

GEO_LABELS = {}
GEO_PATTERN = None
GEO_LOCK = threading.Lock()

def register_geo_label(french, english):
    global GEO_PATTERN
    if french == english: return
    with GEO_LOCK:
        if GEO_LABELS.get(french) == english: return
        GEO_LABELS[french] = english
        GEO_PATTERN = re.compile("|".join(re.escape(k) for k in sorted(GEO_LABELS, key=len, reverse=True)))

def translate(text):
    pattern = GEO_PATTERN
    if pattern is not None:
        text = pattern.sub(lambda m: GEO_LABELS[m.group()], text)
    if text in CATALOG:
        return CATALOG[text]
    return PATTERN.sub(lambda m: CATALOG[m.group()], text)


def translate_script(script):
    def literal(match):
        try:
            value = ast.literal_eval(match.group())
        except (SyntaxError, ValueError):
            return match.group()
        # Translate only registered literals, never identifiers, regex or user input.
        translated = CATALOG.get(value)
        return json.dumps(translated, ensure_ascii=False) if translated is not None else match.group()
    return JS_STRING.sub(literal, script)


class PageTranslator(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.parts = []
        self.stack = []

    def handle_starttag(self, tag, attrs):
        raw = self.get_starttag_text()
        if tag == 'html':
            raw = re.sub(r'lang=[\"\x27]fr[\"\x27]', 'lang="en"', raw)
        for key, value in attrs:
            if key in ('title', 'placeholder', 'aria-label') and value:
                translated = translate(value)
                if translated != value:
                    raw = re.sub(r'('+re.escape(key)+r'\s*=\s*)([\"\x27]).*?\2',
                        lambda m: m[1]+'"'+escape(translated, quote=True)+'"', raw, count=1)
        self.parts.append(raw)
        if tag not in ('area','base','br','col','embed','hr','img','input','link','meta','param','source','track','wbr'):
            self.stack.append(tag)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if self.stack and self.stack[-1] == tag: self.stack.pop()

    def handle_endtag(self, tag):
        self.parts.append('</'+tag+'>')
        if tag in self.stack:
            self.stack = self.stack[:len(self.stack)-1-self.stack[::-1].index(tag)]

    def handle_data(self, data):
        if self.stack and self.stack[-1] == 'script':
            self.parts.append(translate_script(data))
        elif any(t in self.stack for t in ('style','pre','code','textarea')):
            self.parts.append(data)
        else:
            self.parts.append(translate(data))

    def handle_entityref(self, name): self.parts.append('&'+name+';')
    def handle_charref(self, name): self.parts.append('&#'+name+';')
    def handle_decl(self, decl): self.parts.append('<!'+decl+'>')
    def handle_comment(self, data): self.parts.append('<!--'+data+'-->')


def html_english(html):
    parser = PageTranslator(); parser.feed(html); parser.close()
    return ''.join(parser.parts)


def install_i18n(app):
    @app.get('/language')
    def language():
        chosen = request.args.get('lang', 'fr')
        if chosen not in ('fr', 'en'): return 'Invalid language', 400
        target = request.args.get('next','/')
        if target not in ('/', '/manage', '/manage?embedded=1', '/application', '/login'): target = '/'
        response = redirect(target, code=303)
        response.set_cookie('fcp_language', chosen, max_age=31536000,
            httponly=True, samesite='Lax', secure=request.is_secure)
        return response

    @app.after_request
    def localize(response):
        lang = request.cookies.get('fcp_language','fr')
        if lang not in ('fr','en'): lang='fr'
        response.headers['Content-Language'] = lang
        response.vary.add('Cookie')
        if response.status_code == 200 and response.mimetype == 'text/html':
            html = response.get_data(as_text=True)
            if lang == 'en': html = html_english(html)
            response.set_data(html)
        elif lang == 'en' and response.is_json:
            def local(value, key=''):
                if isinstance(value,dict): return {k:local(v,k) for k,v in value.items()}
                if isinstance(value,list): return [local(v,key) for v in value]
                if isinstance(value,str):
                    if key == 'html': return html_english(value)
                    if key in ('error','message','output','location','version') and not '\n' in value: return translate(value)
                return value
            response.set_data(json.dumps(local(response.get_json()),ensure_ascii=False))
        return response
