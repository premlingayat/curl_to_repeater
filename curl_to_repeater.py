# -*- coding: utf-8 -*-
#
# Curl to Repeater (Context Menu) - Burp Suite Extension (Jython / Python 2.7)
# ---------------------------------------------------------------------------
# Adds a right-click menu item "Paste curl -> Repeater" anywhere in Burp.
# It reads a `curl` command from the SYSTEM CLIPBOARD, parses it into a raw
# HTTP request, and sends it straight to the Repeater tab.
#
# Supports proper multipart/form-data (-F) with MIME boundaries, per-part
# headers, file uploads (@file), and ;type= / ;filename= modifiers.
#
# Workflow:
#   1. Copy a curl command (e.g. DevTools > right-click request > Copy as cURL).
#   2. Right-click anywhere in Burp > "Paste curl -> Repeater".
#   3. A new Repeater tab opens with the built request.
#
# Load in Burp:  Extender > Extensions > Add > Extension type: Python
#                (Ensure Jython standalone JAR is set under
#                 Extender > Options > Python Environment)
#
# Author: generated for Prem Lingayat
#

from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem
from java.awt import Toolkit
from java.awt.datatransfer import DataFlavor
from java.net import URL
import shlex
import base64
import os
import random
import string


class BurpExtender(IBurpExtender, IContextMenuFactory):

    # ------------------------------------------------------------------ #
    #  Burp entry point
    # ------------------------------------------------------------------ #
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Curl to Repeater (Context Menu)")
        callbacks.registerContextMenuFactory(self)
        self._log("Curl to Repeater (Context Menu) loaded. "
                  "Right-click anywhere > 'Paste curl -> Repeater'.")
        return

    # ------------------------------------------------------------------ #
    #  Context menu
    # ------------------------------------------------------------------ #
    def createMenuItems(self, invocation):
        item = JMenuItem("Paste curl -> Repeater",
                         actionPerformed=self._on_click)
        return [item]

    def _on_click(self, event):
        try:
            raw = self._read_clipboard()
            if not raw or not raw.strip():
                self._log("[!] Clipboard is empty or not text. Copy a curl command first.")
                return

            host, port, is_https, request = self._parse_curl(raw)
            caption = self._derive_caption(host)
            self._callbacks.sendToRepeater(host, port, is_https, request, caption)
            self._log("[+] Sent to Repeater (tab '%s') -> %s://%s:%d" %
                      (caption, "https" if is_https else "http", host, port))
        except Exception as e:
            self._log("[!] Error: %s" % str(e))

    # ------------------------------------------------------------------ #
    #  Clipboard
    # ------------------------------------------------------------------ #
    def _read_clipboard(self):
        try:
            cb = Toolkit.getDefaultToolkit().getSystemClipboard()
            if cb.isDataFlavorAvailable(DataFlavor.stringFlavor):
                return cb.getData(DataFlavor.stringFlavor)
        except Exception as e:
            self._log("[!] Could not read clipboard: %s" % str(e))
        return None

    def _derive_caption(self, host):
        return host if host else "curl"

    # ------------------------------------------------------------------ #
    #  Curl parsing
    # ------------------------------------------------------------------ #
    def _parse_curl(self, raw):
        if raw is None or not raw.strip():
            raise ValueError("No curl command provided.")

        # Normalise line-continuations
        cleaned = raw.strip()
        cleaned = cleaned.replace("\\\r\n", " ").replace("\\\n", " ")
        cleaned = cleaned.replace("\r\n", " ").replace("\n", " ")
        cleaned = cleaned.replace("^\n", " ")  # windows caret continuation

        try:
            tokens = shlex.split(cleaned)
        except Exception:
            tokens = shlex.split(cleaned, posix=False)

        if not tokens:
            raise ValueError("Could not tokenise the command.")
        if tokens[0].lower() == "curl":
            tokens = tokens[1:]

        method = None
        url = None
        headers = []
        data_parts = []
        form_parts = []          # raw -F strings
        is_form = False
        header_names_lower = set()

        noarg = set(["-k", "--insecure", "-s", "--silent", "-L", "--location",
                     "-i", "--include", "-v", "--verbose", "--compressed",
                     "-g", "--globoff", "-#", "--progress-bar", "-f", "--fail",
                     "-S", "--show-error", "-0", "--http1.0", "--http1.1",
                     "--http2", "-N", "--no-buffer", "-j", "--junk-session-cookies"])

        i = 0
        while i < len(tokens):
            t = tokens[i]

            if t in ("-X", "--request"):
                method = tokens[i + 1]; i += 2; continue

            if t in ("-H", "--header"):
                self._add_header(tokens[i + 1], headers, header_names_lower)
                i += 2; continue

            if t in ("-A", "--user-agent"):
                self._add_header("User-Agent: " + tokens[i + 1], headers, header_names_lower)
                i += 2; continue

            if t in ("-e", "--referer"):
                self._add_header("Referer: " + tokens[i + 1], headers, header_names_lower)
                i += 2; continue

            if t in ("-b", "--cookie"):
                self._add_header("Cookie: " + tokens[i + 1], headers, header_names_lower)
                i += 2; continue

            if t in ("-d", "--data", "--data-raw", "--data-binary",
                     "--data-ascii", "--data-urlencode"):
                data_parts.append(tokens[i + 1]); i += 2; continue

            if t in ("-F", "--form", "--form-string"):
                is_form = True
                form_parts.append(tokens[i + 1]); i += 2; continue

            if t in ("-u", "--user"):
                cred = base64.b64encode(tokens[i + 1].encode("utf-8"))
                self._add_header("Authorization: Basic " + cred, headers, header_names_lower)
                i += 2; continue

            if t in noarg:
                i += 1; continue

            if t in ("--url",):
                url = tokens[i + 1]; i += 2; continue

            if t.startswith("-") and len(t) > 1:
                if i + 1 < len(tokens) and not tokens[i + 1].startswith("-") \
                        and "://" not in tokens[i + 1]:
                    i += 2
                else:
                    i += 1
                continue

            if url is None:
                url = t
            i += 1

        if url is None:
            raise ValueError("No URL found in the curl command.")

        # ---------------- Build body ----------------
        body = ""
        multipart_ct = None

        if is_form and form_parts:
            boundary, body = self._build_multipart(form_parts)
            multipart_ct = "multipart/form-data; boundary=%s" % boundary
        elif data_parts:
            body = "&".join(data_parts)

        if method is None:
            method = "POST" if body else "GET"

        # ---------------- Parse URL ----------------
        if "://" not in url:
            url = "http://" + url
        parsed = URL(url)
        protocol = parsed.getProtocol().lower()
        is_https = (protocol == "https")
        host = parsed.getHost()
        port = parsed.getPort()
        if port == -1:
            port = 443 if is_https else 80

        path = parsed.getFile()
        if not path:
            path = "/"

        host_hdr = host if ((is_https and port == 443) or (not is_https and port == 80)) \
            else "%s:%d" % (host, port)
        if "host" not in header_names_lower:
            headers.insert(0, ("Host", host_hdr))

        # ---------------- Content-Type ----------------
        if multipart_ct:
            # multipart boundary MUST match the body we generated -> override
            headers = [(n, v) for (n, v) in headers if n.lower() != "content-type"]
            headers.append(("Content-Type", multipart_ct))
        elif body and "content-type" not in header_names_lower:
            headers.append(("Content-Type", "application/x-www-form-urlencoded"))

        # ---------------- Content-Length ----------------
        if body:
            headers = [(n, v) for (n, v) in headers if n.lower() != "content-length"]
            headers.append(("Content-Length", str(len(body))))

        # ---------------- Assemble ----------------
        crlf = "\r\n"
        lines = ["%s %s HTTP/1.1" % (method.upper(), path)]
        for (n, v) in headers:
            lines.append("%s: %s" % (n, v))
        raw_request = crlf.join(lines) + crlf + crlf + body

        request_bytes = self._helpers.stringToBytes(raw_request)
        return host, port, is_https, request_bytes

    # ------------------------------------------------------------------ #
    #  Multipart / form-data builder
    # ------------------------------------------------------------------ #
    def _gen_boundary(self):
        rand = "".join(random.choice(string.ascii_letters + string.digits)
                       for _ in range(16))
        return "----BurpFormBoundary" + rand

    def _build_multipart(self, form_fields):
        """
        Build a multipart/form-data body from curl -F strings.
        Supports:
          name=value
          name=@/path/to/file            (file upload; contents read from disk)
          name=@file;type=image/png      (explicit content type)
          name=@file;filename=alt.png    (override filename)
          name=<contents_file            (read value from file, not as upload)
        Returns (boundary, body_string).
        """
        boundary = self._gen_boundary()
        crlf = "\r\n"
        parts = []

        for raw in form_fields:
            if "=" not in raw:
                # malformed field; skip but note it
                self._log("[!] Skipping malformed -F field: %s" % raw)
                continue

            name, value = raw.split("=", 1)
            name = name.strip()

            # Split off ;type= / ;filename= modifiers
            ctype = None
            filename = None
            segs = value.split(";")
            main = segs[0]
            for seg in segs[1:]:
                seg = seg.strip()
                if seg.lower().startswith("type="):
                    ctype = seg[len("type="):]
                elif seg.lower().startswith("filename="):
                    filename = seg[len("filename="):]

            if main.startswith("@") or main.startswith("<"):
                is_upload = main.startswith("@")   # @ = file upload, < = value from file
                filepath = main[1:]
                file_bytes = self._read_file(filepath)

                if is_upload:
                    if filename is None:
                        filename = os.path.basename(filepath)
                    disp = ('Content-Disposition: form-data; name="%s"; filename="%s"'
                            % (name, filename))
                    hdrs = [disp]
                    hdrs.append("Content-Type: %s" %
                                (ctype if ctype else "application/octet-stream"))
                    body_val = file_bytes if file_bytes is not None \
                        else ("<contents of %s - file not found by extension>" % filepath)
                    part = crlf.join(hdrs) + crlf + crlf + body_val
                else:
                    # '<' : use file content as the field value (no filename)
                    disp = 'Content-Disposition: form-data; name="%s"' % name
                    hdrs = [disp]
                    if ctype:
                        hdrs.append("Content-Type: %s" % ctype)
                    body_val = file_bytes if file_bytes is not None \
                        else ("<contents of %s - file not found by extension>" % filepath)
                    part = crlf.join(hdrs) + crlf + crlf + body_val
            else:
                disp = 'Content-Disposition: form-data; name="%s"' % name
                hdrs = [disp]
                if ctype:
                    hdrs.append("Content-Type: %s" % ctype)
                part = crlf.join(hdrs) + crlf + crlf + main

            parts.append(part)

        body = ""
        for p in parts:
            body += "--" + boundary + crlf + p + crlf
        body += "--" + boundary + "--" + crlf
        return boundary, body

    def _read_file(self, filepath):
        """Read a local file as a latin-1 string (byte-preserving). Returns None on failure."""
        try:
            f = open(filepath, "rb")
            try:
                data = f.read()
            finally:
                f.close()
            # Decode as latin-1 so every byte maps 1:1 to a char, then
            # stringToBytes re-encodes faithfully for the raw request.
            try:
                return data.decode("latin-1")
            except Exception:
                return data
        except Exception as e:
            self._log("[!] Could not read file '%s': %s" % (filepath, str(e)))
            return None

    # ------------------------------------------------------------------ #
    #  Helpers
    # ------------------------------------------------------------------ #
    def _add_header(self, header_str, headers, names_lower):
        if ":" in header_str:
            name, value = header_str.split(":", 1)
            name = name.strip()
            value = value.strip()
        else:
            name, value = header_str.strip(), ""
        headers.append((name, value))
        names_lower.add(name.lower())

    def _log(self, msg):
        try:
            self._callbacks.printOutput(msg)
        except Exception:
            pass
