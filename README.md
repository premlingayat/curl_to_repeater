# Curl to Repeater

A Burp Suite extension that turns a copied `curl` command into an HTTP request and opens it in Repeater.

## Requirements

- Burp Suite with the Extender API
- Jython standalone JAR configured in **Extender > Options > Python Environment**

## Install and use

1. In Burp, open **Extender > Extensions > Add** and select **Python** as the extension type. Load `curl_to_repeater.py`.
2. Copy a `curl` command to your system clipboard.
3. Right-click in Burp and choose **Paste curl -> Repeater**.

The extension supports common curl request options, including headers, data, basic authentication, and multipart form fields (`-F`). Multipart file fields read the referenced files from the machine running Burp.